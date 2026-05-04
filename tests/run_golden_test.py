#!/usr/bin/env python3
"""
Headless test runner for Cat Mode golden video validation
Runs test_cat_mode_golden.html in headless Chrome/Chromium via Selenium
"""

import sys
import os
import time
import json
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ====================================================================
# Configuration
# ====================================================================

PORT = 8765
TEST_URL = f"http://localhost:{PORT}/tests/test_cat_mode_golden.html"
TIMEOUT_SEC = 120  # 2 minutes


# ====================================================================
# HTTP Server
# ====================================================================


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP handler that suppresses log output"""

    def log_message(self, format, *args):
        pass  # Suppress request logging


def start_server(port=PORT):
    """Start HTTP server in background thread"""

    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    server = HTTPServer(("localhost", port), QuietHTTPRequestHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"✓ Test server running on http://localhost:{port}")
    return server


# ====================================================================
# Headless Chrome Test Runner
# ====================================================================


def run_headless_test():
    """Run golden video test in headless Chrome"""

    print("\n🧪 Running Cat Mode Golden Video Test in Headless Chrome\n")

    # Start HTTP server
    server = start_server()
    time.sleep(1)  # Give server time to start

    try:
        # Configure headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-software-rasterizer")
        # Capture browser console output so timeouts/crashes leave a
        # diagnostic trail instead of an empty TimeoutException.
        chrome_options.set_capability(
            "goog:loggingPrefs", {"browser": "ALL"}
        )

        # Find Chrome binary
        chrome_binary = find_chrome_binary()
        if chrome_binary:
            chrome_options.binary_location = chrome_binary
            print(f"✓ Using Chrome: {chrome_binary}\n")

        # Selenium Manager (built into selenium >=4.6) auto-resolves a
        # chromedriver compatible with the installed Chrome. webdriver-manager
        # downloads the *latest* chromedriver, which can desync from the
        # Chrome version installed by browser-actions/setup-chrome and crash
        # on session start with an empty error message.
        print("✓ Using Selenium Manager for chromedriver resolution\n")
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(TIMEOUT_SEC)

        try:
            # Load test page
            print(f"Loading test page: {TEST_URL}")
            driver.get(TEST_URL)

            # Wait for test to complete (status changes from 'pending')
            print("Waiting for test to complete...")

            status_elem = WebDriverWait(driver, TIMEOUT_SEC).until(
                lambda d: d.find_element(By.ID, "status")
            )

            # Wait for test completion (status class changes from 'pending')
            WebDriverWait(driver, TIMEOUT_SEC).until(
                lambda d: "pending" not in status_elem.get_attribute("class")
            )

            time.sleep(2)  # Give UI time to update

            # Parse test results
            results = parse_test_results(driver)

            # Print results
            print("\n" + "=" * 70)
            print("📊 Test Results")
            print("=" * 70 + "\n")

            if results["assertions"]:
                for assertion in results["assertions"]:
                    icon = "✓" if assertion["pass"] else "✗"
                    color = "\033[32m" if assertion["pass"] else "\033[31m"
                    reset = "\033[0m"

                    print(f"{color}{icon}{reset} {assertion['name']}")
                    print(f"  Expected: {assertion['expected']}")
                    print(f"  Actual:   {assertion['actual']}")
                    print("")

            print("=" * 70)

            if results["all_pass"]:
                print("\033[32m✅ ALL TESTS PASSED\033[0m\n")
                return 0
            else:
                print("\033[31m❌ SOME TESTS FAILED\033[0m\n")
                print("Failed assertions:")
                for assertion in results["assertions"]:
                    if not assertion["pass"]:
                        print(f"  - {assertion['name']}")
                print("")
                return 1

        finally:
            driver.quit()

    except Exception as error:
        import traceback
        print(f"\n❌ Test execution failed: {type(error).__name__}: {error!r}")
        traceback.print_exc()
        # Dump browser console logs and current page status so a timeout
        # tells us what the JS was doing when it stalled.
        try:
            logs = driver.get_log("browser")
            if logs:
                print("\n--- Browser console (last 30) ---")
                for entry in logs[-30:]:
                    print(f"  [{entry.get('level')}] {entry.get('message')}")
            else:
                print("\n--- Browser console: (empty) ---")
            try:
                status_html = driver.find_element(By.ID, "status").get_attribute(
                    "outerHTML"
                )
                print(f"\n--- #status outerHTML ---\n  {status_html}")
            except Exception:
                pass
        except Exception as diag_err:
            print(f"  (diagnostics unavailable: {diag_err!r})")
        return 1

    finally:
        server.shutdown()
        print("✓ Test server stopped\n")


def find_chrome_binary():
    """Find Chrome/Chromium binary path"""

    paths = [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/snap/bin/chromium",
        os.environ.get("CHROME_BIN"),
    ]

    for path in paths:
        if path and os.path.exists(path):
            return path

    return None  # Let Selenium find it


def parse_test_results(driver):
    """Parse test results from page DOM"""

    results = {"assertions": [], "all_pass": False}

    try:
        # Get assertions
        assertion_elements = driver.find_elements(By.CLASS_NAME, "assertion")

        for elem in assertion_elements:
            classes = elem.get_attribute("class")
            pass_status = "pass" in classes

            # Extract text content
            text = elem.text
            lines = text.split("\n")

            name = lines[0].replace("✓ ", "").replace("✗ ", "") if lines else "Unknown"
            expected = lines[1].replace("Expected: ", "") if len(lines) > 1 else "N/A"
            actual = lines[2].replace("Actual: ", "") if len(lines) > 2 else "N/A"

            results["assertions"].append(
                {"name": name, "expected": expected, "actual": actual, "pass": pass_status}
            )

        # Check overall status
        status_elem = driver.find_element(By.ID, "status")
        status_text = status_elem.text

        if "TEST PASSED" in status_text:
            results["all_pass"] = True
        elif "TEST FAILED" in status_text:
            results["all_pass"] = False
        elif results["assertions"]:
            results["all_pass"] = all(a["pass"] for a in results["assertions"])

    except Exception as e:
        print(f"Warning: Could not parse results: {e}")

    return results


# ====================================================================
# Main
# ====================================================================

if __name__ == "__main__":
    exit_code = run_headless_test()
    sys.exit(exit_code)
