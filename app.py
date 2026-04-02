import argparse
import threading
from scanner.crawler import Crawler
from scanner.portscan import PortScanner
from scanner.sqli import SQLiScanner
from scanner.xss import XSSScanner


# ================= SCANNER ENGINE =================
class ScannerEngine:

    def __init__(self, target, scan_types=None, port_mode="fast", verbose=False):
        self.target = target.rstrip("/")
        self.scan_types = scan_types or []
        self.port_mode = port_mode
        self.verbose = verbose

        self.results = {
            "crawler": [],
            "ports": {},
            "sqli": [],
            "xss": []
        }

        self.status = "Initializing..."
        self.progress = 0
        self.lock = threading.Lock()

    # ================= HELPERS =================
    def update_status(self, message):
        with self.lock:
            self.status = message
        if self.verbose:
            print(f"[STATUS] {message}")

    def update_progress(self, value):
        with self.lock:
            self.progress = value

    # ================= MODULES =================
    def run_crawler(self):
        self.update_status("Running Crawler...")
        crawler = Crawler(self.target, verbose=self.verbose)
        self.results["crawler"] = crawler.scan(verbose=self.verbose)

    def run_portscanner(self):
        self.update_status("Scanning Ports...")
        scanner = PortScanner(self.target, mode=self.port_mode, verbose=self.verbose)
        self.results["ports"] = scanner.scan()

    def run_sqli(self):
        if not self.results["crawler"]:
            self.run_crawler()

        self.update_status("Testing SQL Injection...")
        sqli = SQLiScanner(self.results["crawler"], verbose=self.verbose)
        self.results["sqli"] = sqli.scan()

    def run_xss(self):
        if not self.results["crawler"]:
            self.run_crawler()

        self.update_status("Testing XSS...")
        xss = XSSScanner(self.results["crawler"], verbose=self.verbose)
        self.results["xss"] = xss.scan()

    # ================= MAIN =================
    def run_all(self):

        if not self.scan_types:
            self.update_status("No scan selected")
            self.update_progress(100)
            return

        total_steps = len(self.scan_types)
        step_progress = 100 // total_steps
        current_progress = 0

        if "sqli" in self.scan_types or "xss" in self.scan_types:
            if "crawler" not in self.scan_types:
                self.run_crawler()

        for scan in self.scan_types:

            if scan == "crawler":
                self.run_crawler()

            elif scan == "port":
                self.run_portscanner()

            elif scan == "sqli":
                self.run_sqli()

            elif scan == "xss":
                self.run_xss()

            current_progress += step_progress
            self.update_progress(current_progress)

        self.update_progress(100)
        self.update_status("Completed")


# ================= CLI =================
def main():
    parser = argparse.ArgumentParser(
        description="ScanCLI - Automated Web Application Vulnerability Scanner"
    )

    parser.add_argument("target", help="Target URL (e.g., http://example.com)")

    parser.add_argument(
        "--scan",
        nargs="+",
        choices=["crawler", "port", "sqli", "xss"],
        required=True,
        help="Select scan modules"
    )

    parser.add_argument(
        "--port-mode",
        choices=["fast", "normal", "deep"],
        default="fast",
        help="Port scan mode"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed output"
    )

    args = parser.parse_args()

    print("\n🔥 ScanCLI - Starting Scan 🔥\n")

    scanner = ScannerEngine(
        target=args.target,
        scan_types=args.scan,
        port_mode=args.port_mode,
        verbose=args.verbose
    )

    thread = threading.Thread(target=scanner.run_all)
    thread.start()

    while thread.is_alive():
        print(f"[{scanner.progress}%] {scanner.status}")
        thread.join(1)

    print("\n✅ Scan Completed!\n")

    # ================= RESULTS =================
    print("Target:", scanner.target)

    if scanner.results["ports"]:
        print("\n[PORTS]")
        for port, data in scanner.results["ports"].items():
            print(f"{port} → {data}")

    if scanner.results["sqli"]:
        print("\n[SQLi Vulnerabilities]")
        for v in scanner.results["sqli"]:
            print(v)

    if scanner.results["xss"]:
        print("\n[XSS Vulnerabilities]")
        for v in scanner.results["xss"]:
            print(v)


if __name__ == "__main__":
    main()
