import argparse
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

    # ================= MODULES =================
    def run_crawler(self):
        print("[+] Running Crawler...")
        crawler = Crawler(self.target,timeout=600, verbose=self.verbose)
        self.results["crawler"] = crawler.scan()

    def run_portscanner(self):
        print("[+] Scanning Ports...")
        scanner = PortScanner(self.target, mode=self.port_mode,timeout=600, verbose=self.verbose)
        self.results["ports"] = scanner.scan()

    def run_sqli(self):
        if not self.results["crawler"]:
            self.run_crawler()

        print("[+] Testing SQL Injection...")
        sqli = SQLiScanner(self.results["crawler"],timeout=600, verbose=self.verbose)
        self.results["sqli"] = sqli.scan()

    def run_xss(self):
        if not self.results["crawler"]:
            self.run_crawler()

        print("[+] Testing XSS...")
        xss = XSSScanner(self.results["crawler"],timeout=600, verbose=self.verbose)
        self.results["xss"] = xss.scan()

    # ================= MAIN =================
    def run_all(self):

        if not self.scan_types:
            print("[-] No scan selected")
            return

        # Run crawler first if needed
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

        self.print_results()

    # ================= RESULTS =================
    def print_results(self):
        print("\n========== RESULTS ==========\n")

        # CRAWLER
        print("[CRAWLER]")
        if self.results["crawler"]:
            print(f"Found {len(self.results['crawler'])} URLs")
            for url in self.results["crawler"][:10]:
                print(" -", url)
        else:
            print("No URLs found")

        # PORTS
        print("\n[PORT SCAN]")
        if self.results["ports"]:
            for port, data in self.results["ports"].items():
                print(f"{port}/tcp → {data}")
        else:
            print("No open ports found")

        # SQLi
        print("\n[SQLi]")
        if self.results["sqli"]:
            for v in self.results["sqli"]:
                print(f"{v['parameter']} → {v['url']}")
        else:
            print("No SQL Injection vulnerabilities found")

        # XSS
        print("\n[XSS]")
        if self.results["xss"]:
            for v in self.results["xss"]:
                print(f"{v['parameter']} → {v['url']}")
        else:
            print("No XSS vulnerabilities found")


# ================= CLI =================
def main():
    parser = argparse.ArgumentParser(
        description="ScanCLI - Web Vulnerability Scanner"
    )

    parser.add_argument("target", help="Target URL")

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
        default="fast"
    )

    parser.add_argument(
        "--verbose",
        action="store_true"
    )

    args = parser.parse_args()

    print("\n🔥 ScanCLI Started 🔥\n")

    scanner = ScannerEngine(
        target=args.target,
        scan_types=args.scan,
        port_mode=args.port_mode,
        verbose=args.verbose
    )

    scanner.run_all()


if __name__ == "__main__":
    main()
