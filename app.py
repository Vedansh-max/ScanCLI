import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from scanner.crawler import Crawler
from scanner.portscan import PortScanner
from scanner.sqli import SQLiScanner
from scanner.xss import XSSScanner


class ScannerEngine:
    def __init__(
        self,
        target,
        scan_types=None,
        port_mode="fast",
        timeout=10,
        max_pages=20,
        user_agent=None,
        verbose=False,
        quiet=False,
    ):
        self.target = target.rstrip("/")
        self.scan_types = scan_types or []
        self.port_mode = port_mode
        self.timeout = timeout
        self.max_pages = max_pages
        self.user_agent = user_agent
        self.verbose = verbose
        self.quiet = quiet

        self.results = {
            "target": self.target,
            "crawler": [],
            "ports": {},
            "sqli": [],
            "xss": [],
        }

    def log(self, message, force=False):
        if force or not self.quiet:
            print(message)

    def run_crawler(self):
        self.log("[+] Running crawler...")
        crawler = Crawler(
            self.target,
            max_pages=self.max_pages,
            timeout=self.timeout,
            user_agent=self.user_agent,
            verbose=self.verbose,
        )
        self.results["crawler"] = crawler.scan()

    def run_portscanner(self):
        self.log("[+] Scanning ports...")
        scanner = PortScanner(
            self.target,
            mode=self.port_mode,
            timeout=self.timeout,
            verbose=self.verbose,
        )
        self.results["ports"] = scanner.scan()

    def run_sqli(self):
        if not self.results["crawler"]:
            self.run_crawler()

        self.log("[+] Testing SQL injection...")
        sqli = SQLiScanner(
            self.results["crawler"],
            timeout=self.timeout,
            user_agent=self.user_agent,
            verbose=self.verbose,
        )
        self.results["sqli"] = sqli.scan()

    def run_xss(self):
        if not self.results["crawler"]:
            self.run_crawler()

        self.log("[+] Testing reflected XSS...")
        xss = XSSScanner(
            self.results["crawler"],
            timeout=self.timeout,
            user_agent=self.user_agent,
            verbose=self.verbose,
        )
        self.results["xss"] = xss.scan()

    def run_all(self):
        if not self.scan_types:
            self.log("[-] No scan selected", force=True)
            return self.results

        if ("sqli" in self.scan_types or "xss" in self.scan_types) and "crawler" not in self.scan_types:
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

        return self.results

    def print_results(self):
        print("\n========== RESULTS ==========\n")

        print("[SUMMARY]")
        print(f"Target: {self.target}")
        print(f"URLs discovered: {len(self.results['crawler'])}")
        print(f"Open ports: {len(self.results['ports'])}")
        print(f"SQLi findings: {len(self.results['sqli'])}")
        print(f"XSS findings: {len(self.results['xss'])}")

        print("\n[CRAWLER]")
        if self.results["crawler"]:
            for url in self.results["crawler"][:10]:
                print(f" - {url}")
            if len(self.results["crawler"]) > 10:
                print(f" ... and {len(self.results['crawler']) - 10} more")
        else:
            print("No URLs found")

        print("\n[PORT SCAN]")
        if self.results["ports"]:
            for port in sorted(self.results["ports"]):
                data = self.results["ports"][port]
                service = data.get("service", "unknown")
                method = data.get("method", "unknown")
                print(f" - {port}/tcp open ({service}, via {method})")
        else:
            print("No open ports found")

        print("\n[SQLi]")
        if self.results["sqli"]:
            for finding in self.results["sqli"]:
                print(f" - {finding['parameter']} -> {finding['url']}")
        else:
            print("No SQL injection indicators found")

        print("\n[XSS]")
        if self.results["xss"]:
            for finding in self.results["xss"]:
                print(f" - {finding['parameter']} -> {finding['url']}")
        else:
            print("No reflected XSS indicators found")


class ScanCLIArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        raise SystemExit(f"\nArgument error: {message}")


def normalize_target(target):
    parsed = urlparse(target)

    if not parsed.scheme:
        target = f"http://{target}"
        parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a valid HTTP or HTTPS URL or hostname")

    return target.rstrip("/")


def validate_timeout(value):
    if value <= 0:
        raise ValueError("Timeout must be greater than 0")
    return value


def validate_max_pages(value):
    if value <= 0:
        raise ValueError("max-pages must be greater than 0")
    return value


def save_results(path, results):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] Results saved to {output_path}")


def build_parser():
    parser = ScanCLIArgumentParser(
        description="ScanCLI - educational web security scanner for authorized testing"
    )

    parser.add_argument("target", help="Target URL or hostname")
    parser.add_argument(
        "--scan",
        nargs="+",
        choices=["crawler", "port", "sqli", "xss"],
        required=True,
        help="Select one or more scan modules",
    )
    parser.add_argument(
        "--port-mode",
        choices=["fast", "normal", "deep"],
        default="fast",
        help="Port scan depth for the port module",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request and scan timeout in seconds",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="Maximum number of internal pages to crawl",
    )
    parser.add_argument(
        "--user-agent",
        default="ScanCLI/1.0 (+authorized security testing)",
        help="Custom User-Agent header for HTTP requests",
    )
    parser.add_argument(
        "--output",
        help="Write results to a JSON file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce progress output and show final results only",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        target = normalize_target(args.target)
        timeout = validate_timeout(args.timeout)
        max_pages = validate_max_pages(args.max_pages)
    except ValueError as exc:
        raise SystemExit(f"Input error: {exc}") from exc

    if not args.quiet:
        print("\nScanCLI started\n")
        print("Use this tool only on systems you own or are authorized to test.\n")

    scanner = ScannerEngine(
        target=target,
        scan_types=args.scan,
        port_mode=args.port_mode,
        timeout=timeout,
        max_pages=max_pages,
        user_agent=args.user_agent,
        verbose=args.verbose,
        quiet=args.quiet,
    )

    results = scanner.run_all()
    scanner.print_results()

    if args.output:
        save_results(args.output, results)


if __name__ == "__main__":
    main()
