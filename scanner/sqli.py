import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os


class SQLiScanner:
    def __init__(self, target_urls: List[str], timeout: int = 5, max_threads: int = 10, verbose=False):
        """
        Initialize SQL Injection Scanner
        """
        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.error_signatures = self._error_signatures()

        self.vulnerabilities: List[Dict] = []
        self.found_set = set()  # for deduplication
        self.lock = threading.Lock()

    # ================= LOAD PAYLOADS =================
    def load_payloads(self):
        payload_file = "payloads/sqli.txt"

        if os.path.exists(payload_file):
            try:
                with open(payload_file, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error reading payload file: {e}")

        # fallback payloads
        if self.verbose:
            print("[!] Using default SQLi payloads")

        return [
            "' OR 1=1--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' AND 1=2--",
        ]

    # ================= ERROR SIGNATURES =================
    def _error_signatures(self) -> List[str]:
        return [
            "sql syntax",
            "mysql",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sqlite error",
            "postgresql",
            "fatal error"
        ]

    # ================= INJECT PAYLOAD =================
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if param in query_params:
            query_params[param] = [query_params[param][0] + payload]

        new_query = urlencode(query_params, doseq=True)

        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    # ================= CHECK VULNERABILITY =================
    def _is_vulnerable(self, baseline: str, test: str) -> bool:
        baseline = baseline.lower()
        test = test.lower()

        # Only flag if error appears in test but NOT in baseline
        return any(
            error in test and error not in baseline
            for error in self.error_signatures
        )

    # ================= SCAN PARAM =================
    def _scan_url_param(self, url: str, param: str):
        try:
            baseline_response = requests.get(url, timeout=self.timeout).text
        except requests.RequestException:
            return

        for payload in self.payloads:
            test_url = self._inject_payload(url, param, payload)

            try:
                response = requests.get(test_url, timeout=self.timeout)

                if self._is_vulnerable(baseline_response, response.text):

                    key = (url, param)

                    with self.lock:
                        if key not in self.found_set:
                            self.found_set.add(key)

                            vuln = {
                                "parameter": param,
                                "payload": payload,
                                "url": test_url,
                                "type": "Error-Based SQL Injection"
                            }

                            self.vulnerabilities.append(vuln)

                            if self.verbose:
                                print(f"[VULN] {param} → {test_url}")

            except requests.RequestException as e:
                if self.verbose:
                    print(f"[!] Request error: {e}")
                continue

    # ================= SCAN SINGLE URL =================
    def _scan_single_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param in params.keys():
            self._scan_url_param(url, param)

    # ================= MAIN SCAN =================
    def scan(self) -> List[Dict]:
        if self.verbose:
            print(f"[+] SQLi Scan on {len(self.target_urls)} URLs")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [
                executor.submit(self._scan_single_url, url)
                for url in self.target_urls
            ]

            for future in as_completed(futures):
                future.result()

        if self.verbose:
            print(f"[✓] SQLi Scan Completed → {len(self.vulnerabilities)} vulnerabilities")

        return self.vulnerabilities

    # ================= SUMMARY =================
    def get_summary(self) -> Dict:
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "details": self.vulnerabilities
        }