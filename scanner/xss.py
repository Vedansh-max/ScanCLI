import requests
import threading
import urllib.parse
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import os


class XSSScanner:
    def __init__(self, target_urls: List[str], max_threads=10, timeout=5, verbose=False):
        """
        :param target_urls: List of URLs to scan
        :param max_threads: Number of worker threads
        :param timeout: HTTP timeout
        :param verbose: Debug output
        """
        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.results: List[Dict] = []
        self.found_set = set()
        self.lock = threading.Lock()

    # ================= LOAD PAYLOADS =================
    def load_payloads(self):
        payload_file = "payloads/xss.txt"

        if os.path.exists(payload_file):
            try:
                with open(payload_file, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error reading payload file: {e}")

        if self.verbose:
            print("[!] Using default XSS payloads")

        return [
            "<script>alert(1)</script>",
            "\"'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]

    # ================= EXTRACT PARAMS =================
    def extract_parameters(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())

    # ================= BUILD URL =================
    def build_url(self, url, param, payload):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        params[param] = [payload]

        new_query = urllib.parse.urlencode(params, doseq=True)

        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    # ================= CHECK REFLECTION =================
    def _is_reflected(self, baseline: str, test: str, payload: str) -> bool:
        baseline = baseline.lower()
        test = test.lower()
        payload = payload.lower()

        # Must appear in test but NOT in baseline
        return payload in test and payload not in baseline

    # ================= SCAN PARAM =================
    def _scan_param(self, url, param):
        try:
            baseline_response = requests.get(url, timeout=self.timeout).text
        except requests.RequestException:
            return

        for payload in self.payloads:
            test_url = self.build_url(url, param, payload)

            try:
                response = requests.get(test_url, timeout=self.timeout)

                if self._is_reflected(baseline_response, response.text, payload):

                    key = (url, param)

                    with self.lock:
                        if key not in self.found_set:
                            self.found_set.add(key)

                            vuln = {
                                "parameter": param,
                                "payload": payload,
                                "url": test_url,
                                "type": "Reflected XSS"
                            }

                            self.results.append(vuln)

                            if self.verbose:
                                print(f"[VULN] XSS → {param} → {test_url}")

            except requests.RequestException as e:
                if self.verbose:
                    print(f"[!] Request error: {e}")
                continue

    # ================= SCAN SINGLE URL =================
    def scan_single_url(self, url):
        params = self.extract_parameters(url)

        if not params:
            return

        for param in params:
            self._scan_param(url, param)

    # ================= MAIN SCAN =================
    def scan(self) -> List[Dict]:
        if self.verbose:
            print(f"[+] XSS Scan on {len(self.target_urls)} URLs")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [
                executor.submit(self.scan_single_url, url)
                for url in self.target_urls
            ]

            for future in as_completed(futures):
                future.result()

        if self.verbose:
            print(f"[✓] XSS Scan Completed → {len(self.results)} vulnerabilities")

        return self.results