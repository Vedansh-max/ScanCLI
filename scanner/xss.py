from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


class XSSScanner:
    def __init__(self, target_urls, timeout=10, user_agent=None, verbose=False):
        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.timeout = timeout
        self.user_agent = user_agent or "ScanCLI/1.0"
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.results = []
        self._seen = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def load_payloads(self):
        payload_path = Path(__file__).resolve().parent.parent / "payloads" / "xss.txt"
        try:
            return [line.strip() for line in payload_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except OSError:
            return [
                "<script>alert(1)</script>",
                '\"\'><script>alert(1)</script>',
                "<img src=x onerror=alert(1)>",
            ]

    def extract_params(self, url):
        return parse_qs(urlparse(url).query)

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def reflected(self, baseline, candidate, payload):
        baseline_text = baseline.lower()
        candidate_text = candidate.lower()
        payload_text = payload.lower()
        return payload_text in candidate_text and payload_text not in baseline_text

    def scan_url(self, url):
        params = self.extract_params(url)
        if not params:
            return

        if self.verbose:
            print(f"[SCAN] {url}")

        try:
            baseline_response = self.session.get(url, timeout=self.timeout)
            baseline_text = baseline_response.text
        except requests.RequestException:
            baseline_text = ""

        for param in params:
            for payload in self.payloads:
                test_url = self.inject_payload(url, param, payload)
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                except requests.RequestException:
                    continue

                if not self.reflected(baseline_text, response.text, payload):
                    continue

                key = (param, test_url)
                if key in self._seen:
                    continue
                self._seen.add(key)

                finding = {
                    "parameter": param,
                    "payload": payload,
                    "url": test_url,
                    "type": "reflected",
                }
                self.results.append(finding)
                if self.verbose:
                    print(f"[VULNERABLE] {test_url}")
                break

    def scan(self):
        print(f"[+] XSS scan on {len(self.target_urls)} URLs")
        for url in self.target_urls:
            self.scan_url(url)
        print(f"[+] Found {len(self.results)} XSS indicators")
        return self.results
