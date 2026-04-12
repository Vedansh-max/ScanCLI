from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


class SQLiScanner:
    def __init__(self, target_urls, timeout=5, user_agent=None, verbose=False):
        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.timeout = timeout
        self.user_agent = user_agent or "ScanCLI/1.0"
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.vulnerabilities = []
        self._seen = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def load_payloads(self):
        payload_path = Path(__file__).resolve().parent.parent / "payloads" / "sqli.txt"
        try:
            return [line.strip() for line in payload_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except OSError:
            return ["' OR 1=1--", "' OR '1'='1", '" OR "1"="1']

    def error_signatures(self):
        return [
            "sql syntax",
            "mysql",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sqlite error",
            "postgresql",
            "fatal error",
            "odbc",
            "sqlstate",
        ]

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_value = params.get(param, [""])[0]
        params[param] = [base_value + payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def is_vulnerable(self, response_text):
        text = response_text.lower()
        return any(signature in text for signature in self.error_signatures())

    def scan_url(self, url):
        params = parse_qs(urlparse(url).query)
        if not params:
            return

        if self.verbose:
            print(f"[SCAN] {url}")

        for param in params:
            for payload in self.payloads:
                test_url = self.inject_payload(url, param, payload)
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                except requests.RequestException:
                    continue

                if not self.is_vulnerable(response.text):
                    continue

                key = (param, test_url)
                if key in self._seen:
                    continue
                self._seen.add(key)

                finding = {
                    "parameter": param,
                    "payload": payload,
                    "url": test_url,
                    "type": "error-based",
                }
                self.vulnerabilities.append(finding)
                if self.verbose:
                    print(f"[VULNERABLE] {test_url}")
                break

    def scan(self):
        print(f"[+] SQLi scan on {len(self.target_urls)} URLs")
        for url in self.target_urls:
            self.scan_url(url)
        print(f"[+] Found {len(self.vulnerabilities)} SQLi indicators")
        return self.vulnerabilities
