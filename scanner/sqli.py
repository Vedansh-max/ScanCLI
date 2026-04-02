import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SQLiScanner:
    def __init__(self, target_urls, timeout=5, verbose=False):

        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.timeout = timeout
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.vulnerabilities = []

    # ================= LOAD PAYLOADS =================
    def load_payloads(self):
        try:
            with open("payloads/sqli.txt", "r") as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                "' OR 1=1--",
                "' OR '1'='1",
                "\" OR \"1\"=\"1"
            ]

    # ================= ERROR SIGNATURES =================
    def error_signatures(self):
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
    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        params[param] = [params[param][0] + payload]

        new_query = urlencode(params, doseq=True)

        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    # ================= CHECK VULNERABILITY =================
    def is_vulnerable(self, response_text):
        response_text = response_text.lower()
        return any(err in response_text for err in self.error_signatures())

    # ================= SCAN SINGLE URL =================
    def scan_url(self, url):

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        if self.verbose:
            print(f"[SCAN] {url}")

        for param in params:
            for payload in self.payloads:

                test_url = self.inject_payload(url, param, payload)

                try:
                    response = requests.get(test_url, timeout=self.timeout)

                    if self.is_vulnerable(response.text):
                        self.vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "url": test_url
                        })

                        if self.verbose:
                            print(f"[VULNERABLE] {test_url}")

                except requests.RequestException:
                    continue

    # ================= MAIN SCAN =================
    def scan(self):

        print(f"[+] SQLi Scan on {len(self.target_urls)} URLs")

        for url in self.target_urls:
            self.scan_url(url)

        print(f"[✓] Found {len(self.vulnerabilities)} vulnerabilities")

        return self.vulnerabilities
