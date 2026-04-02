import requests
import urllib.parse


class XSSScanner:
    def __init__(self, target_urls, timeout=300, verbose=False):

        if isinstance(target_urls, str):
            target_urls = [target_urls]

        self.target_urls = target_urls
        self.timeout = timeout
        self.verbose = verbose

        self.payloads = self.load_payloads()
        self.results = []

    # ================= LOAD PAYLOADS =================
    def load_payloads(self):
        try:
            with open("payloads/xss.txt", "r") as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                "<script>alert(1)</script>",
                "\"'><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>"
            ]

    # ================= EXTRACT PARAMETERS =================
    def extract_params(self, url):
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query)

    # ================= BUILD URL =================
    def inject_payload(self, url, param, payload):
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

    # ================= SCAN SINGLE URL =================
    def scan_url(self, url):

        params = self.extract_params(url)

        if not params:
            return

        if self.verbose:
            print(f"[SCAN] {url}")

        for param in params:
            for payload in self.payloads:

                test_url = self.inject_payload(url, param, payload)

                try:
                    response = requests.get(test_url, timeout=self.timeout)

                    # Basic reflected XSS detection
                    if payload.lower() in response.text.lower():
                        self.results.append({
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

        print(f"[+] XSS Scan on {len(self.target_urls)} URLs")

        for url in self.target_urls:
            self.scan_url(url)

        print(f"[✓] Found {len(self.results)} vulnerabilities")

        return self.results
