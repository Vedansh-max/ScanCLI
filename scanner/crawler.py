from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, base_url, max_pages=20, timeout=5, user_agent=None, verbose=False):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent or "ScanCLI/1.0"
        self.verbose = verbose

        self.visited = set()
        self.internal_links = set()

        self.domain = urlparse(self.base_url).netloc
        self.queue = [self.base_url]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def is_internal(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.domain

    def normalize_url(self, url):
        parsed = urlparse(url)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        return clean.rstrip("/")

    def extract_links(self, url):
        links = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            if "text/html" not in response.headers.get("Content-Type", ""):
                return []

            soup = BeautifulSoup(response.text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("javascript:", "mailto:", "tel:")):
                    continue

                absolute = urljoin(url, href)
                normalized = self.normalize_url(absolute)
                if self.is_internal(normalized):
                    links.append(normalized)
        except requests.RequestException as exc:
            if self.verbose:
                print(f"[!] Error fetching {url}: {exc}")
        return links

    def scan(self):
        if self.verbose:
            print(f"[+] Starting crawl on {self.base_url}")

        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.pop(0)
            if current_url in self.visited:
                continue

            if self.verbose:
                print(f"[CRAWLING] {current_url}")

            self.visited.add(current_url)
            links = self.extract_links(current_url)

            for link in links:
                if link not in self.visited and link not in self.queue:
                    self.queue.append(link)

            self.internal_links.update(links)

        if self.verbose:
            print(f"[+] Crawl completed -> {len(self.internal_links)} URLs found")

        return sorted(self.internal_links)
