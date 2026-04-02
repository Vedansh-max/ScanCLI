import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class Crawler:
    def __init__(self, base_url, max_pages=20, timeout=5, verbose=False):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.verbose = verbose

        self.visited = set()
        self.internal_links = set()

        self.domain = urlparse(self.base_url).netloc
        self.queue = [self.base_url]

    # ================= CHECK INTERNAL =================
    def is_internal(self, url):
        return urlparse(url).netloc == self.domain

    # ================= NORMALIZE =================
    def normalize_url(self, url):
        parsed = urlparse(url)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            clean += f"?{parsed.query}"

        return clean.rstrip("/")

    # ================= EXTRACT LINKS =================
    def extract_links(self, url):
        links = []

        try:
            response = requests.get(url, timeout=self.timeout)

            if "text/html" not in response.headers.get("Content-Type", ""):
                return []

            soup = BeautifulSoup(response.text, "html.parser")

            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]

                if href.startswith("javascript:") or href.startswith("mailto:"):
                    continue

                absolute = urljoin(url, href)
                normalized = self.normalize_url(absolute)

                if self.is_internal(normalized):
                    links.append(normalized)

        except requests.RequestException as e:
            if self.verbose:
                print(f"[!] Error fetching {url}: {e}")

        return links

    # ================= MAIN SCAN =================
    def scan(self):
        if self.verbose:
            print(f"[+] Starting Crawl on {self.base_url}")

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
            print(f"[✓] Crawl Completed → {len(self.internal_links)} URLs")

        return list(self.internal_links)
