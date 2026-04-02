import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

class Crawler:
    def __init__(self, base_url, max_threads=10, max_pages=20, timeout=5):

        self.base_url = base_url.rstrip("/")
        self.max_threads = max_threads
        self.max_pages = max_pages
        self.timeout = timeout

        self.visited = set()
        self.internal_links = set()
        self.lock = threading.Lock()
        self.domain = urlparse(self.base_url).netloc
        self.queue = deque([self.base_url])

    
    # Check if URL is internal
    def is_internal(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.domain

    
    # Normalize URL (remove fragments)
    def normalize_url(self, url):
        parsed = urlparse(url)
        clean = parsed.scheme + "://" + parsed.netloc + parsed.path
        if parsed.query:
            clean += "?" + parsed.query
        return clean.rstrip("/")

    
    # Extract links from a page
    def extract_links_from_page(self, url):
        links = []
        try:
            response = requests.get(url, timeout=self.timeout)
            if "text/html" not in response.headers.get("Content-Type", ""):
                return []
            soup = BeautifulSoup(response.text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag['href']

                # Skip javascript/mailto links
                if href.startswith("javascript:") or href.startswith("mailto:"):
                    continue

                absolute = urljoin(url, href)
                normalized = self.normalize_url(absolute)
                if self.is_internal(normalized):
                    links.append(normalized)
        except requests.RequestException:
            pass
        return links

    
    # Worker function for threading
    def _crawl_worker(self):
        while True:
            with self.lock:
                if not self.queue or len(self.visited) >= self.max_pages:
                    return
                current_url = self.queue.popleft()
                if current_url in self.visited:
                    continue
                self.visited.add(current_url)
            # Fetch links
            links = self.extract_links_from_page(current_url)
            with self.lock:
                for link in links:
                    if link not in self.visited and link not in self.queue:
                        self.queue.append(link)
                self.internal_links.update(links)

    
    # Public scan method
    def scan(self, verbose=False):
        """
        Run the crawler and return all internal links
        """

        if verbose:
            print(f"[+] Starting Crawl on {self.base_url}")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._crawl_worker) for _ in range(self.max_threads)]
            for future in as_completed(futures):
                future.result()

        if verbose:
            print(f"[✓] Crawl Completed. Total URLs: {len(self.internal_links)}")

        return list(self.internal_links)