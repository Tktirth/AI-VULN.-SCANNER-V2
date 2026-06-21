"""
BFS web crawler — V2.
Works with authenticated sessions for post-login page discovery.
"""

import logging
from collections import deque
from urllib.parse import urlparse, urljoin, urldefrag
from typing import List, Set, Dict, Any, Optional, Callable

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    BFS crawler that discovers internal pages up to a configurable depth.
    Uses the provided RequestManager — so if it carries auth cookies,
    the crawl will discover authenticated pages too.
    """

    def __init__(
        self,
        base_url: str,
        request_manager,
        max_pages: int = 30,
        max_depth: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.rm = request_manager
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.discovered: List[str] = []

    def crawl(self, progress_callback: Optional[Callable] = None) -> List[str]:
        queue = deque([(self.base_url, 0)])
        self.visited.add(self.base_url)

        while queue and len(self.discovered) < self.max_pages:
            url, depth = queue.popleft()
            if depth > self.max_depth:
                continue

            try:
                resp = self.rm.get(url)
                if not resp:
                    continue

                content_type = resp.headers.get("Content-Type", "")
                self.discovered.append(url)

                if progress_callback:
                    progress_callback(len(self.discovered), self.max_pages, url)

                if "text/html" not in content_type:
                    continue

                for link in self._extract_links(resp.text, url):
                    norm = self._normalize(link)
                    if norm and norm not in self.visited and self._is_internal(norm):
                        self.visited.add(norm)
                        queue.append((norm, depth + 1))

            except Exception as e:
                logger.debug(f"Crawl error [{url}]: {e}")

        logger.info(f"Crawl complete: {len(self.discovered)} pages")
        return self.discovered

    def get_urls_with_params(self) -> List[str]:
        return [u for u in self.discovered if "?" in u]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_pages": len(self.discovered),
            "pages_with_params": len(self.get_urls_with_params()),
            "requests_made": self.rm.get_request_count(),
        }

    def _extract_links(self, html: str, base: str) -> List[str]:
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    links.append(urljoin(base, href))
        except Exception:
            pass
        return links

    def _normalize(self, url: str) -> str:
        try:
            url, _ = urldefrag(url)
            return url.rstrip("/") if len(url) > len(self.base_url) else url
        except Exception:
            return ""

    def _is_internal(self, url: str) -> bool:
        try:
            p = urlparse(url)
            return p.netloc == self.base_domain and p.scheme in ("http", "https")
        except Exception:
            return False
