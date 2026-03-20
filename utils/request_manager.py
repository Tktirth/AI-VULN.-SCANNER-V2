"""
HTTP request manager with session reuse, retry logic,
authenticated session support, and rate limiting.
V2 adds cookie/token injection for authenticated scanning.
"""

import time
import logging
from urllib.parse import urlparse
from typing import Optional, Dict

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; AIVulnScanner/2.0; Security Research)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class RequestManager:
    """
    Manages all HTTP traffic for the scanner.
    Supports unauthenticated and authenticated (cookie/token) modes.
    Built-in retry, SSL fallback, and configurable rate limiting.
    """

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 2,
        delay: float = 0.3,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self._request_count = 0

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(DEFAULT_HEADERS)

        if cookies:
            self.session.cookies.update(cookies)
        if extra_headers:
            self.session.headers.update(extra_headers)

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        return self._request(
            "GET", url,
            params=params,
            headers=headers,
            allow_redirects=allow_redirects,
        )

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        return self._request(
            "POST", url,
            data=data,
            headers=headers,
            allow_redirects=allow_redirects,
        )

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        extra = kwargs.pop("headers", None) or {}
        merged = {**DEFAULT_HEADERS, **extra}

        for attempt in range(self.max_retries + 1):
            try:
                time.sleep(self.delay)
                resp = self.session.request(
                    method, url,
                    headers=merged,
                    timeout=self.timeout,
                    verify=False,
                    **kwargs,
                )
                self._request_count += 1
                return resp
            except requests.exceptions.ConnectionError:
                if attempt < self.max_retries:
                    time.sleep(1)
            except requests.exceptions.Timeout:
                if attempt < self.max_retries:
                    time.sleep(1)
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed [{url}]: {e}")
                return None

        return None

    def inject_cookies(self, cookies: Dict[str, str]):
        """Add or update session cookies at runtime."""
        self.session.cookies.update(cookies)

    def inject_token(self, token: str, scheme: str = "Bearer"):
        """Inject an Authorization header for token-based auth."""
        self.session.headers.update({"Authorization": f"{scheme} {token}"})

    def is_same_domain(self, url: str, base_url: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except Exception:
            return False

    def get_request_count(self) -> int:
        return self._request_count

    def clone_unauthenticated(self) -> "RequestManager":
        """Return a fresh session with no auth — used for IDOR comparison requests."""
        return RequestManager(
            timeout=self.timeout,
            max_retries=self.max_retries,
            delay=self.delay,
        )

    def close(self):
        self.session.close()
