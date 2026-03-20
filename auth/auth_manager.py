"""
Authentication module for V2 scanner.
Handles form-based login, cookie injection, and Bearer token auth.
Returns an authenticated RequestManager ready for scanning.
"""

import logging
from typing import Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Attempts to authenticate against a target web application
    and produces a session-carrying RequestManager.

    Supports three modes:
    - Form login: submits username/password to a detected or specified login form
    - Cookie injection: manually supplies session cookies
    - Token injection: injects a Bearer or custom Authorization header
    """

    def __init__(self, request_manager):
        self.rm = request_manager

    def form_login(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
    ) -> Tuple[bool, str]:
        """
        Perform form-based login.

        Steps:
        1. Fetch the login page and extract the form fields + any CSRF token
        2. Submit credentials to the form action URL
        3. Verify authentication succeeded by checking the response

        Args:
            login_url: URL of the login page
            username: Login username or email
            password: Login password
            username_field: HTML input name for username (auto-detected if blank)
            password_field: HTML input name for password (auto-detected if blank)

        Returns:
            (success: bool, message: str)
        """
        try:
            # Step 1: fetch login page
            page = self.rm.get(login_url)
            if not page:
                return False, f"Could not reach login page: {login_url}"

            soup = BeautifulSoup(page.text, "html.parser")
            form = self._find_login_form(soup)

            if not form:
                return False, "No login form found on the page. Try cookie or token auth instead."

            # Determine form submission URL
            action = form.get("action", "")
            method = form.get("method", "post").upper()
            submit_url = urljoin(login_url, action) if action else login_url

            # Build form data from all existing inputs
            form_data = self._extract_form_fields(form)

            # Auto-detect field names if not specified
            username_field = self._detect_field(form, ["username", "email", "user", "login", "name"]) or username_field
            password_field = self._detect_field(form, ["password", "pass", "passwd", "pwd"]) or password_field

            form_data[username_field] = username
            form_data[password_field] = password

            logger.info(f"Submitting login to {submit_url} [method={method}]")

            # Step 2: submit
            if method == "POST":
                resp = self.rm.post(submit_url, data=form_data)
            else:
                resp = self.rm.get(submit_url, params=form_data)

            if not resp:
                return False, "No response from login endpoint."

            # Step 3: verify success
            success, reason = self._verify_login(resp, login_url, username)
            return success, reason

        except Exception as e:
            logger.error(f"Form login error: {e}")
            return False, f"Login attempt failed with exception: {e}"

    def cookie_auth(self, cookies: Dict[str, str]) -> Tuple[bool, str]:
        """
        Inject manually provided cookies into the session.

        Args:
            cookies: dict of cookie name → value

        Returns:
            (True, confirmation message)
        """
        if not cookies:
            return False, "No cookies provided."
        self.rm.inject_cookies(cookies)
        cookie_names = ", ".join(cookies.keys())
        return True, f"Cookies injected into session: {cookie_names}"

    def token_auth(self, token: str, scheme: str = "Bearer") -> Tuple[bool, str]:
        """
        Inject an Authorization token into all future requests.

        Args:
            token: The token string
            scheme: Auth scheme prefix (Bearer, Token, etc.)

        Returns:
            (True, confirmation message)
        """
        if not token:
            return False, "No token provided."
        self.rm.inject_token(token, scheme)
        return True, f"{scheme} token injected into Authorization header."

    def verify_session(self, check_url: str, logged_in_indicator: Optional[str] = None) -> bool:
        """
        Verify the current session is authenticated by fetching a URL
        and optionally checking for a string that only appears when logged in.

        Args:
            check_url: URL to request
            logged_in_indicator: String to look for in the response (optional)

        Returns:
            True if session appears authenticated
        """
        resp = self.rm.get(check_url)
        if not resp:
            return False

        # If a specific indicator was given, check for it
        if logged_in_indicator:
            return logged_in_indicator.lower() in resp.text.lower()

        # Otherwise, assume logged in if we got a 200 and the page
        # doesn't redirect back to a login page
        if resp.status_code == 200:
            lower = resp.text.lower()
            login_signals = ["login", "sign in", "signin", "please log in", "access denied"]
            for signal in login_signals:
                if signal in lower and len(resp.text) < 5000:
                    return False
            return True

        return False

    # ── Private helpers ──────────────────────────────────────────────────────

    def _find_login_form(self, soup: BeautifulSoup):
        """Find the most likely login form on the page."""
        forms = soup.find_all("form")
        if not forms:
            return None

        # Prefer a form that has a password input
        for form in forms:
            inputs = form.find_all("input")
            types = [i.get("type", "text").lower() for i in inputs]
            if "password" in types:
                return form

        # Fall back to first form
        return forms[0]

    def _extract_form_fields(self, form) -> Dict[str, str]:
        """Pull all existing input values from a form (for CSRF tokens etc.)."""
        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            value = inp.get("value", "")
            inp_type = inp.get("type", "text").lower()
            if name and inp_type not in ("submit", "button", "reset", "file", "image"):
                data[name] = value
        for sel in form.find_all("select"):
            name = sel.get("name")
            if name:
                options = sel.find_all("option")
                data[name] = options[0].get("value", "") if options else ""
        return data

    def _detect_field(self, form, candidates: list) -> Optional[str]:
        """Find a form input whose name matches one of the candidate strings."""
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            for candidate in candidates:
                if candidate in name:
                    return inp.get("name")
        return None

    def _verify_login(self, resp, login_url: str, username: str) -> Tuple[bool, str]:
        """
        Heuristically determine if login succeeded.
        Checks: redirect away from login page, absence of error keywords,
        presence of username in response.
        """
        # If we ended up back on the login page, it failed
        final_url = resp.url if hasattr(resp, "url") else ""
        login_domain_path = urlparse(login_url).path.lower()
        final_path = urlparse(final_url).path.lower() if final_url else ""

        if login_domain_path and login_domain_path in final_path and resp.status_code == 200:
            body_lower = resp.text.lower()
            error_signals = [
                "invalid password", "invalid credentials", "login failed",
                "incorrect password", "wrong password", "authentication failed",
                "invalid username", "account not found",
            ]
            for signal in error_signals:
                if signal in body_lower:
                    return False, f"Login failed — server returned error: '{signal}'"

        # Positive signal: username appears in response
        if username.lower() in resp.text.lower():
            return True, f"Login succeeded — username '{username}' found in response."

        # Positive signal: redirected away from login page
        if final_url and login_domain_path not in final_path:
            return True, f"Login succeeded — redirected to {final_url}"

        # Ambiguous — assume success if no error was detected
        return True, "Login submitted — no error detected in response."
