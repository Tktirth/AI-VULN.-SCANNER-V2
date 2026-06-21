"""
CSRF detector — V2.
"""
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from utils.request_manager import RequestManager

logger = logging.getLogger(__name__)

def detect_csrf(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    try:
        resp = request_manager.get(url)
        if not resp:
            return vulns
        
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            if method != "POST":
                continue
                
            action = form.get("action", url)
            form_url = urljoin(url, action)
            
            # Check if form has a CSRF token
            has_csrf = False
            token_candidates = ["csrf", "xsrf", "token", "anti-forgery"]
            inputs = form.find_all("input")
            for inp in inputs:
                name = (inp.get("name") or "").lower()
                if any(candidate in name for candidate in token_candidates):
                    has_csrf = True
                    break
                    
            if not has_csrf:
                # Form is missing CSRF token!
                # Now verify if it accepts POST from a new session
                new_session_rm = RequestManager(timeout=request_manager.timeout, delay=request_manager.delay)
                
                # Build dummy form data
                form_data = {}
                for inp in inputs:
                    name = inp.get("name")
                    itype = inp.get("type", "text").lower()
                    if name and itype not in ("submit", "button", "reset", "file"):
                        form_data[name] = inp.get("value", "test")
                
                # Try submitting POST with new session
                try:
                    csrf_resp = new_session_rm.post(form_url, data=form_data)
                    # If it returns 200, 201, 302, it accepted it
                    if csrf_resp and csrf_resp.status_code in (200, 201, 302):
                        vulns.append({
                            "type": "CSRF",
                            "subtype": "Missing CSRF Token on POST Form",
                            "url": url,
                            "parameter": "Form: " + action,
                            "payload": "POST request from new session",
                            "method": "POST",
                            "evidence": f"Form at {form_url} lacks CSRF token and accepted POST from new session (status {csrf_resp.status_code})",
                            "description": (
                                f"CSRF vulnerability detected in form action '{action}'. "
                                f"The form accepts POST requests but lacks a CSRF anti-forgery token, "
                                f"and successfully processed a POST request from a completely new session."
                            ),
                            "remediation": (
                                "Implement stateful anti-CSRF tokens in all state-changing POST forms. "
                                "Use double-submit cookie pattern or synchronized token pattern. "
                                "Ensure cookies have SameSite=Lax or SameSite=Strict attributes."
                            )
                        })
                except Exception as e:
                    logger.debug(f"CSRF POST test failed: {e}")
                finally:
                    new_session_rm.close()
                    
    except Exception as e:
        logger.debug(f"CSRF extraction error for {url}: {e}")
        
    return vulns
