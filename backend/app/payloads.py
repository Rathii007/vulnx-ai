"""
payloads.py — Attack payloads organised by vulnerability category.

╔══════════════════════════════════════════════════════════════════╗
║  ⚠  EDUCATIONAL USE ONLY                                       ║
║  Never use these payloads against systems you do not own or     ║
║  have explicit written permission to test.                      ║
╚══════════════════════════════════════════════════════════════════╝

HOW PAYLOADS WORK
─────────────────
A "payload" is a specially crafted input string that, if the target
application fails to validate or sanitise it, will trigger detectable
behaviour (e.g. the payload string appears verbatim in the HTML
response, or a SQL error message leaks out).

The scanner injects each payload into form fields or URL query
parameters and then inspects the HTTP response for indicators that
the payload was processed unsafely.
"""

# ── Cross-Site Scripting (XSS) ──────────────────────────────────────
# These payloads attempt to inject JavaScript.  If the response body
# contains the payload *unescaped*, the parameter is likely vulnerable.

XSS_PAYLOADS: list[str] = [
    # Classic script-tag injection
    '<script>alert("XSS")</script>',
    "<script>alert(1)</script>",

    # Event-handler injection (bypasses some naive tag filters)
    '"><img src=x onerror=alert(1)>',
    "' onfocus='alert(1)' autofocus='",

    # SVG-based injection (sometimes slips past WAFs)
    "<svg/onload=alert(1)>",

    # Injection inside an attribute value
    '" onmouseover="alert(1)"',
]

# ── SQL Injection ───────────────────────────────────────────────────
# These payloads try to break out of a SQL string context.
# We look for database error messages in the response to confirm
# the injection worked.

SQLI_PAYLOADS: list[str] = [
    # Tautology attack — always-true condition
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",

    # UNION-based detection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",

    # Error-based detection (MySQL / PostgreSQL / MSSQL)
    "1' AND 1=CONVERT(int, @@version)--",
]

# Strings that indicate a SQL error leaked into the response
SQLI_ERROR_SIGNATURES: list[str] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "postgresql query failed",
    "pg_query",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "ora-01756",
]

# ── Open Redirect ───────────────────────────────────────────────────
# These payloads try to force a redirect to an external domain.
# Common vulnerable parameter names: redirect, url, next, return, goto.

OPEN_REDIRECT_PAYLOADS: list[str] = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
]

REDIRECT_PARAM_NAMES: list[str] = [
    "redirect", "redirect_url", "redirect_uri",
    "url", "next", "return", "returnTo",
    "goto", "destination", "redir", "out",
]

# ── Sensitive Files ─────────────────────────────────────────────────
# Paths that should *never* be publicly accessible.  A 200 OK response
# (with expected content) indicates exposure.

SENSITIVE_FILE_PATHS: list[dict[str, str]] = [
    {
        "path": "/.env",
        "description": "Environment variables (may contain API keys, DB passwords)",
        "signatures": "SECRET=|TOKEN=|PASSWORD=|APP_KEY=|DB_", 
    },
    {
        "path": "/.git/config",
        "description": "Git configuration (exposes repository metadata)",
        "signatures": "[core]|repositoryformatversion",
    },
    {
        "path": "/.git/HEAD",
        "description": "Git HEAD ref (confirms .git directory exposure)",
        "signatures": "ref:",
    },
    {
        "path": "/backup.zip",
        "description": "Backup archive (may contain source code)",
        "signatures": "PK",
    },
    {
        "path": "/config.php",
        "description": "PHP configuration file",
        "signatures": "<?php",
    },
    {
        "path": "/wp-config.php",
        "description": "WordPress configuration (contains DB credentials)",
        "signatures": "DB_NAME|DB_USER|DB_PASSWORD",
    },
    {
        "path": "/phpinfo.php",
        "description": "PHP info page (leaks server configuration)",
        "signatures": "phpinfo()|PHP Version|PHP Credits",
    },
    {
        "path": "/.htaccess",
        "description": "Apache configuration file",
        "signatures": "RewriteEngine|RewriteRule|Deny from all",
    },
]

# ── Directory Listing ───────────────────────────────────────────────
# Strings that typically appear when a web server's directory indexing
# is enabled (Apache, Nginx, IIS, etc.).

DIRECTORY_LISTING_SIGNATURES: list[str] = [
    "Index of /",
    "Directory listing for",
    "[To Parent Directory]",          # IIS
    "Parent Directory",               # Apache
]

# ── Paths to probe for directory listing ────────────────────────────
DIRECTORY_LISTING_PATHS: list[str] = [
    "/images/",
    "/uploads/",
    "/assets/",
    "/static/",
    "/backup/",
    "/tmp/",
    "/admin/",
    "/includes/",
]
