"""Secure-by-default constants.

The safe configuration IS the zero-config configuration (Principle 1). Every value
here is a hardened default the integrator may override — but never has to, to be safe.
"""
from __future__ import annotations

# --- Security headers (module: headers) -------------------------------------
# Strict, OWASP-aligned defaults. ASVS V14.4 / V14.5.
DEFAULT_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    # HSTS is added dynamically only over HTTPS (see headers module).
}

# Strict default CSP: deny everything, allow self. Override per app as needed.
DEFAULT_CSP: str = (
    "default-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "upgrade-insecure-requests"
)

DEFAULT_HSTS_MAX_AGE = 63072000  # 2 years, includeSubDomains + preload friendly

# --- Session / cookies (module: session) ------------------------------------
DEFAULT_COOKIE_FLAGS = {
    "httponly": True,
    "secure": True,        # forced True in production (boot gate)
    "samesite": "Lax",     # "Strict" available; Lax balances CSRF + UX
    "path": "/",
}
DEFAULT_SESSION_TTL = 3600          # 1 hour
DEFAULT_SESSION_IDLE_TTL = 900      # 15 min idle

# --- Rate limiting (module: ratelimit) --------------------------------------
DEFAULT_RATE_LIMIT_PER_IP = (300, 60)        # 300 requests / 60s per IP
DEFAULT_RATE_LIMIT_PER_IDENTITY = (120, 60)  # 120 requests / 60s per identity
# Auth endpoints get their own, much tighter bucket + lockout:
DEFAULT_AUTH_RATE_LIMIT = (5, 60)            # 5 attempts / 60s
DEFAULT_LOCKOUT_THRESHOLD = 5                # failures before lockout
DEFAULT_LOCKOUT_BASE_SECONDS = 30            # exponential backoff base

# --- AuthN / tokens (module: authn) -----------------------------------------
DEFAULT_JWT_ALGORITHM = "HS256"     # symmetric default; RS256/EdDSA supported
DEFAULT_ACCESS_TTL = 900            # 15 min access token
DEFAULT_REFRESH_TTL = 1209600       # 14 day refresh token
DEFAULT_JWT_LEEWAY = 10             # clock-skew tolerance (s)

# --- Anomaly (module: anomaly) ----------------------------------------------
DEFAULT_ANOMALY_AUTHFAIL_THRESHOLD = 10   # auth failures in window -> alert
DEFAULT_ANOMALY_WINDOW = 300              # 5 min

# --- Deception (module: deception) ------------------------------------------
# Decoy paths no legitimate client ever requests. A hit is a high-confidence probe:
# the source IP is flagged, blocklisted, and cut off from every endpoint.
DEFAULT_HONEYPOT_PATHS = (
    "/.env", "/.git/config", "/.git/HEAD", "/.aws/credentials", "/.ssh/id_rsa",
    "/wp-login.php", "/wp-admin", "/admin.php", "/phpmyadmin", "/actuator/env",
    "/server-status", "/config.json", "/.DS_Store", "/vendor/phpunit",
)
DEFAULT_DECEPTION_BLOCK_TTL = 3600  # keep a trapped IP blocked for 1 hour

# --- Egress / SSRF guard (service: egress) ----------------------------------
DEFAULT_EGRESS_ALLOWED_SCHEMES = ("https",)  # add "http" only via egress_allow_http

# Weak/placeholder secrets that must never reach production.
SECRET_DENYLIST = frozenset(
    {
        "", "changeme", "change-me", "secret", "password", "default",
        "test", "dev", "aegis", "todo", "xxx", "placeholder", "your-secret-key",
    }
)
