"""
API security helpers: key authentication and in-memory rate limiting.

Rate limiting uses a sliding-window counter (per IP or per API key).
No external dependencies required.
"""
import time
import hmac
import hashlib
import threading
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, current_app


# ---------------------------------------------------------------------------
# Thread-safe in-memory sliding-window rate limiter
# ---------------------------------------------------------------------------

_lock = threading.Lock()
# Structure: { identifier: [(timestamp, count), ...] }
_windows: dict[str, list] = defaultdict(list)


def _check_rate_limit(identifier: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """
    Returns (allowed: bool, remaining: int).
    Uses a sliding window: counts requests made within the last `window_seconds`.
    """
    now = time.monotonic()
    cutoff = now - window_seconds

    with _lock:
        # Evict expired buckets
        _windows[identifier] = [ts for ts in _windows[identifier] if ts > cutoff]
        count = len(_windows[identifier])
        if count >= limit:
            return False, 0
        _windows[identifier].append(now)
        return True, limit - count - 1


# ---------------------------------------------------------------------------
# API key validation
# ---------------------------------------------------------------------------

def _get_api_keys() -> set[str]:
    """
    Return the configured set of valid API keys.
    Keys are stored in THREATPARSER_API_KEYS as a comma-separated string.
    If the config value is empty / unset, API key enforcement is disabled.
    """
    raw = current_app.config.get("API_KEYS", "")
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def _constant_time_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison to prevent timing attacks."""
    return hmac.compare_digest(
        hashlib.sha256(a.encode()).digest(),
        hashlib.sha256(b.encode()).digest(),
    )


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_api_key(f):
    """
    Decorator: require a valid API key in the X-API-Key header.
    Skipped entirely when no API keys are configured (open mode).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        valid_keys = _get_api_keys()
        if not valid_keys:
            # No keys configured — open access (dev mode)
            return f(*args, **kwargs)

        provided = request.headers.get("X-API-Key", "").strip()
        if not provided:
            return jsonify(success=False, error="Missing X-API-Key header."), 401

        if not any(_constant_time_compare(provided, k) for k in valid_keys):
            return jsonify(success=False, error="Invalid API key."), 403

        return f(*args, **kwargs)
    return decorated


def rate_limit(requests_per_minute: int = 30, config_key: str = None):
    """
    Decorator factory: sliding-window rate limit per remote IP.
    If `config_key` is given, the limit is read from app config at call
    time, falling back to `requests_per_minute` if the key is absent.
    Uses the X-Forwarded-For header when behind a trusted proxy
    (controlled by THREATPARSER_TRUSTED_PROXY config flag).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            limit = (
                current_app.config.get(config_key, requests_per_minute)
                if config_key
                else requests_per_minute
            )

            if current_app.config.get("TRUSTED_PROXY"):
                ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
                # Only take the first (client) IP from the chain
                ip = ip.split(",")[0].strip()
            else:
                ip = request.remote_addr or "unknown"

            identifier = f"{f.__name__}:{ip}"
            allowed, remaining = _check_rate_limit(identifier, limit, 60)

            if not allowed:
                resp = jsonify(
                    success=False,
                    error=f"Rate limit exceeded. Max {limit} requests/minute.",
                )
                resp.headers["Retry-After"] = "60"
                resp.headers["X-RateLimit-Limit"] = str(limit)
                resp.headers["X-RateLimit-Remaining"] = "0"
                return resp, 429

            response = f(*args, **kwargs)

            # Attach rate-limit headers to successful responses
            if isinstance(response, tuple):
                resp_obj, status = response[0], response[1]
            else:
                resp_obj, status = response, 200

            resp_obj.headers["X-RateLimit-Limit"] = str(limit)
            resp_obj.headers["X-RateLimit-Remaining"] = str(remaining)

            return resp_obj, status
        return decorated
    return decorator
