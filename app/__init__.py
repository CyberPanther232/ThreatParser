import os
from flask import Flask


def create_app():
    app = Flask(__name__)

    # ── Core ──────────────────────────────────────────────────────────────
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(24)
    app.config["TURNSTILE_SITE_KEY"] = os.environ.get("THREATPARSER_TURNSTILE_SITE_KEY", "").strip()
    app.config["TURNSTILE_SECRET_KEY"] = os.environ.get("THREATPARSER_TURNSTILE_SECRET_KEY", "").strip()
    app.config["TURNSTILE_SITE_GATE_ENABLED"] = (
        os.environ.get("THREATPARSER_TURNSTILE_SITE_GATE", "").lower() in ("1", "true", "yes")
    )

    # ── API security ──────────────────────────────────────────────────────
    # Comma-separated list of valid API keys.
    # Leave unset (or empty) to run in open/dev mode (no key required).
    app.config["API_KEYS"] = os.environ.get("THREATPARSER_API_KEYS", "")

    # Set to "1" / "true" when running behind a reverse proxy (nginx, etc.)
    # so that X-Forwarded-For is trusted for rate-limit keying.
    app.config["TRUSTED_PROXY"] = os.environ.get("THREATPARSER_TRUSTED_PROXY", "").lower() in ("1", "true", "yes")

    # ── Rate limits (requests per minute) ────────────────────────────────
    app.config["RATE_LIMIT_ANALYZE"] = int(os.environ.get("THREATPARSER_RATE_LIMIT_ANALYZE", "20"))
    app.config["RATE_LIMIT_HEALTH"]  = int(os.environ.get("THREATPARSER_RATE_LIMIT_HEALTH",  "60"))

    from .routes import main
    app.register_blueprint(main)

    return app
