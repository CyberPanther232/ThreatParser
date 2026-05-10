import os
from pathlib import Path
from app import create_app


def _load_local_dotenv() -> None:
    """
    Load environment variables from a local .env file if present.
    Existing process environment variables are not overwritten.
    """
    dotenv_path = Path(__file__).resolve().parent / ".env"
    if not dotenv_path.is_file():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        # Remove matching single or double quote wrappers.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]

        os.environ.setdefault(key, value)


_load_local_dotenv()
app = create_app()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_ssl_context():
    cert_file = os.environ.get("THREATPARSER_SSL_CERT_FILE", "").strip()
    key_file = os.environ.get("THREATPARSER_SSL_KEY_FILE", "").strip()
    ssl_enabled = _env_bool("THREATPARSER_SSL_ENABLED", default=False)
    ssl_adhoc = _env_bool("THREATPARSER_SSL_ADHOC", default=False)

    if cert_file or key_file:
        if not cert_file or not key_file:
            raise RuntimeError(
                "Both THREATPARSER_SSL_CERT_FILE and THREATPARSER_SSL_KEY_FILE "
                "must be set together."
            )
        if not os.path.isfile(cert_file):
            raise RuntimeError(f"SSL certificate file not found: {cert_file}")
        if not os.path.isfile(key_file):
            raise RuntimeError(f"SSL key file not found: {key_file}")
        return cert_file, key_file

    if ssl_enabled:
        if ssl_adhoc:
            # Werkzeug will generate a temporary self-signed cert for local testing.
            return "adhoc"
        raise RuntimeError(
            "SSL is enabled but no certificate/key files were configured. "
            "Set THREATPARSER_SSL_CERT_FILE + THREATPARSER_SSL_KEY_FILE, "
            "or set THREATPARSER_SSL_ADHOC=true for local development."
        )

    return None

if __name__ == "__main__":
    host = os.environ.get("THREATPARSER_HOST", "0.0.0.0")
    port = int(os.environ.get("THREATPARSER_PORT", "80"))
    debug = _env_bool("THREATPARSER_DEBUG", default=True)
    ssl_context = _get_ssl_context()

    app.run(debug=debug, port=port, host=host, ssl_context=ssl_context)
