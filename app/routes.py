import os
import json
from datetime import datetime
from urllib import parse as urlparse
from urllib import request as urlrequest
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session
from werkzeug.utils import secure_filename
from .parser import parse_eml_bytes, extract_headers, extract_urls, extract_attachments, score_threat, scan_urls_virustotal, scan_urls_urlhaus, get_email_md5_hash, get_email_sha1_hash, get_email_sha256_hash
from .security import require_api_key, rate_limit

main = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {"eml"}


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _verify_turnstile(response_token: str) -> tuple[bool, str | None]:
    """
    Verify Cloudflare Turnstile token.
    Verification is enforced only when THREATPARSER_TURNSTILE_SECRET_KEY is set.
    """
    secret_key = current_app.config.get("TURNSTILE_SECRET_KEY", "").strip()
    if not secret_key:
        return True, None

    if not response_token:
        return False, "Please complete the Turnstile check before submitting."

    remote_ip = request.remote_addr or ""
    payload = {
        "secret": secret_key,
        "response": response_token,
        "remoteip": remote_ip,
    }
    body = urlparse.urlencode(payload).encode("utf-8")
    req = urlrequest.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urlrequest.urlopen(req, timeout=6) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
    except Exception:
        return False, "Turnstile verification is temporarily unavailable. Please try again."

    if data.get("success") is True:
        return True, None

    return False, "Turnstile verification failed. Please try again."


def _site_gate_is_enabled() -> bool:
    return bool(current_app.config.get("TURNSTILE_SITE_GATE_ENABLED"))


def _site_gate_has_required_keys() -> bool:
    return bool(
        current_app.config.get("TURNSTILE_SITE_KEY", "").strip()
        and current_app.config.get("TURNSTILE_SECRET_KEY", "").strip()
    )


def _sanitize_next_path(value: str) -> str:
    if not value or not value.startswith("/"):
        return url_for("main.index")
    if value.startswith("//"):
        return url_for("main.index")
    return value


@main.before_app_request
def enforce_turnstile_site_gate():
    """Require a one-time Turnstile check before serving UI pages."""
    if not _site_gate_is_enabled() or not _site_gate_has_required_keys():
        return None

    if request.path.startswith("/api/"):
        return None

    if request.endpoint in ("static", "main.turnstile_gate", "main.turnstile_gate_verify"):
        return None

    if session.get("turnstile_human_verified") is True:
        return None

    next_path = request.full_path if request.query_string else request.path
    return redirect(url_for("main.turnstile_gate", next=next_path))


@main.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        turnstile_site_key=current_app.config.get("TURNSTILE_SITE_KEY", ""),
        turnstile_site_gate_enabled=_site_gate_is_enabled() and _site_gate_has_required_keys(),
    )


@main.route("/human-check", methods=["GET"])
def turnstile_gate():
    next_path = _sanitize_next_path(request.args.get("next", ""))
    return render_template(
        "turnstile_gate.html",
        turnstile_site_key=current_app.config.get("TURNSTILE_SITE_KEY", ""),
        next_path=next_path,
    )


@main.route("/human-check/verify", methods=["POST"])
def turnstile_gate_verify():
    next_path = _sanitize_next_path(request.form.get("next", ""))
    turnstile_token = request.form.get("cf-turnstile-response", "").strip()
    turnstile_ok, turnstile_error = _verify_turnstile(turnstile_token)

    if not turnstile_ok:
        flash(turnstile_error or "Turnstile verification failed.", "danger")
        return redirect(url_for("main.turnstile_gate", next=next_path))

    session["turnstile_human_verified"] = True
    return redirect(next_path)


@main.route("/about", methods=["GET"])
def about():
    return render_template("about.html")


@main.route("/analyze", methods=["POST"])
def analyze():
    site_gate_active = _site_gate_is_enabled() and _site_gate_has_required_keys()

    if site_gate_active:
        if session.get("turnstile_human_verified") is not True:
            flash("Please complete the human verification check.", "danger")
            return redirect(url_for("main.turnstile_gate", next=url_for("main.index")))
    else:
        turnstile_token = request.form.get("cf-turnstile-response", "").strip()
        turnstile_ok, turnstile_error = _verify_turnstile(turnstile_token)
        if not turnstile_ok:
            flash(turnstile_error or "Turnstile verification failed.", "danger")
            return redirect(url_for("main.index"))

    if "eml_file" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("main.index"))

    f = request.files["eml_file"]

    if f.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("main.index"))

    if not _allowed_file(f.filename):
        flash("Only .eml files are supported.", "danger")
        return redirect(url_for("main.index"))

    file_bytes = f.read()
    # Enforce size limit manually (Werkzeug raises RequestEntityTooLarge but we
    # add a belt-and-suspenders check here)
    if len(file_bytes) > 10 * 1024 * 1024:
        flash("File exceeds the 10 MB limit.", "danger")
        return redirect(url_for("main.index"))

    try:
        msg = parse_eml_bytes(file_bytes)
        headers = extract_headers(msg)
        urls = extract_urls(msg)
        attachments = extract_attachments(msg)
    except Exception as exc:
        flash(f"Failed to parse email: {exc}", "danger")
        return redirect(url_for("main.index"))

    # Optional VirusTotal scan — run BEFORE scoring so results feed into threat score
    vt_api_key = request.form.get("vt_api_key", "").strip()
    vt_results = {}
    if vt_api_key and urls:
        try:
            vt_results = scan_urls_virustotal(urls, vt_api_key)
        except Exception as exc:
            flash(f"VirusTotal scan failed: {exc}", "warning")

    # Optional URLhaus scan — run BEFORE scoring so results feed into threat score
    urlhaus_api_key = request.form.get("urlhaus_api_key", "").strip()
    urlhaus_results = {}
    if urlhaus_api_key and urls:
        try:
            urlhaus_results = scan_urls_urlhaus(urls, urlhaus_api_key)
        except Exception as exc:
            flash(f"URLhaus scan failed: {exc}", "warning")

    try:
        threat = score_threat(headers, urls, attachments, vt_results=vt_results, urlhaus_results=urlhaus_results)
        file_info = {
            "size_bytes": len(file_bytes),
            "content_type": f.content_type,
            "md5": get_email_md5_hash(msg),
            "sha1": get_email_sha1_hash(msg),
            "sha256": get_email_sha256_hash(msg),
            "analysis_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as exc:
        flash(f"Failed to score email: {exc}", "danger")
        return redirect(url_for("main.index"))

    filename = secure_filename(f.filename)

    return render_template(
        "results.html",
        filename=filename,
        headers=headers,
        urls=urls,
        attachments=attachments,
        threat=threat,
        vt_results=vt_results,
        urlhaus_results=urlhaus_results,
        file_info=file_info
    )

# ----------------------------------- API Routes -----------------------------------

@main.route("/api/analyze", methods=["POST"])
@require_api_key
@rate_limit(requests_per_minute=20, config_key="RATE_LIMIT_ANALYZE")
def api_analyze():
    """
    Analyze an .eml file and return JSON results.

    Form fields:
      eml_file   — (required) the .eml file to analyze
      vt_api_key — (optional) VirusTotal API key; also accepted as the
                   X-VT-API-Key request header
    """
    if "eml_file" not in request.files:
        return jsonify(success=False, error="No file part in the request"), 400

    f = request.files["eml_file"]

    if f.filename == "":
        return jsonify(success=False, error="No file selected"), 400

    if not _allowed_file(f.filename):
        return jsonify(success=False, error="Only .eml files are supported"), 400

    file_bytes = f.read()
    if len(file_bytes) > 10 * 1024 * 1024:
        return jsonify(success=False, error="File exceeds the 10 MB limit"), 400

    try:
        msg = parse_eml_bytes(file_bytes)
        headers = extract_headers(msg)
        urls = extract_urls(msg)
        attachments = extract_attachments(msg)
    except Exception as exc:
        return jsonify(success=False, error=f"Failed to parse email: {exc}"), 500

    # VirusTotal: run BEFORE scoring so results feed into the threat score
    vt_api_key = (
        request.form.get("vt_api_key", "").strip()
        or request.headers.get("X-VT-API-Key", "").strip()
    )
    vt_results = {}
    vt_error = None
    if vt_api_key and urls:
        try:
            vt_results = scan_urls_virustotal(urls, vt_api_key)
        except Exception as exc:
            vt_error = str(exc)

    # URLhaus: run BEFORE scoring so results feed into the threat score
    urlhaus_api_key = (
        request.form.get("urlhaus_api_key", "").strip()
        or request.headers.get("X-URLhaus-API-Key", "").strip()
    )
    urlhaus_results = {}
    urlhaus_error = None
    if urlhaus_api_key and urls:
        try:
            urlhaus_results = scan_urls_urlhaus(urls, urlhaus_api_key)
        except Exception as exc:
            urlhaus_error = str(exc)

    try:
        threat = score_threat(headers, urls, attachments, vt_results=vt_results, urlhaus_results=urlhaus_results)
        file_info = {
            "filename": secure_filename(f.filename),
            "size_bytes": len(file_bytes),
            "md5": get_email_md5_hash(msg),
            "sha1": get_email_sha1_hash(msg),
            "sha256": get_email_sha256_hash(msg),
            "analysis_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as exc:
        return jsonify(success=False, error=f"Failed to score email: {exc}"), 500

    response = {
        "success": True,
        "file": file_info,
        "threat": {
            "score": threat["score"],
            "verdict": threat["verdict"],
            "verdict_class": threat["verdict_class"],
            "email_type": threat["email_type"],
            "findings": threat["findings"],
        },
        "headers": headers,
        "urls": urls,
        "attachments": attachments,
        "virustotal": vt_results if vt_api_key else None,
        "urlhaus": urlhaus_results if urlhaus_api_key else None,
    }
    if vt_error:
        response["virustotal_error"] = vt_error
    if urlhaus_error:
        response["urlhaus_error"] = urlhaus_error

    return jsonify(response), 200


@main.route("/api/health", methods=["GET"])
@rate_limit(requests_per_minute=60, config_key="RATE_LIMIT_HEALTH")
def api_health():
    """Liveness check."""
    return jsonify(status="ok", version="1.0.0"), 200


@main.route("/api/docs", methods=["GET"])
def api_docs():
    """Return a minimal API reference document."""
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "ThreatParser API", "version": "1.0.0"},
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/analyze",
                "description": "Analyze an .eml file and return threat intelligence as JSON.",
                "request": {
                    "content_type": "multipart/form-data",
                    "fields": {
                        "eml_file": "(required) The .eml file to analyze.",
                        "vt_api_key": "(optional) VirusTotal v3 API key. "
                                      "Can also be supplied via the X-VT-API-Key header.",
                    },
                },
                "response_200": {
                    "success": True,
                    "file": {
                        "filename": "string",
                        "size_bytes": "integer",
                        "md5": "string",
                        "sha1": "string",
                        "sha256": "string",
                        "analysis_time": "string (UTC)",
                    },
                    "threat": {
                        "score": "integer (0–100)",
                        "verdict": "string",
                        "verdict_class": "success | warning | danger",
                        "email_type": "clean | spam | phishing | mixed",
                        "findings": [
                            {
                                "severity": "low | medium | high | critical",
                                "category": "string",
                                "type_tag": "SPAM | PHISHING | null",
                                "detail": "string",
                            }
                        ],
                    },
                    "headers": "object — extracted email headers",
                    "urls": [
                        {
                            "url": "string",
                            "suspicious_flags": "array of strings",
                            "is_tracking": "boolean",
                            "file_ext": "string | null",
                            "file_type": "string | null",
                            "ext_suspicious": "boolean",
                        }
                    ],
                    "attachments": [
                        {
                            "filename": "string",
                            "content_type": "string",
                            "size_bytes": "integer",
                            "dangerous": "boolean",
                        }
                    ],
                    "virustotal": "object (url -> vt_result) or null if no key provided",
                },
            },
            {
                "method": "GET",
                "path": "/api/health",
                "description": "Liveness check. Returns {status: 'ok', version: '1.0.0'}.",
            },
            {
                "method": "GET",
                "path": "/api/docs",
                "description": "This document.",
            },
        ],
    }), 200

