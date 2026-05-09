import re
import json
import ssl
import base64
import urllib.request
import urllib.parse
import urllib.error
from email import policy
from email.parser import BytesParser
from email.header import decode_header
import hashlib
import os

HEADER_FIELDS = [
    "From", "To", "Cc", "Bcc", "Reply-To",
    "Subject", "Date", "Message-ID",
    "Return-Path", "X-Mailer", "X-Originating-IP",
    "Received-SPF", "DKIM-Signature", "Authentication-Results",
    "List-Unsubscribe", "Feedback-ID", "X-SG-EID",
    "X-Campaign-ID", "X-Mailer-LID",
]

PHISHING_KEYWORDS = [
    "invoice", "payment", "urgent", "password", "account", "security",
    "update", "verify", "click", "login", "bank", "paypal", "amazon",
    "apple", "microsoft", "google", "facebook", "twitter",
    "free", "offer", "win", "prize", "lottery", "congratulations",
    "limited time", "act now", "attachment", "document", "pdf", "xls",
    "doc", "zip", "exe", "phishing", "scam", "malware", "virus",
    "ransomware", "spyware", "important", "notice", "alert", "warning",
    "confirm", "suspend", "reactivate",
]

SPAM_KEYWORDS = [
    "free", "win", "winner", "prize", "lottery",
    "congratulations", "limited time", "act now", "offer", "cheap",
    "discount", "rebate", "bonus", "cash", "credit", "debt",
    "loan", "mortgage", "insurance",    "sale", "deal", "shop", "buy now", "order now", "promo", "coupon",
    "unsubscribe", "newsletter", "save", "% off", "subscribe",
    "click here", "shop now", "view in browser", "manage preferences",
]

BULK_MAIL_HEADERS = [
    "List-Unsubscribe", "Feedback-ID", "X-SG-EID",
    "X-Campaign-ID", "X-Mailer-LID",
]

SPAM_TRACKING_PATTERNS = [
    re.compile(r'tracksg\.', re.IGNORECASE),
    re.compile(r'/ls/click', re.IGNORECASE),
    re.compile(r'[?&]upn=', re.IGNORECASE),
    re.compile(r'/wf/open', re.IGNORECASE),
    re.compile(r'\.(sendgrid|mailchimp|klaviyo|constantcontact)\.', re.IGNORECASE),
    re.compile(r'(mandrillapp|mailgun|sparkpost|brevo)\.(com|net)', re.IGNORECASE),
    re.compile(r'[?&](utm_source|utm_medium|utm_campaign)=', re.IGNORECASE),
    re.compile(r'[?&](mc_eid|mc_cid|sg_eid|fbclid|gclid)=', re.IGNORECASE),]

# File extension type mapping: ext -> (type_label, is_suspicious)
FILE_EXT_MAP = {
    # Images — benign
    ".png": ("image", False), ".jpg": ("image", False), ".jpeg": ("image", False),
    ".gif": ("image", False), ".bmp": ("image", False), ".svg": ("image", False),
    ".webp": ("image", False), ".ico": ("image", False),
    # Video — benign
    ".mp4": ("video", False), ".avi": ("video", False), ".mov": ("video", False),
    ".wmv": ("video", False), ".mkv": ("video", False), ".flv": ("video", False),
    # Audio — benign
    ".mp3": ("audio", False), ".wav": ("audio", False), ".flac": ("audio", False),
    ".aac": ("audio", False), ".ogg": ("audio", False),
    # Documents — macro-enabled variants are suspicious
    ".pdf": ("document", False), ".doc": ("document", True), ".docx": ("document", False),
    ".docm": ("document", True), ".xls": ("document", True), ".xlsx": ("document", False),
    ".xlsm": ("document", True), ".ppt": ("document", False), ".pptx": ("document", False),
    ".pptm": ("document", True), ".rtf": ("document", False),
    # Archives — suspicious (often used to smuggle payloads)
    ".zip": ("archive", True), ".rar": ("archive", True), ".7z": ("archive", True),
    ".tar": ("archive", True), ".gz": ("archive", True), ".bz2": ("archive", True),
    ".iso": ("archive", True), ".cab": ("archive", True),
    # Executables — highly suspicious
    ".exe": ("executable", True), ".bat": ("executable", True), ".cmd": ("executable", True),
    ".scr": ("executable", True), ".pif": ("executable", True), ".msi": ("executable", True),
    ".jar": ("executable", True), ".appx": ("executable", True),
    ".deb": ("executable", True), ".rpm": ("executable", True),
    # Scripts — highly suspicious
    ".vbs": ("script", True), ".js": ("script", True), ".ps1": ("script", True),
    ".sh": ("script", True), ".py": ("script", True), ".rb": ("script", True),
    ".pl": ("script", True), ".hta": ("script", True), ".wsf": ("script", True),
    # Web / data — benign
    ".html": ("webpage", False), ".htm": ("webpage", False),
    ".php": ("webpage", False), ".asp": ("webpage", False), ".aspx": ("webpage", False),
    ".json": ("data", False), ".xml": ("data", False), ".csv": ("data", False),
    ".txt": ("text", False),
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+')

SUSPICIOUS_URL_PATTERNS = [
    (re.compile(r'@'),                                                               "Credentials in URL"),
    (re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),                          "Raw IP address"),
    (re.compile(r'(login|verify|secure|account|update|confirm)', re.IGNORECASE),    "Phishing keyword in URL"),
    (re.compile(r'\.exe$|\.zip$|\.scr$|\.pif$|\.msi$', re.IGNORECASE),            "Suspicious file extension"),
    (re.compile(r'bit\.ly|goo\.gl|t\.co|tinyurl\.com', re.IGNORECASE),            "URL shortener"),
    (re.compile(r'tracking|analytics|click|track|tracks', re.IGNORECASE),           "Tracking URL"),
]

# Brand name -> set of legitimate sender domains
BRAND_IMPERSONATION_MAP = {
    "PayPal":     {"paypal.com"},
    "Amazon":     {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
                   "amazon.co.jp", "amazon.ca", "amazon.com.au"},
    "Apple":      {"apple.com", "icloud.com"},
    "Microsoft":  {"microsoft.com", "outlook.com", "hotmail.com",
                   "live.com", "office.com", "office365.com"},
    "Google":     {"google.com", "gmail.com", "googlemail.com"},
    "Facebook":   {"facebook.com", "facebookmail.com", "meta.com"},
    "Netflix":    {"netflix.com"},
    "DHL":        {"dhl.com", "dhl.de", "dhl.co.uk"},
    "FedEx":      {"fedex.com"},
    "UPS":        {"ups.com"},
    "HMRC":       {"hmrc.gov.uk"},
    "IRS":        {"irs.gov"},
    "LinkedIn":   {"linkedin.com", "e.linkedin.com"},
    "Twitter":    {"twitter.com", "x.com"},
    "Instagram":  {"instagram.com"},
    "WhatsApp":   {"whatsapp.com"},
    "Dropbox":    {"dropbox.com"},
    "DocuSign":   {"docusign.com", "docusign.net"},
}

def get_email_sha256_hash(msg) -> str:
    """Compute a hash of the email for deduplication."""
    hasher = hashlib.sha256()
    for field in HEADER_FIELDS:
        value = msg.get(field)
        if value:
            hasher.update(str(value).encode())
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True)
        if payload:
            hasher.update(payload)
    return hasher.hexdigest()

def get_email_md5_hash(msg) -> str:
    """Compute an MD5 hash of the email for quick lookup."""
    hasher = hashlib.md5()
    for field in HEADER_FIELDS:
        value = msg.get(field)
        if value:
            hasher.update(str(value).encode())
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True)
        if payload:
            hasher.update(payload)
    return hasher.hexdigest()

def get_email_sha1_hash(msg) -> str:
    """Compute a SHA-1 hash of the email for quick lookup."""
    hasher = hashlib.sha1()
    for field in HEADER_FIELDS:
        value = msg.get(field)
        if value:
            hasher.update(str(value).encode())
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True)
        if payload:
            hasher.update(payload)
    return hasher.hexdigest()

def decode_mime_words(value: str) -> str:
    if value is None:
        return ""
    parts = []
    for decoded_bytes, charset in decode_header(value):
        if isinstance(decoded_bytes, bytes):
            parts.append(decoded_bytes.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(decoded_bytes)
    return " ".join(parts)


def _get_url_file_ext(url: str):
    """Return the lowercase file extension from the URL path, or None."""
    try:
        path = urllib.parse.urlparse(url).path
        last_segment = path.split("/")[-1]
        if "." in last_segment:
            ext = "." + last_segment.rsplit(".", 1)[-1].lower()
            if 2 <= len(ext) <= 6:  # sane extension length (.js to .docx)
                return ext
    except Exception:
        pass
    return None


def parse_eml_bytes(file_bytes: bytes):
    return BytesParser(policy=policy.default).parsebytes(file_bytes)


def extract_headers(msg) -> dict:
    headers = {}
    for field in HEADER_FIELDS:
        value = msg.get(field)
        if value:
            headers[field] = decode_mime_words(str(value))
    received = msg.get_all("Received")
    if received:
        headers["Received"] = [str(r).strip() for r in received]
    return headers


def extract_urls(msg) -> list:
    urls = set()
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        for url in URL_PATTERN.findall(text):
            urls.add(url.rstrip(".,;:!?"))
    result = []
    for url in sorted(urls):
        flags = [label for pattern, label in SUSPICIOUS_URL_PATTERNS if pattern.search(url)]
        is_tracking = any(p.search(url) for p in SPAM_TRACKING_PATTERNS)
        ext = _get_url_file_ext(url)
        file_type, ext_suspicious = FILE_EXT_MAP.get(ext, (None, False)) if ext else (None, False)
        result.append({
            "url": url,
            "suspicious_flags": flags,
            "is_tracking": is_tracking,
            "file_ext": ext if file_type else None,
            "file_type": file_type,
            "ext_suspicious": ext_suspicious,
        })
    return result


def extract_attachments(msg) -> list:
    attachments = []
    dangerous_exts = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1",
                      ".scr", ".pif", ".com", ".msi", ".jar", ".zip",
                      ".rar", ".7z", ".iso", ".doc", ".docm", ".xls",
                      ".xlsm", ".ppt", ".pptm"}
    for part in msg.walk():
        if part.get_content_disposition() not in ("attachment", "inline"):
            continue
        filename = part.get_filename()
        if not filename:
            continue
        filename = decode_mime_words(filename)
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "dangerous": ext in dangerous_exts,
        })
    return attachments


def score_threat(headers: dict, urls: list, attachments: list, vt_results: dict = None, urlhaus_results: dict = None) -> dict:
    """
    Produce a threat score (0–100) with separate phishing/spam tracking
    and an email_type classification: 'phishing', 'spam', 'mixed', or 'clean'.
    Each finding includes a 'type_tag' of 'PHISHING', 'SPAM', or None.
    Pass vt_results (url -> vt_result dict from scan_urls_virustotal) to
    incorporate VirusTotal intelligence into the score.
    Pass urlhaus_results (url -> uh_result dict from scan_urls_urlhaus) to
    incorporate Abuse.CH URLhaus intelligence into the score.
    """
    phishing_score = 0
    spam_score = 0
    findings = []

    subject = headers.get("Subject", "")
    subject_lower = subject.lower()

    # --- Phishing keywords in subject ---
    found_phishing = [kw for kw in PHISHING_KEYWORDS if kw in subject_lower]
    if found_phishing:
        phishing_score += min(len(found_phishing) * 8, 30)
        findings.append({
            "severity": "high",
            "category": "Subject",
            "type_tag": "PHISHING",
            "confidence": "medium",
            "detail": f"Phishing keywords in subject: {', '.join(found_phishing)}",
        })

    # --- Spam/advertising keywords in subject ---
    found_spam = [kw for kw in SPAM_KEYWORDS if kw in subject_lower]
    if found_spam:
        spam_score += min(len(found_spam) * 5, 20)
        findings.append({
            "severity": "medium",
            "category": "Subject",
            "type_tag": "SPAM",
            "confidence": "low",
            "detail": f"Advertising/spam keywords in subject: {', '.join(found_spam)}",
        })

    # --- Bulk/commercial mail headers ---
    bulk_found = [h for h in BULK_MAIL_HEADERS if headers.get(h)]
    if bulk_found:
        spam_score += min(len(bulk_found) * 8, 20)
        findings.append({
            "severity": "low",
            "category": "Headers",
            "type_tag": "SPAM",
            "confidence": "high",
            "detail": f"Bulk/commercial mail headers detected: {', '.join(bulk_found)}",
        })

    # --- SPF / DKIM / DMARC ---
    auth_results = headers.get("Authentication-Results", "").lower()
    if "dkim=fail" in auth_results or "dkim=none" in auth_results:
        phishing_score += 20
        findings.append({"severity": "high", "category": "Authentication",
                          "type_tag": "PHISHING", "confidence": "high",
                          "detail": "DKIM signature failed or missing."})
    if "spf=fail" in auth_results or "spf=none" in auth_results:
        phishing_score += 15
        findings.append({"severity": "high", "category": "Authentication",
                          "type_tag": "PHISHING", "confidence": "high",
                          "detail": "SPF check failed or missing."})
    if "dmarc=fail" in auth_results or "dmarc=none" in auth_results:
        phishing_score += 15
        findings.append({"severity": "high", "category": "Authentication",
                          "type_tag": "PHISHING", "confidence": "high",
                          "detail": "DMARC check failed or missing."})

    # --- Reply-To domain mismatch ---
    reply_to = headers.get("Reply-To", "")
    from_addr = headers.get("From", "")
    if reply_to and from_addr:
        from_domain = from_addr.split("@")[-1].rstrip(">").lower() if "@" in from_addr else ""
        reply_domain = reply_to.split("@")[-1].rstrip(">").lower() if "@" in reply_to else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            phishing_score += 10
            findings.append({"severity": "medium", "category": "Headers",
                              "type_tag": "PHISHING", "confidence": "high",
                              "detail": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})."})

    # --- Brand impersonation in From display name / address ---
    from_raw = headers.get("From", "").lower()
    from_domain = from_raw.split("@")[-1].rstrip(">").strip() if "@" in from_raw else ""
    for brand, legit_domains in BRAND_IMPERSONATION_MAP.items():
        if brand.lower() in from_raw and from_domain not in legit_domains:
            phishing_score += 30
            findings.append({
                "severity": "high",
                "category": "Sender",
                "type_tag": "PHISHING",
                "confidence": "high",
                "detail": (
                    f"Sender claims to be {brand} but is sending from "
                    f"{from_domain or 'an unknown domain'} — not a legitimate {brand} domain."
                ),
            })
            break  # Only report the first matching brand to avoid noise

    # --- URL checks ---
    tracking_urls = [u for u in urls if u.get("is_tracking")]
    phishing_urls = [u for u in urls if u["suspicious_flags"] and not u.get("is_tracking")]

    if tracking_urls:
        ratio = len(tracking_urls) / max(len(urls), 1)
        spam_score += min(len(tracking_urls) * 2, 20)
        findings.append({
            "severity": "medium",
            "category": "URLs",
            "type_tag": "SPAM",
            "confidence": "high",
            "detail": (
                f"{len(tracking_urls)} tracking/marketing URL(s) detected "
                f"({int(ratio * 100)}% of all URLs)."
            ),
        })

    if phishing_urls:
        phishing_score += min(len(phishing_urls) * 5, 25)
        findings.append({
            "severity": "high",
            "category": "URLs",
            "type_tag": "PHISHING",
            "confidence": "medium",
            "detail": f"{len(phishing_urls)} URL(s) with phishing indicators detected.",
        })

    # --- Dangerous attachments ---
    dangerous_att = [a for a in attachments if a["dangerous"]]
    if dangerous_att:
        phishing_score += min(len(dangerous_att) * 15, 30)
        names = ", ".join(a["filename"] for a in dangerous_att)
        findings.append({"severity": "critical", "category": "Attachments",
                          "type_tag": "PHISHING", "confidence": "high",
                          "detail": f"Dangerous attachment(s): {names}"})

    # --- VirusTotal results ---
    if vt_results:
        # Only consider URLs that VT actually returned a verdict for (status == 'ok')
        vt_ok = [
            url_item["url"] for url_item in urls
            if vt_results.get(url_item["url"], {}).get("status") == "ok"
        ]
        vt_malicious = [
            url for url in vt_ok
            if vt_results[url].get("malicious", 0) > 0
        ]
        vt_suspicious = [
            url for url in vt_ok
            if vt_results[url].get("suspicious", 0) > 0
            and vt_results[url].get("malicious", 0) == 0
        ]
        vt_clean = [
            url for url in vt_ok
            if vt_results[url].get("malicious", 0) == 0
            and vt_results[url].get("suspicious", 0) == 0
        ]

        if vt_malicious:
            phishing_score += min(len(vt_malicious) * 35, 70)
            findings.append({
                "severity": "critical",
                "category": "VirusTotal",
                "type_tag": "PHISHING",
                "confidence": "high",
                "detail": f"{len(vt_malicious)} URL(s) confirmed malicious by VirusTotal.",
            })
        if vt_suspicious:
            phishing_score += min(len(vt_suspicious) * 12, 24)
            findings.append({
                "severity": "high",
                "category": "VirusTotal",
                "type_tag": "PHISHING",
                "confidence": "medium",
                "detail": f"{len(vt_suspicious)} URL(s) flagged suspicious by VirusTotal.",
            })
        if vt_clean and not vt_malicious and not vt_suspicious:
            # All scanned URLs came back clean — reduce both scores slightly.
            # Reduction scales with how many URLs were checked, capped at 20 pts.
            reduction = min(len(vt_clean) * 3, 20)
            phishing_score = max(0, phishing_score - reduction)
            spam_score = max(0, spam_score - reduction)
            findings.append({
                "severity": "info",
                "category": "VirusTotal",
                "type_tag": None,
                "confidence": "high",
                "detail": (
                    f"{len(vt_clean)} URL(s) verified clean by VirusTotal "
                    f"(score reduced by {reduction} pt{'s' if reduction != 1 else ''})."
                ),
            })
            
    # --- URLhaus results ---
    if urlhaus_results:
        uh_ok = [
            url_item["url"] for url_item in urls
            if urlhaus_results.get(url_item["url"], {}).get("status") == "ok"
        ]
        uh_online = [u for u in uh_ok if urlhaus_results[u].get("url_status") == "online"]
        uh_offline = [u for u in uh_ok if urlhaus_results[u].get("url_status") in ("offline", "unknown")]
        uh_clean = [
            url_item["url"] for url_item in urls
            if urlhaus_results.get(url_item["url"], {}).get("status") == "no_results"
        ]

        if uh_online:
            phishing_score += min(len(uh_online) * 40, 70)
            findings.append({
                "severity": "critical",
                "category": "URLhaus",
                "type_tag": "PHISHING",
                "confidence": "high",
                "detail": (
                    f"{len(uh_online)} URL(s) confirmed actively serving malware by Abuse.CH URLhaus."
                ),
            })
        if uh_offline:
            phishing_score += min(len(uh_offline) * 20, 40)
            findings.append({
                "severity": "high",
                "category": "URLhaus",
                "type_tag": "PHISHING",
                "confidence": "high",
                "detail": (
                    f"{len(uh_offline)} URL(s) previously identified as malware distribution "
                    f"by Abuse.CH URLhaus (currently offline)."
                ),
            })
        if uh_clean and not uh_online and not uh_offline:
            reduction = min(len(uh_clean) * 3, 20)
            phishing_score = max(0, phishing_score - reduction)
            spam_score = max(0, spam_score - reduction)
            findings.append({
                "severity": "info",
                "category": "URLhaus",
                "type_tag": None,
                "confidence": "high",
                "detail": (
                    f"{len(uh_clean)} URL(s) not found in Abuse.CH URLhaus "
                    f"(score reduced by {reduction} pt{'s' if reduction != 1 else ''})."
                ),
            })

    # --- Classify email type ---
    if phishing_score >= 15 and spam_score >= 15:
        email_type = "mixed"
    elif phishing_score >= spam_score and phishing_score >= 10:
        email_type = "phishing"
    elif spam_score > phishing_score and spam_score >= 10:
        email_type = "spam"
    else:
        email_type = "clean"

    total_score = min(phishing_score + spam_score, 100)

    # --- Score floors: phishing findings must never produce "Likely Safe" ---
    phishing_findings = [f for f in findings if f.get("type_tag") == "PHISHING"]
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    if critical_findings and total_score < 70:
        total_score = 70          # critical → High Risk at minimum
    elif phishing_findings and total_score < 35:
        total_score = 35          # any phishing signal → Suspicious at minimum

    # --- Verdict ---
    if total_score >= 70:
        if email_type in ("phishing", "mixed"):
            verdict = "High Risk \u2013 Likely Phishing \u2013 DO NOT OPEN, CLICK, OR DOWNLOAD AND REPORT AS PHISHING!"
            verdict_class = "danger"
        else:
            verdict = "High Risk Spam \u2013 Likely Malicious Campaign \u2013 Do Not Click Any Links"
            verdict_class = "danger"
    elif total_score >= 35:
        if email_type == "spam":
            verdict = "Likely Spam \u2013 Unsolicited Commercial Email \u2013 Exercise Caution"
            verdict_class = "warning"
        elif email_type == "mixed":
            verdict = "Suspicious \u2013 Mixed Phishing & Spam Signals \u2013 Exercise Caution"
            verdict_class = "warning"
        else:
            verdict = "Suspicious \u2013 Possible Phishing Attempt \u2013 Exercise Caution"
            verdict_class = "warning"
    else:
        verdict = "Likely Safe \u2013 No Major Red Flags Detected \u2013 Still Exercise Caution"
        verdict_class = "success"

    return {
        "score": total_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "email_type": email_type,
        "findings": findings,
    }


# ── VirusTotal integration ──────────────────────────────────────

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_TIMEOUT = 12  # seconds per request


def _vt_url_id(url: str) -> str:
    """Return the VirusTotal URL identifier (base64url, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _make_ssl_context() -> ssl.SSLContext:
    """Return an SSL context with a trusted CA bundle.

    Priority:
    1. certifi (if installed) — best cross-platform coverage.
    2. Windows certificate store (ssl.enum_certificates) — works on Windows
       without any extra packages.
    3. Python's default context — covers most other platforms.

    Never disables certificate verification.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    ctx = ssl.create_default_context()
    # Windows: load Root and Intermediate CA certs from the system store.
    # ssl.enum_certificates() is only available on Windows.
    if hasattr(ssl, "enum_certificates"):
        for store in ("ROOT", "CA"):
            for cert, _encoding, _trust in ssl.enum_certificates(store):
                try:
                    ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert))
                except Exception:
                    pass
    return ctx


def _vt_get(path: str, api_key: str) -> dict:
    req = urllib.request.Request(
        f"{_VT_BASE}{path}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, context=_make_ssl_context(), timeout=_VT_TIMEOUT) as resp:
        return json.loads(resp.read())


def _vt_submit_url(url: str, api_key: str) -> dict:
    data = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request(
        f"{_VT_BASE}/urls",
        data=data,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=_make_ssl_context(), timeout=_VT_TIMEOUT) as resp:
        return json.loads(resp.read())


def scan_urls_urlhaus(urls: list, api_key: str) -> dict:
    """
    Look up each URL against Abuse.CH URLhaus and return a mapping of
    url -> uh_result dict.

    uh_result keys:
      status:          'ok' | 'no_results' | 'error'
      url_status:      'online' | 'offline' | 'unknown' | None
      threat:          str | None   (e.g. 'malware_download')
      tags:            list | None
      urlhaus_reference: str | None
      error:           str  (only when status == 'error')
    """
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
    results = {}
    for item in urls:
        url = item["url"]
        try:
            post_data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(
                URLHAUS_API,
                data=post_data,
                headers={"Auth-Key": api_key, "Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, context=_make_ssl_context(), timeout=15) as resp:
                data = json.loads(resp.read().decode())
            qs = data.get("query_status", "")
            if qs == "ok":
                results[url] = {
                    "status": "ok",
                    "url_status":        data.get("url_status"),
                    "threat":            data.get("threat"),
                    "tags":              data.get("tags") or [],
                    "urlhaus_reference": data.get("urlhaus_reference"),
                }
            elif qs in ("no_results", "invalid_url"):
                results[url] = {"status": "no_results"}
            else:
                results[url] = {"status": "error", "error": f"Unexpected query_status: {qs}"}
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                err = {"status": "error", "error": "Invalid Auth-Key (403)."}
                for remaining in urls:
                    if remaining["url"] not in results:
                        results[remaining["url"]] = err
                break
            elif exc.code == 429:
                err = {"status": "error", "error": "URLhaus rate limit reached. Try again shortly."}
                for remaining in urls:
                    if remaining["url"] not in results:
                        results[remaining["url"]] = err
                break
            else:
                results[url] = {"status": "error", "error": f"HTTP {exc.code}"}
        except Exception as exc:
            results[url] = {"status": "error", "error": str(exc)}
    return results


def scan_urls_virustotal(urls: list, api_key: str) -> dict:
    """
    Look up each URL against VirusTotal and return a mapping of
    url -> vt_result dict.

    vt_result keys:
      malicious, suspicious, harmless, undetected  (int counts)
      status: 'ok' | 'submitted' | 'error'
      error: str  (only when status == 'error')
    """
    results = {}
    for item in urls:
        url = item["url"]
        url_id = _vt_url_id(url)
        try:
            data = _vt_get(f"/urls/{url_id}", api_key)
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            results[url] = {
                "status": "ok",
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
            }
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # URL not in VT yet — submit it
                try:
                    _vt_submit_url(url, api_key)
                    results[url] = {"status": "submitted"}
                except Exception as sub_exc:
                    results[url] = {"status": "error", "error": str(sub_exc)}
            elif exc.code == 401:
                # Bad key — abort remaining lookups
                err = {"status": "error", "error": "Invalid API key (401)."}
                for remaining in urls:
                    if remaining["url"] not in results:
                        results[remaining["url"]] = err
                break
            elif exc.code == 429:
                err = {"status": "error", "error": "VT rate limit reached. Try again shortly."}
                for remaining in urls:
                    if remaining["url"] not in results:
                        results[remaining["url"]] = err
                break
            else:
                results[url] = {"status": "error", "error": f"HTTP {exc.code}"}
        except Exception as exc:
            results[url] = {"status": "error", "error": str(exc)}
    return results
