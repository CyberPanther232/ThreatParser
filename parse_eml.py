import os
import re
import sys
import argparse
from email import policy
from email.parser import BytesParser
from email.header import decode_header


HEADER_FIELDS = [
    "From", "To", "Cc", "Bcc", "Reply-To",
    "Subject", "Date", "Message-ID",
    "Return-Path", "X-Mailer", "X-Originating-IP",
    "Received-SPF", "DKIM-Signature", "Authentication-Results",
]

PHISHING_KEYWORDS = [
    "invoice", "payment", "urgent", "password", "account", "security", "update", "verify", "click", "login",
    "bank", "paypal", "amazon", "apple", "microsoft", "google", "facebook", "twitter",
    "free", "offer", "win", "prize", "lottery", "congratulations", "limited time", "act now",
    "attachment", "document", "pdf", "xls", "doc", "zip", "exe",
    "phishing", "scam", "malware", "virus", "ransomware", "spyware",
    "urgent", "important", "notice", "alert", "warning", "security", "update",
    "account", "password", "login", "verify", "confirm", "suspend", "reactivate"
]

SPAM_KEYWORDS = [
    "free", "win", "winner", "prize", "lottery", 
    "congratulations", "limited time",
    "act now", "offer", "cheap", "discount",
    "rebate", "bonus", "cash", "credit", "debt", "loan", "mortgage", "insurance"
]

URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+')

def decode_mime_words(value: str) -> str:
    """Decode encoded MIME header words (e.g. =?utf-8?Q?...?=)."""
    if value is None:
        return ""
    parts = []
    for decoded_bytes, charset in decode_header(value):
        if isinstance(decoded_bytes, bytes):
            parts.append(decoded_bytes.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(decoded_bytes)
    return " ".join(parts)

def parse_eml(file_path: str):
    """Parse an .eml file and return the email message object."""
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def extract_headers(msg) -> dict:
    """Extract key headers from the message."""
    headers = {}
    for field in HEADER_FIELDS:
        value = msg.get(field)
        if value:
            headers[field] = decode_mime_words(str(value))

    # Also collect all Received headers in order
    received = msg.get_all("Received")
    if received:
        headers["Received"] = [str(r).strip() for r in received]

    return headers

def extract_urls(msg) -> list:
    """Extract all unique URLs from text/plain and text/html body parts."""
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
            # Strip trailing punctuation that may have been captured
            urls.add(url.rstrip(".,;:!?"))
    return sorted(urls)


def extract_attachments(msg, save_dir: str = None) -> list:
    """
    List (and optionally save) attachments found in the email.

    Returns a list of dicts with filename, content_type, and size.
    If save_dir is provided the attachment bytes are written there.
    """
    attachments = []
    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        if content_disposition not in ("attachment", "inline"):
            continue
        filename = part.get_filename()
        if not filename:
            continue
        filename = decode_mime_words(filename)
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        info = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
        }

        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
            # Sanitize filename to prevent path traversal
            safe_name = os.path.basename(filename)
            out_path = os.path.join(save_dir, safe_name)
            with open(out_path, "wb") as f:
                f.write(payload)
            info["saved_to"] = out_path

        attachments.append(info)
    return attachments


def print_results(headers: dict, urls: list, attachments: list) -> None:
    print("=" * 60)
    print("HEADERS")
    print("=" * 60)
    for key, value in headers.items():
        if key == "Received":
            print(f"\n{'Received'} ({len(value)} hops):")
            for i, hop in enumerate(value, 1):
                print(f"  [{i}] {hop}")
        else:
            print(f"{key}: {value}")
            
        if key == "Subject":
            # Check for keywords in the subject line
            subject_lower = value.lower()
            found_phishing_keywords = [kw for kw in PHISHING_KEYWORDS if kw in subject_lower]
            if found_phishing_keywords:
                print(f"  (Phishing Keywords found in subject: {', '.join(found_phishing_keywords)})")
            found_spam_keywords = [kw for kw in SPAM_KEYWORDS if kw in subject_lower]
            if found_spam_keywords:
                print(f"  (Spam keywords found in subject: {', '.join(found_spam_keywords)})")

    print("\n" + "=" * 60)
    print(f"URLs ({len(urls)} found)")
    print("=" * 60)
    if urls:
        for url in urls:
            print(f"  {url}")
    else:
        print("  (none)")

    print("\n" + "=" * 60)
    print(f"ATTACHMENTS ({len(attachments)} found)")
    print("=" * 60)
    if attachments:
        for att in attachments:
            print(f"  Filename    : {att['filename']}")
            print(f"  Content-Type: {att['content_type']}")
            print(f"  Size        : {att['size_bytes']:,} bytes")
            if "saved_to" in att:
                print(f"  Saved to    : {att['saved_to']}")
            print()
    else:
        print("  (none)")


def main():
    parser = argparse.ArgumentParser(
        description="Parse an .eml file and extract headers, URLs, and attachments."
    )
    parser.add_argument("eml_file", nargs="?", default="sample_email.eml",
                        help="Path to the .eml file (default: sample_email.eml)")
    parser.add_argument("--save-attachments", metavar="DIR",
                        help="Directory to save attachments to")
    args = parser.parse_args()

    if not os.path.isfile(args.eml_file):
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)

    msg = parse_eml(args.eml_file)
    headers = extract_headers(msg)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg, save_dir=args.save_attachments)

    print_results(headers, urls, attachments)


if __name__ == "__main__":
    main()
