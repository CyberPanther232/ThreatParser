# ThreatParser – Scoring System

All scoring logic lives in `app/parser.py` inside the `score_threat()` function.

---

## Overview

ThreatParser uses two **independent score tracks** that are summed into a single 0–100 threat score:

| Track | What it measures |
|---|---|
| `phishing_score` | Indicators of credential harvesting, identity spoofing, or malware delivery |
| `spam_score` | Indicators of unsolicited bulk/commercial mail |

The final score is: `total_score = min(phishing_score + spam_score, 100)`

**Score floors** prevent high-severity findings from being buried by an otherwise low score:

| Condition | Floor |
|---|---|
| Any finding with `severity == "critical"` | Total ≥ **70** |
| Any finding with `type_tag == "PHISHING"` | Total ≥ **35** |

---

## Verdict Bands

| Score | Email type | Verdict |
|---|---|---|
| 0–34 | any | Likely Safe |
| 35–69 | spam | Likely Spam |
| 35–69 | mixed | Suspicious – Mixed Signals |
| 35–69 | phishing | Suspicious – Possible Phishing |
| 70–100 | phishing / mixed | High Risk – Likely Phishing |
| 70–100 | spam | High Risk Spam |

**Email type classification** (before score floors are applied):

| Condition | Type |
|---|---|
| `phishing_score >= 15` AND `spam_score >= 15` | `mixed` |
| `phishing_score >= spam_score` AND `phishing_score >= 10` | `phishing` |
| `spam_score > phishing_score` AND `spam_score >= 10` | `spam` |
| Neither track reaches 10 | `clean` |

---

## Detection Checks

Each check lists: the constant/pattern to edit, the points awarded, the cap, and the track affected.

---

### 1. Phishing Keywords in Subject

**Constant:** `PHISHING_KEYWORDS` (list of strings, top of `parser.py`)

| Detail | Value |
|---|---|
| Points per keyword match | **+8** to `phishing_score` |
| Cap | **30 pts** |
| Severity | `high` |
| Confidence | `medium` |

**To tune:** Add or remove words from `PHISHING_KEYWORDS`. To change the points-per-keyword or cap, edit these two values in `score_threat()`:
```python
phishing_score += min(len(found_phishing) * 8, 30)
#                                            ^  ^^
#                              pts/keyword   |  cap
```

---

### 2. Spam / Advertising Keywords in Subject

**Constant:** `SPAM_KEYWORDS` (list of strings, top of `parser.py`)

| Detail | Value |
|---|---|
| Points per keyword match | **+5** to `spam_score` |
| Cap | **20 pts** |
| Severity | `medium` |
| Confidence | `low` |

**To tune:**
```python
spam_score += min(len(found_spam) * 5, 20)
#                                    ^  ^^
```

---

### 3. Bulk / Commercial Mail Headers

**Constant:** `BULK_MAIL_HEADERS` (list of header names, top of `parser.py`)

| Detail | Value |
|---|---|
| Points per header found | **+8** to `spam_score` |
| Cap | **20 pts** |
| Severity | `low` |
| Confidence | `high` |

**To tune:** Add header names to `BULK_MAIL_HEADERS`. Change weights:
```python
spam_score += min(len(bulk_found) * 8, 20)
```

---

### 4. DKIM / SPF / DMARC Authentication Failures

Checks the `Authentication-Results` header for `fail` or `none` results.

| Check | Points | Track |
|---|---|---|
| DKIM fail / none | **+20** | `phishing_score` |
| SPF fail / none | **+15** | `phishing_score` |
| DMARC fail / none | **+15** | `phishing_score` |

All three are `severity: high`, `confidence: high`.

**To tune** — find the three blocks in `score_threat()`:
```python
if "dkim=fail" in auth_results or "dkim=none" in auth_results:
    phishing_score += 20   # ← change this value
```

---

### 5. Reply-To Domain Mismatch

Fires when the domain in `Reply-To` differs from the domain in `From`.

| Detail | Value |
|---|---|
| Points | **+10** to `phishing_score` |
| Severity | `medium` |
| Confidence | `high` |

**To tune:**
```python
phishing_score += 10   # inside the Reply-To mismatch block
```

> **Note:** Mismatched Reply-To is common in legitimate mailing lists (e.g. Google Groups, Mailman). Keep this value low unless your use case is narrow.

---

### 6. Brand Impersonation

**Constant:** `BRAND_IMPERSONATION_MAP` (dict of brand → set of legitimate domains, top of `parser.py`)

Fires when the `From` display name or address contains a brand name but the sending domain is not in the brand's allow-list.

| Detail | Value |
|---|---|
| Points | **+30** to `phishing_score` |
| Severity | `high` |
| Confidence | `high` |

**To tune — add a brand:**
```python
BRAND_IMPERSONATION_MAP = {
    ...
    "MyBank": {"mybank.com", "mybank.co.uk"},
}
```

**To change the score weight:**
```python
phishing_score += 30   # inside the brand impersonation loop
```

---

### 7. Tracking / Marketing URLs

**Constant:** `SPAM_TRACKING_PATTERNS` (list of compiled regexes, top of `parser.py`)

Fires when one or more URLs match known tracking service patterns (SendGrid, Mailchimp, UTM params, etc.).

| Detail | Value |
|---|---|
| Points per tracking URL | **+2** to `spam_score` |
| Cap | **20 pts** |
| Severity | `medium` |
| Confidence | `high` |

**To tune — add a tracking pattern:**
```python
SPAM_TRACKING_PATTERNS = [
    ...
    re.compile(r'your-pattern-here', re.IGNORECASE),
]
```

**To change the score weight:**
```python
spam_score += min(len(tracking_urls) * 2, 20)
```

---

### 8. Heuristic Phishing URLs

**Constant:** `SUSPICIOUS_URL_PATTERNS` (list of `(compiled_regex, "Label")` tuples, top of `parser.py`)

Fires when a URL matches any heuristic pattern (raw IP, URL shortener, credentials in URL, suspicious file extension, phishing keyword in URL, tracking URL label).

| Detail | Value |
|---|---|
| Points per suspicious URL | **+5** to `phishing_score` |
| Cap | **25 pts** |
| Severity | `high` |
| Confidence | `medium` |

**To tune — add a pattern:**
```python
SUSPICIOUS_URL_PATTERNS = [
    ...
    (re.compile(r'your-pattern', re.IGNORECASE), "Human-readable label"),
]
```

**To change the score weight:**
```python
phishing_score += min(len(phishing_urls) * 5, 25)
```

---

### 9. Dangerous Attachments

**Constant:** `dangerous_exts` (set of extensions, inside `extract_attachments()`)

| Detail | Value |
|---|---|
| Points per dangerous attachment | **+15** to `phishing_score` |
| Cap | **30 pts** |
| Severity | `critical` |
| Confidence | `high` |

**To tune — add an extension:**
```python
dangerous_exts = {".exe", ".bat", ..., ".hta"}   # add here
```

**To change the score weight:**
```python
phishing_score += min(len(dangerous_att) * 15, 30)
```

---

### 10. VirusTotal Results

Requires a VT API key. Only URLs with `status == "ok"` are considered.

| Verdict | Points | Cap | Track | Severity | Confidence |
|---|---|---|---|---|---|
| Malicious (≥1 engine) | **+35 / URL** | 70 pts | `phishing_score` | `critical` | `high` |
| Suspicious (no malicious) | **+12 / URL** | 24 pts | `phishing_score` | `high` | `medium` |
| All clean (no mal/sus) | **−3 / URL** | −20 pts | both tracks | `info` | `high` |

**To tune:**
```python
# Malicious
phishing_score += min(len(vt_malicious) * 35, 70)

# Suspicious
phishing_score += min(len(vt_suspicious) * 12, 24)

# Clean reduction
reduction = min(len(vt_clean) * 3, 20)
```

---

### 11. Abuse.CH URLhaus Results

Requires a URLhaus Auth-Key. Only URLs with `status == "ok"` are considered.

| Verdict | Points | Cap | Track | Severity | Confidence |
|---|---|---|---|---|---|
| Active malware (`url_status = online`) | **+40 / URL** | 70 pts | `phishing_score` | `critical` | `high` |
| Previously malicious (`offline` / `unknown`) | **+20 / URL** | 40 pts | `phishing_score` | `high` | `high` |
| Not listed (`status = no_results`, all clean) | **−3 / URL** | −20 pts | both tracks | `info` | `high` |

**To tune:**
```python
# Active malware
phishing_score += min(len(uh_online) * 40, 70)

# Previously malicious
phishing_score += min(len(uh_offline) * 20, 40)

# Not listed reduction
reduction = min(len(uh_clean) * 3, 20)
```

---

## Confidence Tags

Every finding carries a `confidence` field used to render badges in the UI.

| Value | Meaning | Typical sources |
|---|---|---|
| `high` | Signal is definitive or from an authoritative source | Auth failures, brand impersonation, VT/URLhaus confirmed, dangerous attachments, bulk headers, tracking URLs |
| `medium` | Heuristic match — likely correct but prone to false positives | Phishing keywords in subject, heuristic URL patterns, VT suspicious |
| `low` | Weak signal — common in legitimate mail | Spam/ad keywords in subject |

To change the confidence on any finding, edit the `"confidence"` key in the corresponding `findings.append()` call in `score_threat()`.

---

## Quick-Reference: All Score Weights

| Check | Points | Cap | Track |
|---|---|---|---|
| Phishing keywords (subject) | +8 / keyword | 30 | phishing |
| Spam keywords (subject) | +5 / keyword | 20 | spam |
| Bulk mail headers | +8 / header | 20 | spam |
| DKIM fail/none | +20 | — | phishing |
| SPF fail/none | +15 | — | phishing |
| DMARC fail/none | +15 | — | phishing |
| Reply-To mismatch | +10 | — | phishing |
| Brand impersonation | +30 | — | phishing |
| Tracking URLs | +2 / URL | 20 | spam |
| Heuristic phishing URLs | +5 / URL | 25 | phishing |
| Dangerous attachments | +15 / file | 30 | phishing |
| VT malicious | +35 / URL | 70 | phishing |
| VT suspicious | +12 / URL | 24 | phishing |
| VT clean (all clean) | −3 / URL | −20 | both |
| URLhaus active malware | +40 / URL | 70 | phishing |
| URLhaus previously malicious | +20 / URL | 40 | phishing |
| URLhaus not listed (all clean) | −3 / URL | −20 | both |
