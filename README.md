# 📧 Email Phishing Analyzer

A Python CLI tool for analyzing suspicious `.eml` files and producing structured phishing reports — covering authentication checks, header anomalies, IP reputation, URL scanning, attachment hashing, keyword detection, and a weighted risk score.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-3.0.0-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## What It Does

Feed it a `.eml` file and it produces a color-coded terminal report covering every layer of the email:

```
python3 analyzer.py suspicious.eml
```

---

## What It Checks

**Authentication**
Parses SPF, DKIM, and DMARC directly from the `Authentication-Results` header. Flags fail, softfail, and none results with color coding.

**Header Anomalies**
Detects Reply-To / From domain mismatches, missing Message-ID headers, and display name impersonation of known brands (PayPal, Apple, Google, Microsoft, etc.).

**Sender IP Reputation**
Queries AbuseIPDB for abuse confidence score, country, ISP, total report count, last reported date, and Tor exit node status.

**URL Extraction & Scanning**
Extracts all URLs from the email body with clean punctuation stripping, then submits each to the VirusTotal API v3 for a full malicious / suspicious / harmless breakdown. Pre-built VT links are shown even in offline mode.

**Attachment Analysis**
Lists every attachment with filename, content type, size in bytes, and MD5 hash. Flags high-risk extensions (`.exe`, `.bat`, `.ps1`, `.vbs`, `.js`, `.scr`, `.hta`, etc.) and provides a direct VirusTotal MD5 search link for each.

**Keyword Detection**
Scans the email body across 8 categories:

| Category | Examples |
|:---|:---|
| 💰 Financial | account, wire transfer, credit card, invoice |
| 🔑 Personal Info | password, SSN, PIN, bank account number |
| 🚨 Urgent Action | urgent, act immediately, failure to act |
| ⚖️ Threats | legal action, suspended account, lawsuit |
| 🎭 Fake Brands | paypal, apple, microsoft, amazon, google |
| ⚙️ Tech Terms | security patch, account locked, data breach |
| 👆 Social Engineering | click here, download now, open attachment |
| 🎁 Rewards | free gift, winner, claim now, gift card |

**Weighted Risk Score**
Produces a 0–100 score with a visual progress bar, a per-factor breakdown, and a final verdict.

---

## Risk Score

| Score | Verdict |
|:---|:---|
| 70 – 100 | HIGH RISK — likely phishing |
| 40 – 69 | MEDIUM RISK — suspicious |
| 15 – 39 | LOW RISK — minor indicators |
| 0 – 14 | CLEAN — no significant indicators |

**Score factors and weights:**

| Factor | Points |
|:---|:---|
| SPF / DKIM / DMARC fail or none | +10 each |
| Header anomaly (mismatch, spoofing, missing ID) | +15 each |
| IP abuse confidence > 75% | +20 |
| IP abuse confidence 25–75% | +10 |
| Tor exit node | +10 |
| Malicious URL confirmed by VirusTotal | +20 per URL |
| Keyword hits | +2 to +15 per category |

---

## Requirements

Python 3.8 or higher and one dependency:

```bash
pip install requests
```

The tool works fully offline without any API keys — VirusTotal and AbuseIPDB checks are skipped gracefully with clear messaging.

---

## Installation

```bash
git clone https://github.com/DwsHunter/email-phishing-analyzer.git
cd email-phishing-analyzer
pip install -r requirements.txt
```

---

## API Keys (Optional)

Two free API integrations extend what the tool can detect:

- **VirusTotal** — scan URLs against 90+ antivirus engines → https://www.virustotal.com/gui/join-us  *(500 lookups/day free)*
- **AbuseIPDB** — check sender IP reputation → https://www.abuseipdb.com/register  *(1,000 lookups/day free)*

Run the setup wizard once to save your keys:

```bash
python3 analyzer.py --setup
```

Keys are stored in `~/.epa_config` with restricted permissions (chmod 600). Alternatively set environment variables:

```bash
export VT_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
```

---

## First Run

On first launch the tool runs a startup check automatically:

```
  STARTUP CHECK
  Checking your environment before running…

  ✓ Python version        Python 3.11
  ✓ Required packages     requests, email, configparser
  ✓ Internet              reachable
  ✓ Write permission      C:\Users\You — OK
  ⚠ Config file           not found (API keys not configured)

  API Keys
  VirusTotal :  ✗  not configured
  AbuseIPDB  :  ✗  not configured

  Set up API keys now? (Y/n):
```

It checks Python version, required packages (and offers to install them), internet connectivity, write permissions, config file, and API keys — and walks you through fixing anything that's missing. After the first run it skips this check automatically.

---

## Usage

```bash
# Basic — prints report to terminal
python3 analyzer.py suspicious.eml

# Save report as JSON
python3 analyzer.py suspicious.eml -o json

# Save report as both JSON and TXT
python3 analyzer.py suspicious.eml -o both

# Offline mode — skip all API calls
python3 analyzer.py suspicious.eml --offline

# Headers only — fast triage, skip body and attachments
python3 analyzer.py suspicious.eml --headers-only

# Print email body in the report
python3 analyzer.py suspicious.eml --show-body

# Guided interactive mode
python3 analyzer.py --interactive

# First-time API key setup
python3 analyzer.py --setup

# Test that your API keys are working
python3 analyzer.py --test-api

# Re-run the startup environment check
python3 analyzer.py --health
```

**All options:**

| Flag | Description |
|:---|:---|
| `file` | Path to `.eml` file |
| `-o json\|txt\|both` | Save report with timestamp |
| `--offline` | Skip all API calls |
| `--no-vt` | Skip VirusTotal only |
| `--no-ip` | Skip AbuseIPDB only |
| `--headers-only` | Headers analysis only |
| `--show-body` | Print email body in report |
| `--setup` | API key setup wizard |
| `--interactive` | Guided prompts |
| `--test-api` | Test API connectivity and key validity |
| `--health` | Re-run environment check |
| `--quiet` | Suppress banner and tips |

---

## Output Example

```
──────────────────────────── HEADERS ───────────────────────────────

  From                        PayPal Security Team <security@paypa1-alert.com>
  To                          victim@gmail.com
  Reply-To                    collect@harvester-ru.com
  Subject                     URGENT: Your PayPal account has been suspended
  X-Originating-IP            45.133.1.25
  X-Mailer                    ThunderMailer-Pro v1.0

────────────────────────── AUTHENTICATION ──────────────────────────

  SPF          N/A
  DKIM         N/A
  DMARC        N/A
  Sender IP    45.133.1.25

─────────────────────────── HEADER ANOMALIES ───────────────────────

  ⚑  Reply-To domain (harvester-ru.com) ≠ From domain (paypa1-alert.com)
  ⚑  Missing Message-ID — common in spoofed/bulk emails
  ⚑  Display name impersonates 'PayPal Security Team' but address is <security@paypa1-alert.com>

──────────────────────────── ATTACHMENTS ───────────────────────────

  ⊞  PayPal_Invoice_OVERDUE.pdf
     Type: application/pdf  Size: 626 bytes  MD5: e41d6a4b277c0a8fc2d9e14c9ca77988
  ⊞  account_recovery_tool.exe
     Type: application/octet-stream  Size: 140 bytes  MD5: 14439695d2fee8917c8054352ac8af79
     ⚠ High-risk file extension

────────────────────────── SUSPICIOUS KEYWORDS ─────────────────────

  💰  Financial          account, bank, credit card, balance, funds
  🔑  Personal Info      password, SSN, PIN, bank account number
  🚨  Urgent Action      urgent, verify, failure to act, act immediately
  ⚖️  Threats            unauthorized login, legal action
  🎭  Fake Brands        paypal

════════════════════════════════════════════════════════════════════
  RISK SCORE  100/100   HIGH RISK — likely phishing
  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
════════════════════════════════════════════════════════════════════

  Score Breakdown:
  +15   Header anomaly: Reply-To domain mismatch
  +15   Header anomaly: Missing Message-ID
  +15   Header anomaly: Display name impersonation
  +15   Keywords [financial]: account, bank, credit card…
  +15   Keywords [urgent_action]: urgent, verify, failure to act…
  ...

  💡  HIGH RISK — do not click any links or open attachments.
```

---

## Tips

Drop a `.eml` directly onto your terminal window to auto-fill the path.

Use `--offline` for fast first-pass triage before submitting anything to external APIs.

Use `-o json` to feed results into a SIEM, script, or case management system.

MD5 hashes in the attachment section are ready to search directly on VirusTotal — the tool prints the link.

SPF fail + DKIM none + DMARC fail + Reply-To mismatch in the same email is a near-certain phishing signal.

Use `--test-api` after setup to confirm your keys work before running a real investigation.

---

## Project Structure

```
email-phishing-analyzer/
├── analyzer.py        # Full tool — single file, no extra modules
├── requirements.txt   # requests only
├── LICENSE
└── README.md
```

---

## License

MIT — free to use, modify, and share.
