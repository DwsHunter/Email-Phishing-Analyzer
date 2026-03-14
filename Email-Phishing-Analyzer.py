"""
Email Phishing Analyzer v2.0
Author  : DwsHunter
"""

import os, re, sys, json, base64, hashlib, argparse, configparser, textwrap, shutil, time
import requests
from pathlib import Path
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

# ──────────────────────────────────────────────────────────────
#  TERMINAL COLORS  (pure ANSI — no third-party libs needed)
# ──────────────────────────────────────────────────────────────
def _supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

class C:
    RESET   = "\033[0m"   if USE_COLOR else ""
    BOLD    = "\033[1m"   if USE_COLOR else ""
    DIM     = "\033[2m"   if USE_COLOR else ""
    RED     = "\033[91m"  if USE_COLOR else ""
    YELLOW  = "\033[93m"  if USE_COLOR else ""
    GREEN   = "\033[92m"  if USE_COLOR else ""
    CYAN    = "\033[96m"  if USE_COLOR else ""
    BLUE    = "\033[94m"  if USE_COLOR else ""
    MAGENTA = "\033[95m"  if USE_COLOR else ""
    WHITE   = "\033[97m"  if USE_COLOR else ""
    GRAY    = "\033[90m"  if USE_COLOR else ""

def col(text, *codes):
    return "".join(codes) + str(text) + C.RESET if USE_COLOR else str(text)

def status_color(val):
    v = str(val).lower()
    if v in ("pass", "ok", "clean"):        return col(val, C.GREEN, C.BOLD)
    if v in ("fail", "softfail", "none"):   return col(val, C.RED, C.BOLD)
    if v in ("neutral", "n/a"):             return col(val, C.YELLOW)
    return col(val, C.WHITE)

def risk_color(score):
    if score >= 70:  return col(f"{score}/100", C.RED,    C.BOLD)
    if score >= 40:  return col(f"{score}/100", C.YELLOW, C.BOLD)
    if score >= 15:  return col(f"{score}/100", C.CYAN)
    return col(f"{score}/100", C.GREEN, C.BOLD)

def verdict_color(verdict):
    v = verdict.upper()
    if "HIGH"   in v: return col(verdict, C.RED,    C.BOLD)
    if "MEDIUM" in v: return col(verdict, C.YELLOW, C.BOLD)
    if "LOW"    in v: return col(verdict, C.CYAN)
    return col(verdict, C.GREEN, C.BOLD)

W = shutil.get_terminal_size((100, 24)).columns
W = min(W, 100)

def divider(char="─", color=C.GRAY):
    return col(char * W, color)

def section(title):
    t = f"  {title}  "
    pad = (W - len(t)) // 2
    return col("─" * pad, C.GRAY) + col(t, C.CYAN, C.BOLD) + col("─" * pad, C.GRAY)

def step(msg):
    print(col("  ›", C.CYAN, C.BOLD) + " " + col(msg, C.WHITE))

def ok(msg):
    print(col("  ✓", C.GREEN, C.BOLD) + " " + col(msg, C.WHITE))

def warn(msg):
    print(col("  ⚠", C.YELLOW, C.BOLD) + " " + col(msg, C.YELLOW))

def err(msg):
    print(col("  ✗", C.RED, C.BOLD) + " " + col(msg, C.RED))

def tip(msg):
    print(col("  💡 TIP:", C.MAGENTA, C.BOLD) + col(f" {msg}", C.GRAY))

# ──────────────────────────────────────────────────────────────
#  CONFIG  (~/.epa_config)
# ──────────────────────────────────────────────────────────────
CONFIG_PATH = Path.home() / ".epa_config"

def load_config():
    cfg = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        cfg.read(CONFIG_PATH)
    return cfg

def save_config(vt_key, abuse_key):
    cfg = configparser.ConfigParser()
    cfg["api_keys"] = {
        "virustotal":  vt_key.strip(),
        "abuseipdb":   abuse_key.strip(),
    }
    CONFIG_PATH.write_text(cfg.write if False else "")
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)
    CONFIG_PATH.chmod(0o600)

def get_api_keys():
    """Priority: env var > config file > empty"""
    cfg = load_config()
    if cfg.has_section("api_keys"):
        vt_cfg    = cfg["api_keys"].get("virustotal", "")
        abuse_cfg = cfg["api_keys"].get("abuseipdb", "")
    else:
        vt_cfg = abuse_cfg = ""
    vt    = os.getenv("VT_API_KEY")        or vt_cfg
    abuse = os.getenv("ABUSEIPDB_API_KEY") or abuse_cfg
    return vt.strip(), abuse.strip()


# ──────────────────────────────────────────────────────────────
#  FIRST-RUN HEALTH CHECK
# ──────────────────────────────────────────────────────────────
FIRST_RUN_FLAG = Path.home() / ".epa_ready"

def check_python_version():
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 8):
        return False, f"Python {major}.{minor} detected — 3.8 or higher required"
    return True, f"Python {major}.{minor}"

def check_package(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False

def check_internet():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except Exception:
        return False

def check_write_permission():
    try:
        test = Path.home() / ".epa_write_test"
        test.write_text("ok")
        test.unlink()
        return True
    except Exception:
        return False

def run_health_check(vt_key, abuse_key, force=False):
    """
    Runs a full environment check on first launch (or when forced).
    Guides the user through any issues interactively.
    Returns True if ready to proceed, False if critical issue found.
    """
    if FIRST_RUN_FLAG.exists() and not force:
        return True

    print()
    print(divider("═", C.CYAN))
    print(col("  STARTUP CHECK", C.CYAN, C.BOLD))
    print(col("  Checking your environment before running…", C.GRAY))
    print(divider("═", C.CYAN))
    print()

    all_clear = True

    # ── 1. Python version ───────────────────────────────────────
    py_ok, py_msg = check_python_version()
    if py_ok:
        ok(f"Python version        {py_msg}")
    else:
        err(f"Python version        {py_msg}")
        print(col("     Please upgrade Python at https://www.python.org/downloads/", C.GRAY))
        all_clear = False

    # ── 2. Required packages ────────────────────────────────────
    missing = []
    for pkg in ["requests", "email", "configparser"]:
        if not check_package(pkg):
            missing.append(pkg)

    if not missing:
        ok("Required packages     requests, email, configparser")
    else:
        err(f"Missing packages      {', '.join(missing)}")
        print()
        answer = input(col(f"  Install missing packages now? (Y/n): ", C.CYAN)).strip().lower()
        if answer not in ("n", "no"):
            import subprocess
            for pkg in missing:
                step(f"Installing {pkg}…")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    ok(f"Installed {pkg}")
                else:
                    err(f"Failed to install {pkg} — run: pip install {pkg}")
                    all_clear = False
        else:
            all_clear = False

    # ── 3. Internet connectivity ────────────────────────────────
    print()
    step("Checking internet connectivity…")
    if check_internet():
        ok("Internet              reachable")
    else:
        warn("Internet              unreachable — API features will not work")
        tip("The tool still works offline for header and keyword analysis.")

    # ── 4. Config file & write permission ───────────────────────
    print()
    if check_write_permission():
        ok(f"Write permission      {Path.home()} — OK")
    else:
        warn(f"Write permission      cannot write to home directory")
        tip("Config and reports may not save correctly.")

    if CONFIG_PATH.exists():
        ok(f"Config file           {CONFIG_PATH} — found")
    else:
        warn(f"Config file           not found (API keys not configured)")

    # ── 5. API keys ─────────────────────────────────────────────
    print()
    print(f"  {col('API Keys', C.WHITE, C.BOLD)}")
    print()

    vt_status    = col("✓  configured", C.GREEN) if vt_key    else col("✗  not configured", C.RED)
    abuse_status = col("✓  configured", C.GREEN) if abuse_key else col("✗  not configured", C.RED)
    print(f"  {col('VirusTotal :', C.GRAY)}  {vt_status}")
    print(f"  {col('AbuseIPDB  :', C.GRAY)}  {abuse_status}")
    print()

    if not vt_key and not abuse_key:
        print(col("""  These APIs are free and expand what the tool can detect:
  · VirusTotal  — scan URLs against 90+ antivirus engines
  · AbuseIPDB   — check if the sender IP is a known threat

  Get free keys at:
    https://www.virustotal.com/gui/join-us
    https://www.abuseipdb.com/register
""", C.GRAY))
        answer = input(col("  Set up API keys now? (Y/n): ", C.CYAN)).strip().lower()
        if answer not in ("n", "no"):
            print()
            new_vt    = input(col("  VirusTotal API key  (Enter to skip): ", C.CYAN)).strip()
            new_abuse = input(col("  AbuseIPDB  API key  (Enter to skip): ", C.CYAN)).strip()
            if new_vt or new_abuse:
                save_config(new_vt, new_abuse)
                ok(f"Keys saved to {CONFIG_PATH}")
                vt_key, abuse_key = new_vt, new_abuse
            else:
                warn("No keys saved — continuing in offline mode")
                tip("Add keys any time with: python3 analyzer.py --setup")
        else:
            warn("Skipping API setup — continuing in offline mode")
            tip("Add keys any time with: python3 analyzer.py --setup")

    elif not vt_key:
        answer = input(col("  VirusTotal key missing. Add it now? (Y/n): ", C.CYAN)).strip().lower()
        if answer not in ("n", "no"):
            new_vt = input(col("  VirusTotal API key: ", C.CYAN)).strip()
            if new_vt:
                save_config(new_vt, abuse_key)
                ok("VirusTotal key saved")
                vt_key = new_vt

    elif not abuse_key:
        answer = input(col("  AbuseIPDB key missing. Add it now? (Y/n): ", C.CYAN)).strip().lower()
        if answer not in ("n", "no"):
            new_abuse = input(col("  AbuseIPDB API key: ", C.CYAN)).strip()
            if new_abuse:
                save_config(vt_key, new_abuse)
                ok("AbuseIPDB key saved")
                abuse_key = new_abuse

    # ── 6. Live API test (only if keys present and internet is up) ──
    api_test_passed = True
    if (vt_key or abuse_key) and check_internet():
        print()
        answer = input(col("  Test API keys now? (Y/n): ", C.CYAN)).strip().lower()
        if answer not in ("n", "no"):
            abuse_ok, vt_ok = test_api_keys(vt_key, abuse_key)
            # Only flag failure for keys that are actually configured
            if vt_key and not vt_ok:
                api_test_passed = False
                warn("VirusTotal key test failed — URL scanning will be skipped")
                tip("Update your key with: python3 analyzer.py --setup")
            if abuse_key and not abuse_ok:
                api_test_passed = False
                warn("AbuseIPDB key test failed — IP lookups will be skipped")
                tip("Update your key with: python3 analyzer.py --setup")

    # ── Done ────────────────────────────────────────────────────
    print()
    print(divider("═", C.CYAN))
    ready = all_clear and api_test_passed
    if ready:
        ok("All checks passed — ready to run")
        FIRST_RUN_FLAG.write_text("ready")
        tip("This check only runs once. Use --health to run it again any time.")
    elif not all_clear:
        err("Critical issues found — fix the errors above before continuing")
    else:
        warn("Ready to run — but fix the API key issues above for full functionality")
        ok("Saving ready state anyway (tool works offline)")
        FIRST_RUN_FLAG.write_text("ready")
    print(divider("═", C.CYAN))
    print()

    if not all_clear:
        sys.exit(1)

    return vt_key, abuse_key

# ──────────────────────────────────────────────────────────────
#  SETUP WIZARD
# ──────────────────────────────────────────────────────────────
def run_setup_wizard():
    print()
    print(divider("═", C.CYAN))
    print(col("  API KEY SETUP WIZARD", C.CYAN, C.BOLD))
    print(divider("═", C.CYAN))
    print(col("""
  This tool integrates with two free APIs:

  1. VirusTotal  — scan URLs for malicious content
     Get a free key at: https://www.virustotal.com/gui/join-us
     Free tier: 4 lookups/min, 500/day

  2. AbuseIPDB   — check sender IP reputation
     Get a free key at: https://www.abuseipdb.com/register
     Free tier: 1,000 lookups/day

  Keys are saved to ~/.epa_config (chmod 600).
  You can skip either and the tool still works offline.
""", C.WHITE))

    vt_key    = input(col("  VirusTotal API key  (Enter to skip): ", C.CYAN)).strip()
    abuse_key = input(col("  AbuseIPDB  API key  (Enter to skip): ", C.CYAN)).strip()

    if vt_key or abuse_key:
        save_config(vt_key, abuse_key)
        ok(f"Keys saved to {CONFIG_PATH}")
        tip("Run 'python3 analyzer.py --setup' any time to update them.")
    else:
        warn("No keys saved. Running in offline mode.")
        tip("Add keys later with: python3 analyzer.py --setup")

    print()

# ──────────────────────────────────────────────────────────────
#  BANNER & HELP
# ──────────────────────────────────────────────────────────────
BANNER = f"""
{col('  ╔══════════════════════════════════════════════════╗', C.CYAN)}
{col('  ║', C.CYAN)}  {col('Email Phishing Analyzer', C.WHITE, C.BOLD)}  {col('v3.0', C.GRAY)}{'':>23}{col('║', C.CYAN)}
{col('  ║', C.CYAN)}  {col('DwsHunter', C.CYAN)}  {col('·  github.com/DwsHunter', C.GRAY)}{'':>18}{col('║', C.CYAN)}
{col('  ╚══════════════════════════════════════════════════╝', C.CYAN)}
"""

USAGE_EXAMPLES = f"""
{col('USAGE', C.CYAN, C.BOLD)}
  python3 analyzer.py {col('[file]', C.YELLOW)} {col('[options]', C.GRAY)}

{col('EXAMPLES', C.CYAN, C.BOLD)}
  {col('# Basic analysis — prints report to terminal', C.GRAY)}
  python3 analyzer.py suspicious.eml

  {col('# Save report as JSON and TXT', C.GRAY)}
  python3 analyzer.py suspicious.eml {col('-o both', C.YELLOW)}

  {col('# Offline mode — skip API calls (fast, no keys needed)', C.GRAY)}
  python3 analyzer.py suspicious.eml {col('--offline', C.YELLOW)}

  {col('# First-time setup — save your API keys', C.GRAY)}
  python3 analyzer.py {col('--setup', C.YELLOW)}

  {col('# Interactive mode — guided prompts', C.GRAY)}
  python3 analyzer.py {col('--interactive', C.YELLOW)}

  {col('# Scan only headers, skip body analysis', C.GRAY)}
  python3 analyzer.py suspicious.eml {col('--headers-only', C.YELLOW)}

  {col('# Test that your API keys are working', C.GRAY)}
  python3 analyzer.py {col('--test-api', C.YELLOW)}

{col('OPTIONS', C.CYAN, C.BOLD)}
  {col('file', C.YELLOW)}              Path to .eml file (positional)
  {col('-o json|txt|both', C.YELLOW)}  Save report to file
  {col('--offline', C.YELLOW)}         Skip all API calls
  {col('--no-vt', C.YELLOW)}           Skip VirusTotal only
  {col('--no-ip', C.YELLOW)}           Skip AbuseIPDB only
  {col('--headers-only', C.YELLOW)}    Analyze headers only (no body/URL scan)
  {col('--setup', C.YELLOW)}           Run API key setup wizard
  {col('--interactive', C.YELLOW)}     Guided interactive mode
  {col('--quiet', C.YELLOW)}           Suppress banner and tips
  {col('--show-body', C.YELLOW)}       Print email body in report
  {col('--test-api', C.YELLOW)}         Test both API keys and exit
  {col('--health', C.YELLOW)}            Re-run the startup environment check

{col('TIPS', C.CYAN, C.BOLD)}
  {col('·', C.MAGENTA)} Drop the .eml on the terminal to auto-fill the path
  {col('·', C.MAGENTA)} Use {col('--offline', C.YELLOW)} for quick triage before external lookups
  {col('·', C.MAGENTA)} Use {col('-o json', C.YELLOW)} to feed results into SIEM or scripts
  {col('·', C.MAGENTA)} First run? Use {col('--setup', C.YELLOW)} to save your API keys once
  {col('·', C.MAGENTA)} SPF/DKIM/DMARC all fail + Reply-To mismatch = strong phishing signal
  {col('·', C.MAGENTA)} MD5 hashes in attachment output can be searched on VirusTotal directly
"""

# ──────────────────────────────────────────────────────────────
#  SUSPICIOUS KEYWORDS
# ──────────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = {
    "financial":              ["account","bank","transaction","invoice","payment","credit card","debit card","balance","transfer","withdrawal","deposit","funds","loan","bill","refund","claim","tax","wire transfer","earnings"],
    "personal_info":          ["password","login","username","SSN","social security","email address","verification","personal information","ID number","security question","birthday","driver's license","passport number","credit report","bank account number","PIN","security code"],
    "urgent_action":          ["urgent","immediate","action required","respond now","attention","asap","verify","act fast","important","critical","failure to act","limited time","time sensitive","deadline","don't miss","last chance","act immediately"],
    "rewards_and_incentives": ["offer","free","gift","reward","promotion","claim now","redeem","winner","prize","congratulations","exclusive offer","limited time offer","exclusive access","discount","voucher","bonus","gift card","cash prize","holiday special","get your reward"],
    "fake_brands":            ["paypal","apple","google","amazon","microsoft","facebook","instagram","twitter","netflix","ebay","adobe","bank of america","wells fargo","chase","american express","samsung","t-mobile","att","verizon","citi","hsbc","barclays","skype","dropbox","linkedin","zoom","whatsapp"],
    "tech_terms":             ["software update","security patch","virus alert","malware","warning","trojan","phishing attempt","firewall","password reset","2FA","login attempt","account locked","suspicious activity","data breach","new device login","account compromised","encrypted","secure","authenticator"],
    "social_engagement":      ["click here","download","open attachment","open link","view image","open file","accept request","join now","sign up","register","secure your account","unlock","click to claim","view offer","start now","download now","take action","confirm","subscribe","free download","open now","free access"],
    "threats_and_intimidation":["suspended account","your account will be locked","illegal activity","fraud alert","unauthorized login","immediately block","stop using","you have been flagged","unpaid balance","compensation","legal action","court","lawsuit","sue","severe consequences","non-compliance","imminent danger","fail to act"],
}

# ──────────────────────────────────────────────────────────────
#  EMAIL PARSING
# ──────────────────────────────────────────────────────────────
def read_email_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            return BytesParser(policy=policy.default).parse(f)
    except UnicodeDecodeError:
        try:
            with open(file_path, 'rb') as f:
                return BytesParser(policy=policy.compat32).parse(f)
        except Exception as e:
            err(f"Encoding fallback failed: {e}"); return None
    except Exception as e:
        err(f"Error reading email: {e}"); return None

def extract_headers(msg):
    def safe(k): v = msg.get(k); return str(v) if v else "Not Present"
    return {
        "From":                   safe("From"),
        "To":                     safe("To"),
        "Reply-To":               safe("Reply-To"),
        "Subject":                safe("Subject"),
        "Date":                   safe("Date"),
        "Message-ID":             safe("Message-ID"),
        "X-Originating-IP":       safe("X-Originating-IP"),
        "Received-SPF":           safe("Received-SPF"),
        "Authentication-Results": safe("Authentication-Results"),
        "X-Mailer":               safe("X-Mailer"),
        "MIME-Version":           safe("MIME-Version"),
    }

def extract_ip_from_headers(headers):
    ip = None; domain = None
    auth = headers.get("Authentication-Results", "")
    x_ip = headers.get("X-Originating-IP", "")
    m = re.search(r"\(sender IP is ([\d\.]+)\)", auth)
    d = re.search(r"smtp\.mailfrom=([\w.\-]+)", auth)
    if m:   ip = m.group(1)
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", x_ip.strip().strip("'\"")):  ip = x_ip.strip().strip("'\"")
    if d:   domain = d.group(1)
    return ip, domain

def parse_authentication_results(auth):
    if not auth or auth == "Not Present":
        return {"SPF": "N/A", "DKIM": "N/A", "DMARC": "N/A"}
    out = {}
    for k, p in [("SPF",r"spf=([\w\-]+)"),("DKIM",r"dkim=([\w\-]+)"),("DMARC",r"dmarc=([\w\-]+)")]:
        m = re.search(p, auth, re.IGNORECASE)
        out[k] = m.group(1) if m else "N/A"
    return out

def get_email_body(msg):
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if "attachment" in str(part.get("Content-Disposition","")): continue
            if ctype == "text/plain":
                try: parts.append(part.get_content())
                except:
                    r = part.get_payload(decode=True)
                    if r: parts.append(r.decode("utf-8", errors="replace"))
            elif ctype == "text/html" and not parts:
                try: html = part.get_content()
                except:
                    r = part.get_payload(decode=True)
                    html = r.decode("utf-8", errors="replace") if r else ""
                parts.append(re.sub(r"<[^>]+>"," ", html))
    else:
        try: content = msg.get_content()
        except:
            r = msg.get_payload(decode=True)
            content = r.decode("utf-8", errors="replace") if r else "No body found"
        if msg.get_content_type() == "text/html":
            content = re.sub(r"<[^>]+>"," ", content)
        parts.append(content)
    body = "\n".join(parts).strip()
    body = re.sub(r"[ \t]+"," ", body)
    body = re.sub(r"\n{3,}","\n\n", body)
    return body or "No body content found"

def extract_urls(body):
    raw = re.findall(r'https?://[^\s<>"\']+', body)
    seen = []; out = []
    for url in raw:
        url = re.sub(r'[.,;:!?\)\]>]+$','', url)
        if url not in seen: seen.append(url); out.append(url)
    return out

def extract_attachments(msg):
    atts = []
    for part in msg.walk():
        if "attachment" in str(part.get("Content-Disposition","")):
            fn  = part.get_filename() or "unnamed"
            raw = part.get_payload(decode=True)
            sz  = len(raw) if raw else 0
            md5 = hashlib.md5(raw).hexdigest() if raw else "N/A"
            atts.append({"filename": fn, "content_type": part.get_content_type(), "size_bytes": sz, "md5": md5})
    return atts

def check_header_anomalies(headers):
    issues = []
    from_raw    = headers.get("From","")
    replyto_raw = headers.get("Reply-To","Not Present")
    msg_id      = headers.get("Message-ID","Not Present")
    fd = re.search(r"@([\w.\-]+)", from_raw)
    rd = re.search(r"@([\w.\-]+)", replyto_raw)
    if fd and rd and fd.group(1).lower() != rd.group(1).lower():
        issues.append(f"Reply-To domain ({rd.group(1)}) ≠ From domain ({fd.group(1)})")
    if msg_id == "Not Present":
        issues.append("Missing Message-ID — common in spoofed/bulk emails")
    m = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_raw)
    if m:
        display = m.group(1).strip().lower()
        address = m.group(2).strip().lower()
        for brand in ["paypal","apple","google","amazon","microsoft","facebook","netflix","chase","wellsfargo"]:
            if brand in display and brand not in address:
                issues.append(f"Display name impersonates '{m.group(1).strip()}' but address is <{m.group(2).strip()}>")
    return issues

def analyze_keywords(body):
    out = {}
    for cat, kws in SUSPICIOUS_KEYWORDS.items():
        found = [k for k in kws if re.search(r"\b"+re.escape(k)+r"\b", body, re.IGNORECASE)]
        if found: out[cat] = found
    return out

# ──────────────────────────────────────────────────────────────
#  API CALLS
# ──────────────────────────────────────────────────────────────
def analyze_ip_abuseipdb(ip, api_key):
    if not api_key:
        return {"status": "skipped", "reason": "no API key"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        if r.status_code == 200:
            d = r.json().get("data",{})
            return {"ip": d.get("ipAddress"), "abuse_confidence": d.get("abuseConfidenceScore"),
                    "country": d.get("countryCode"), "isp": d.get("isp"),
                    "total_reports": d.get("totalReports"), "last_reported": d.get("lastReportedAt"),
                    "is_tor": d.get("isTor")}
        return {"error": f"HTTP {r.status_code}"}
    except requests.Timeout: return {"error": "timeout"}
    except Exception as e:   return {"error": str(e)}

def scan_url_virustotal(url, api_key):
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    gui    = f"https://www.virustotal.com/gui/url/{url_id}"
    if not api_key:
        return {"url": url, "status": "skipped — no API key", "gui_link": gui}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}, timeout=15)
        if r.status_code == 200:
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"url": url, "malicious": stats.get("malicious",0),
                    "suspicious": stats.get("suspicious",0), "harmless": stats.get("harmless",0),
                    "undetected": stats.get("undetected",0), "gui_link": gui}
        if r.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key}, data={"url": url}, timeout=15)
            return {"url": url, "status": "submitted — check back shortly", "gui_link": gui}
        return {"url": url, "error": f"HTTP {r.status_code}", "gui_link": gui}
    except requests.Timeout: return {"url": url, "error": "timeout", "gui_link": gui}
    except Exception as e:   return {"url": url, "error": str(e), "gui_link": gui}

# ──────────────────────────────────────────────────────────────
#  SCORING
# ──────────────────────────────────────────────────────────────
def calculate_risk(auth, anomalies, ip_data, url_results, keywords):
    score = 0; breakdown = []
    for check in ["SPF","DKIM","DMARC"]:
        v = auth.get(check,"N/A").lower()
        if v in ("fail","softfail","none"):
            score += 10; breakdown.append((10, f"{check} = {v}"))
    for a in anomalies:
        score += 15; breakdown.append((15, f"Header anomaly: {a}"))
    if isinstance(ip_data, dict):
        c = ip_data.get("abuse_confidence") or 0
        if   c > 75: score += 20; breakdown.append((20, f"IP abuse confidence {c}%"))
        elif c > 25: score += 10; breakdown.append((10, f"IP abuse confidence {c}%"))
        if ip_data.get("is_tor"): score += 10; breakdown.append((10, "Sender IP is a Tor exit node"))
    for res in url_results:
        if isinstance(res, dict) and (res.get("malicious") or 0) > 0:
            score += 20; breakdown.append((20, f"Malicious URL: {res.get('url','')}"))
    weights = {"threats_and_intimidation":8,"urgent_action":6,"personal_info":5,"financial":4,"fake_brands":5,"tech_terms":3,"social_engagement":3,"rewards_and_incentives":2}
    for cat, hits in keywords.items():
        w = weights.get(cat, 2)
        pts = min(w * len(hits), 15)
        score += pts
        breakdown.append((pts, f"Keywords [{cat}]: {', '.join(hits[:4])}{'…' if len(hits)>4 else ''}"))
    score = min(score, 100)
    if   score >= 70: verdict = "HIGH RISK — likely phishing"
    elif score >= 40: verdict = "MEDIUM RISK — suspicious"
    elif score >= 15: verdict = "LOW RISK — minor indicators"
    else:             verdict = "CLEAN — no significant indicators"
    return {"score": score, "verdict": verdict, "breakdown": breakdown}

# ──────────────────────────────────────────────────────────────
#  DISPLAY  (color terminal report)
# ──────────────────────────────────────────────────────────────
def print_report(headers, auth, anomalies, ip, domain, ip_data,
                 urls, url_results, attachments, keywords, risk,
                 show_body=False, body=""):

    def row(label, value, vfn=None):
        v = vfn(value) if vfn else col(str(value), C.WHITE)
        print(f"  {col(f'{label:<26}', C.GRAY)}  {v}")

    # ── Headers ──────────────────────────────────────
    print(section("HEADERS"))
    for k, v in headers.items():
        if v != "Not Present":
            row(k, v)
        else:
            row(k, col("Not Present", C.GRAY))
    print()

    # ── Authentication ────────────────────────────────
    print(section("AUTHENTICATION"))
    row("SPF",   auth.get("SPF","N/A"),  status_color)
    row("DKIM",  auth.get("DKIM","N/A"), status_color)
    row("DMARC", auth.get("DMARC","N/A"),status_color)
    if ip:     row("Sender IP",  ip)
    if domain: row("From Domain",domain)
    print()

    # ── Anomalies ─────────────────────────────────────
    print(section("HEADER ANOMALIES"))
    if anomalies:
        for a in anomalies:
            print(f"  {col('⚑', C.RED, C.BOLD)}  {col(a, C.YELLOW)}")
    else:
        print(f"  {col('✓  None detected', C.GREEN)}")
    print()

    # ── IP Reputation ─────────────────────────────────
    print(section("IP REPUTATION"))
    if isinstance(ip_data, dict) and "error" not in ip_data and "status" not in ip_data:
        conf = ip_data.get("abuse_confidence", 0) or 0
        conf_col = C.RED if conf > 75 else (C.YELLOW if conf > 25 else C.GREEN)
        row("IP",               ip_data.get("ip","—"))
        row("Abuse Confidence", col(f"{conf}%", conf_col, C.BOLD))
        row("Country",          ip_data.get("country","—"))
        row("ISP",              ip_data.get("isp","—"))
        row("Total Reports",    ip_data.get("total_reports","—"))
        row("Last Reported",    ip_data.get("last_reported","—") or "Never")
        row("Tor Exit Node",    col("YES", C.RED, C.BOLD) if ip_data.get("is_tor") else col("No", C.GREEN))
    elif isinstance(ip_data, dict):
        reason = ip_data.get("reason") or ip_data.get("error","")
        print(f"  {col(reason, C.GRAY)}")
    elif ip:
        print(f"  {col(ip, C.WHITE)}  {col('— lookup skipped (offline mode or no API key)', C.GRAY)}")
    else:
        print(f"  {col('No sender IP found in headers', C.GRAY)}")
    print()

    # ── URLs ──────────────────────────────────────────
    print(section("URLS & SCAN RESULTS"))
    if not urls:
        print(f"  {col('No URLs found in body', C.GRAY)}")
    else:
        for res in url_results:
            u = res.get("url","")
            mal = res.get("malicious", 0) or 0
            sus = res.get("suspicious", 0) or 0
            skipped = "skipped" in str(res.get("status","")).lower()
            url_col = C.RED if mal > 0 else (C.YELLOW if sus > 0 else C.WHITE)
            print(f"  {col('URL', C.GRAY)}  {col(u, url_col)}")
            if not skipped and "error" not in res:
                print(f"       {col('Malicious:', C.GRAY)} {col(str(mal), C.RED if mal>0 else C.GREEN)}  "
                      f"{col('Suspicious:', C.GRAY)} {col(str(sus), C.YELLOW if sus>0 else C.GREEN)}  "
                      f"{col('Harmless:', C.GRAY)} {col(str(res.get('harmless',0)), C.GREEN)}")
            elif skipped:
                print(f"       {col('Scan skipped — no API key', C.GRAY)}")
            if res.get("gui_link"):
                print(f"       {col('VT:', C.GRAY)} {col(res['gui_link'], C.BLUE)}")
            print()
    print()

    # ── Attachments ───────────────────────────────────
    print(section("ATTACHMENTS"))
    if not attachments:
        print(f"  {col('None', C.GRAY)}")
    else:
        for att in attachments:
            ext = Path(att["filename"]).suffix.lower()
            risky_ext = ext in (".exe",".bat",".ps1",".vbs",".js",".scr",".hta",".cmd",".dll",".jar")
            fn_col = C.RED if risky_ext else C.WHITE
            print(f"  {col('⊞', C.CYAN)}  {col(att['filename'], fn_col, C.BOLD)}")
            print(f"     {col('Type:', C.GRAY)} {att['content_type']}  "
                  f"{col('Size:', C.GRAY)} {att['size_bytes']} bytes  "
                  f"{col('MD5:', C.GRAY)} {col(att['md5'], C.CYAN)}")
            if risky_ext:
                print(f"     {col('⚠ High-risk file extension', C.RED, C.BOLD)}")
            tip(f"Search MD5 on VT: https://www.virustotal.com/gui/file/{att['md5']}")
    print()

    # ── Keywords ──────────────────────────────────────
    print(section("SUSPICIOUS KEYWORDS"))
    if not keywords:
        print(f"  {col('None detected', C.GREEN)}")
    else:
        cat_icons = {
            "financial":"💰","personal_info":"🔑","urgent_action":"🚨",
            "rewards_and_incentives":"🎁","fake_brands":"🎭","tech_terms":"⚙️",
            "social_engagement":"👆","threats_and_intimidation":"⚖️"
        }
        for cat, hits in keywords.items():
            icon = cat_icons.get(cat, "•")
            label = col(f"  {icon}  {cat.replace('_',' ').title():<28}", C.GRAY)
            kws   = col(", ".join(hits), C.YELLOW)
            print(f"{label} {kws}")
    print()

    # ── Risk Score ────────────────────────────────────
    score   = risk["score"]
    verdict = risk["verdict"]
    bar_len = int((score / 100) * (W - 10))
    bar_col = C.RED if score >= 70 else (C.YELLOW if score >= 40 else (C.CYAN if score >= 15 else C.GREEN))
    print(divider("═", C.CYAN))
    print(f"  {col('RISK SCORE', C.WHITE, C.BOLD)}  {risk_color(score)}   {verdict_color(verdict)}")
    print(f"  {col('▓' * bar_len, bar_col)}{col('░' * (W - 10 - bar_len), C.GRAY)}")
    print(divider("═", C.CYAN))
    print()
    print(f"  {col('Score Breakdown:', C.CYAN, C.BOLD)}")
    for pts, reason in risk["breakdown"]:
        pts_col = C.RED if pts >= 15 else (C.YELLOW if pts >= 10 else C.GRAY)
        print(f"  {col(f'+{pts:<4}', pts_col, C.BOLD)} {col(reason, C.WHITE)}")
    print()

    # ── Body (optional) ───────────────────────────────
    if show_body and body:
        print(section("EMAIL BODY"))
        wrapped = textwrap.fill(body[:2000], width=W-4, initial_indent="  ", subsequent_indent="  ")
        print(col(wrapped, C.GRAY))
        if len(body) > 2000:
            print(col(f"  … (truncated, {len(body)} chars total)", C.GRAY))
        print()

# ──────────────────────────────────────────────────────────────
#  JSON / TXT REPORT SAVE
# ──────────────────────────────────────────────────────────────
def build_json_report(file_path, headers, auth, anomalies, ip, domain,
                      ip_data, urls, url_results, keywords, attachments, risk):
    return {
        "meta": {
            "tool": "Email Phishing Analyzer v3.0 — DwsHunter",
            "analyzed": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "file": os.path.basename(file_path),
        },
        "headers":          headers,
        "authentication":   {**auth, "sender_ip": ip, "from_domain": domain},
        "header_anomalies": anomalies or [],
        "ip_reputation":    ip_data or {},
        "urls":             urls,
        "url_scan_results": url_results,
        "attachments":      attachments,
        "keywords":         keywords,
        "risk":             {"score": risk["score"], "verdict": risk["verdict"],
                             "breakdown": [{"points": p, "reason": r} for p,r in risk["breakdown"]]},
    }

def save_report(report, file_path, fmt):
    base = os.path.splitext(file_path)[0]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{base}_report_{ts}.{fmt}"
    if fmt == "json":
        with open(path,"w",encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
    else:
        with open(path,"w",encoding="utf-8") as f:
            f.write(json.dumps(report, indent=4, ensure_ascii=False))
    return path

# ──────────────────────────────────────────────────────────────
#  INTERACTIVE MODE
# ──────────────────────────────────────────────────────────────
def interactive_mode(vt_key, abuse_key):
    print(col("\n  INTERACTIVE MODE\n", C.CYAN, C.BOLD))
    tip("You can drag-and-drop a .eml file into the terminal to paste its path.")
    print()

    file_path = input(col("  Path to .eml file: ", C.CYAN)).strip().strip("'\"")
    if not os.path.isfile(file_path):
        err(f"File not found: {file_path}"); return

    print()
    skip_vt = input(col("  Run VirusTotal URL scan? (Y/n): ", C.CYAN)).strip().lower() in ("n","no")
    skip_ip = input(col("  Run AbuseIPDB IP check? (Y/n): ", C.CYAN)).strip().lower() in ("n","no")
    show_body = input(col("  Print email body in report? (y/N): ", C.CYAN)).strip().lower() in ("y","yes")

    fmt_input = input(col("  Save report? (json / txt / both / no): ", C.CYAN)).strip().lower()
    save_fmt  = None if fmt_input in ("no","n","") else fmt_input

    return file_path, skip_vt, skip_ip, show_body, save_fmt


# ──────────────────────────────────────────────────────────────
#  API KEY TESTER
# ──────────────────────────────────────────────────────────────
def test_api_keys(vt_key, abuse_key):
    """
    Tests both API keys with a safe known endpoint.
    Returns (abuse_ok, vt_ok) booleans so callers can react to failures.
    """
    print()
    print(divider("═", C.CYAN))
    print(col("  API KEY TEST", C.CYAN, C.BOLD))
    print(divider("═", C.CYAN))
    print()

    abuse_ok = False
    vt_ok    = False

    # ── AbuseIPDB ─────────────────────────────────────────────
    print(f"  {col('AbuseIPDB', C.WHITE, C.BOLD)}")
    if not abuse_key:
        warn("No key configured — run --setup to add one")
    else:
        print(f"  {col('Key:', C.GRAY)} {col(abuse_key[:6] + '•' * 10, C.GRAY)}")
        step("Sending test request (checking 8.8.8.8)…")
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                ok(f"Connected  —  ISP: {d.get('isp','?')}  Country: {d.get('countryCode','?')}")
                abuse_ok = True
            elif r.status_code == 401:
                err("Invalid API key — update it with: python3 analyzer.py --setup")
            elif r.status_code == 422:
                err("Key format rejected — check for copy-paste errors")
            elif r.status_code == 429:
                warn("Rate limit hit — key is valid but daily quota is exhausted")
                abuse_ok = True  # key works, just throttled
            else:
                err(f"Unexpected response: HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            err("Connection failed — check your internet connection")
        except requests.exceptions.Timeout:
            err("Request timed out — AbuseIPDB may be unreachable")
        except Exception as e:
            err(f"Error: {e}")

    print()

    # ── VirusTotal ────────────────────────────────────────────
    # NOTE: Free tier does NOT allow /ip_addresses — use /users/me which
    # works on all tiers and confirms the key is valid without spending quota.
    print(f"  {col('VirusTotal', C.WHITE, C.BOLD)}")
    if not vt_key:
        warn("No key configured — run --setup to add one")
    else:
        print(f"  {col('Key:', C.GRAY)} {col(vt_key[:6] + '•' * 10, C.GRAY)}")
        step("Sending test request (verifying key via /users/me)…")
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/users/me",
                headers={"x-apikey": vt_key},
                timeout=15
            )
            if r.status_code == 200:
                data       = r.json().get("data", {})
                attrs      = data.get("attributes", {})
                username   = data.get("id", "?")
                tier       = attrs.get("status", "standard")
                quota_used = attrs.get("quota_attributes", {}).get("api_requests_daily", {}).get("used", "?")
                quota_max  = attrs.get("quota_attributes", {}).get("api_requests_daily", {}).get("allowed", "?")
                ok(f"Connected  —  User: {username}  Tier: {tier}  Quota: {quota_used}/{quota_max} today")
                vt_ok = True
            elif r.status_code == 401:
                err("Invalid API key — update it with: python3 analyzer.py --setup")
            elif r.status_code == 403:
                # 403 on /users/me is rare but means key exists with restricted scope
                # Try a lightweight URL lookup to double-check
                step("Got 403 on /users/me — trying URL lookup to verify scope…")
                test_url_id = base64.urlsafe_b64encode(b"https://google.com").rstrip(b"=").decode()
                r2 = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{test_url_id}",
                    headers={"x-apikey": vt_key},
                    timeout=15
                )
                if r2.status_code in (200, 404):
                    ok("Key works for URL scanning (limited scope — cannot read account info)")
                    vt_ok = True
                elif r2.status_code == 401:
                    err("Invalid API key — update it with: python3 analyzer.py --setup")
                else:
                    err(f"Key has restricted permissions (HTTP 403)")
                    tip("Go to https://www.virustotal.com/gui/my-apikey and verify your key is active")
            elif r.status_code == 429:
                warn("Rate limit hit — key is valid but quota exhausted. Wait a minute and retry.")
                vt_ok = True
            else:
                err(f"Unexpected response: HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            err("Connection failed — check your internet connection")
        except requests.exceptions.Timeout:
            err("Request timed out — VirusTotal may be unreachable")
        except Exception as e:
            err(f"Error: {e}")

    print()
    print(divider("═", C.CYAN))
    print()
    return abuse_ok, vt_ok

# ──────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Email Phishing Analyzer v3.0 — DwsHunter",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    parser.add_argument("email",           nargs="?",      help="Path to .eml file")
    parser.add_argument("-o","--output",   choices=["json","txt","both"], default=None)
    parser.add_argument("--offline",       action="store_true", help="Skip all API calls")
    parser.add_argument("--no-vt",         action="store_true")
    parser.add_argument("--no-ip",         action="store_true")
    parser.add_argument("--headers-only",  action="store_true")
    parser.add_argument("--show-body",     action="store_true")
    parser.add_argument("--setup",         action="store_true", help="Run API key wizard")
    parser.add_argument("--interactive",   action="store_true")
    parser.add_argument("--quiet",         action="store_true")
    parser.add_argument("-h","--help",     action="store_true")
    parser.add_argument("--test-api",      action="store_true", help="Test API keys and exit")
    parser.add_argument("--health",         action="store_true", help="Re-run startup health check")
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    if args.help:
        print(USAGE_EXAMPLES); return

    if args.setup:
        run_setup_wizard(); return

    vt_key, abuse_key = get_api_keys()

    if args.test_api:
        test_api_keys(vt_key, abuse_key); return

    # First-run health check (or forced with --health)
    if not args.quiet:
        result = run_health_check(vt_key, abuse_key, force=getattr(args, "health", False))
        if result and result is not True:
            vt_key, abuse_key = result  # keys may have been configured during check

    if getattr(args, "health", False):
        return

    # Show API key status
    if not args.quiet:
        vt_ok    = bool(vt_key)
        abuse_ok = bool(abuse_key)
        vt_status    = col("active", C.GREEN) if vt_ok    else col("not configured", C.GRAY)
        abuse_status = col("active", C.GREEN) if abuse_ok else col("not configured", C.GRAY)
        print(f"  {col('VirusTotal:', C.GRAY)} {vt_status}   {col('AbuseIPDB:', C.GRAY)} {abuse_status}")
        print()

    # Interactive mode
    if args.interactive:
        result = interactive_mode(vt_key, abuse_key)
        if not result: return
        file_path, skip_vt, skip_ip, show_body, save_fmt = result
    else:
        file_path = args.email
        if not file_path:
            tip("Usage: python3 analyzer.py <file.eml>  |  --help for all options")
            file_path = input(col("\n  Path to .eml file: ", C.CYAN)).strip().strip("'\"")
        skip_vt   = args.no_vt or args.offline
        skip_ip   = args.no_ip or args.offline
        show_body = args.show_body
        save_fmt  = args.output

    if not os.path.isfile(file_path):
        err(f"File not found: {file_path}"); sys.exit(1)

    # ── Parse ─────────────────────────────────────────
    print(divider())
    step(f"Parsing  →  {os.path.basename(file_path)}")
    msg = read_email_file(file_path)
    if not msg: err("Failed to parse email."); sys.exit(1)

    step("Extracting headers & authentication…")
    headers   = extract_headers(msg)
    auth      = parse_authentication_results(headers["Authentication-Results"])
    ip, domain = extract_ip_from_headers(headers)
    anomalies  = check_header_anomalies(headers)

    body = ""; urls = []; keywords = {}; attachments = []
    if not args.headers_only:
        step("Extracting body, URLs, and attachments…")
        body        = get_email_body(msg)
        urls        = extract_urls(body)
        keywords    = analyze_keywords(body)
        attachments = extract_attachments(msg)

    ip_data = None
    if ip and not skip_ip:
        step(f"Checking IP reputation  →  {ip}")
        ip_data = analyze_ip_abuseipdb(ip, abuse_key)

    url_results = []
    if urls and not skip_vt:
        step(f"Scanning {len(urls)} URL(s) on VirusTotal…")
        for u in urls:
            url_results.append(scan_url_virustotal(u, vt_key))
    elif urls and skip_vt:
        for u in urls:
            url_id = base64.urlsafe_b64encode(u.encode()).rstrip(b"=").decode()
            url_results.append({"url": u, "status": "skipped", "gui_link": f"https://www.virustotal.com/gui/url/{url_id}"})

    step("Calculating risk score…")
    risk = calculate_risk(auth, anomalies, ip_data, url_results, keywords)
    print(divider())
    print()

    # ── Print ─────────────────────────────────────────
    print_report(headers, auth, anomalies, ip, domain, ip_data,
                 urls, url_results, attachments, keywords, risk,
                 show_body=show_body, body=body)

    # ── Save ──────────────────────────────────────────
    if save_fmt:
        report = build_json_report(file_path, headers, auth, anomalies, ip, domain,
                                   ip_data, urls, url_results, keywords, attachments, risk)
        fmts = ["json","txt"] if save_fmt == "both" else [save_fmt]
        for fmt in fmts:
            out = save_report(report, file_path, fmt)
            ok(f"Report saved → {out}")
        print()

    # ── Quick tips at end ─────────────────────────────
    if not args.quiet:
        score = risk["score"]
        if score >= 70:
            tip("HIGH RISK — do not click any links or open attachments. Report to your security team.")
        elif score >= 40:
            tip("Treat this email with caution. Verify the sender through a separate channel.")
        if attachments:
            tip("Upload attachment MD5 hashes to VirusTotal before opening any files.")
        if not vt_key and urls:
            tip(f"URLs found but not scanned. Add a VT key with --setup to enable scanning.")

if __name__ == "__main__":
    main()
