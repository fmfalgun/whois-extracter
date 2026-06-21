#!/usr/bin/env python3
"""
whois-extracter.py

Runs whois against a single domain, parses every security-relevant field,
scores risk, caches the result in a local SQLite cache (./cache.db), and
optionally writes the full JSON result to a file.

Output behaviour:
  - stdout     : always (coloured terminal summary)
  - cache.db   : always (SQLite TTL cache, ./cache.db — auto-created)
  - JSON file  : optional (--output <path>)

Cache behaviour:
  - Results are cached for 24 hours by default (tune with --ttl)
  - Use --no-cache to force a fresh fetch (cache is still written)

Usage examples:
  python3 whois-extracter.py -d nmap.org
  python3 whois-extracter.py -d nmap.org -o results.json
  python3 whois-extracter.py -d nmap.org --no-cache
  python3 whois-extracter.py -d nmap.org --ttl 6
"""

import subprocess   # to call the system whois binary and capture its output
import json         # stdlib JSON — no external dep needed
import re           # stdlib regex for parsing unstructured whois text
import sqlite3      # stdlib SQLite — for the TTL cache
import sys
import argparse     # stdlib CLI argument parsing
from datetime import datetime, timezone, timedelta
from pathlib import Path        # cleaner file path handling than os.path
from typing import Optional     # type hints — makes the code self-documenting


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS — Risk Scoring Rules
#
# All scoring thresholds and classification lists live here, not buried in
# functions. When whois output surprises you (false positives), this is the
# first place to tune without touching logic.
# ════════════════════════════════════════════════════════════════════════════

# Email providers that indicate personal (non-corporate) accounts.
# A personal email as registrant/admin means no org-enforced MFA, no email
# security policy, and a weaker spear-phishing barrier.
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com", "ymail.com", "rediffmail.com"
}

# NS patterns that indicate a parked domain (not live yet).
# Parking providers serve placeholder pages — the domain has no real attack
# surface yet, but it may go live soon, so we flag it for monitoring.
PARKED_NS_PATTERNS = [
    "parking", "sedo", "dan.com", "bodis", "above.com",
    "cashparking", "domainsbyproxy", "parkingcrew"
]

# NS strings that identify Cloudflare — the real origin IP is hidden behind
# Cloudflare's proxy. Separate bypass techniques are needed to find the origin.
CLOUDFLARE_NS_PATTERNS = ["cloudflare"]

# NS substrings that identify major cloud DNS providers.
# These are well-managed and unlikely to allow zone transfers, but misconfigs
# in the cloud account itself (IAM, Route53 policy) are still worth probing.
CLOUD_NS_PATTERNS = {
    "awsdns":    "aws",
    "azure-dns": "azure",
    "googledomains": "google-dns",
    "domaincontrol": "godaddy-dns",
}

# NS substrings that reveal shared hosting environments.
# On shared hosting, dozens of unrelated sites share one IP. This opens the
# door to virtual host enumeration — find other tenants on the same server.
SHARED_HOSTING_NS_PATTERNS = [
    "hostgator", "bluehost", "siteground", "dreamhost",
    "inmotionhosting", "a2hosting", "hostinger", "namecheap"
]

# EPP status codes that indicate the domain is brand-new, expiring, or dead.
# These are the lifecycle codes that matter most as attack signals.
LIFECYCLE_EPP_CODES = {
    "addperiod",          # registered < 5 days ago — almost always suspicious
    "redemptionperiod",   # expired, owner in 30-day rescue window
    "pendingdelete",      # ~5 days from being deleted — takeover opportunity
    "serverhold",         # registry killed DNS — ICANN enforcement
    "clienthold",         # registrar killed DNS — account suspended
    "pendingrestore",     # owner trying to rescue domain from redemption
}

# EPP lock codes — each one present adds protection against hijacking.
# 6 locks = fortress. 0 locks (just "ok") = open to social engineering.
LOCK_EPP_CODES = {
    "clienttransferprohibited",
    "clientupdateprohibited",
    "clientdeleteprohibited",
    "servertransferprohibited",
    "serverupdateprohibited",
    "serverdeleteprohibited",
}

# Registrar names (lowercase substrings) that indicate enterprise-grade
# protection. These registrars have hardened support teams — social engineering
# a domain transfer is nearly impossible.
ENTERPRISE_REGISTRAR_PATTERNS = [
    "markmonitor", "csc global", "safenames", "networksolutions",
    "register.com", "verisign"
]

# Budget registrar patterns — consumer-grade support, historically more
# susceptible to social engineering and account takeover via support chat.
BUDGET_REGISTRAR_PATTERNS = [
    "hostinger", "publicdomainregistry", "pdr", "namecheap",
    "godaddy", "namesilo", "name.com", "epik", "dynadot"
]

# TLDs that are statistically overrepresented in phishing and spam campaigns.
# Seeing one of these doesn't confirm malice — but it raises the prior.
ABUSIVE_TLDS = {
    ".xyz", ".top", ".club", ".site", ".online", ".tk",
    ".ml", ".ga", ".cf", ".gq", ".buzz", ".icu", ".cyou"
}

# Risk score thresholds — tune these if you're seeing too many false positives
# or missing real threats in your target population.
RISK_HIGH_THRESHOLD   = 60
RISK_MEDIUM_THRESHOLD = 30
RISK_LOW_THRESHOLD    = 10

# Path to the local TTL cache database — always relative to CWD.
CACHE_DB = "./cache.db"


# ════════════════════════════════════════════════════════════════════════════
# CACHE — SQLite TTL cache
# ════════════════════════════════════════════════════════════════════════════

def _cache_connect() -> sqlite3.Connection:
    """
    Open (or create) the cache.db and ensure the schema exists.

    The table uses domain as the PRIMARY KEY so UPSERT (INSERT OR REPLACE)
    keeps exactly one row per domain — no unbounded growth across runs.
    """
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whois_cache (
            domain      TEXT PRIMARY KEY,
            fetched_at  TEXT NOT NULL,
            json_data   TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_read(domain: str, ttl_hours: int) -> Optional[dict]:
    """
    Return the cached result for `domain` if it was fetched within `ttl_hours`.

    Returns None if:
      - No cache entry for this domain
      - Entry exists but is older than ttl_hours
    """
    conn = _cache_connect()
    try:
        row = conn.execute(
            "SELECT fetched_at, json_data FROM whois_cache WHERE domain = ?",
            (domain,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    fetched_at_str, json_data = row
    try:
        fetched_at = datetime.fromisoformat(fetched_at_str)
        # Attach UTC if naive (should always be UTC from our writes, but be safe)
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    age = datetime.now(timezone.utc) - fetched_at
    if age > timedelta(hours=ttl_hours):
        return None  # expired

    return json.loads(json_data)


def cache_write(domain: str, result: dict) -> None:
    """
    Write (or overwrite) a result dict to the cache.

    `fetched_at` is stored as an ISO 8601 UTC string so it survives
    process restarts without needing a real datetime column type.
    """
    fetched_at = datetime.now(timezone.utc).isoformat()
    conn = _cache_connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO whois_cache (domain, fetched_at, json_data) "
            "VALUES (?, ?, ?)",
            (domain, fetched_at, json.dumps(result))
        )
        conn.commit()
    finally:
        conn.close()


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — Fetch raw whois output
# ════════════════════════════════════════════════════════════════════════════

def fetch_raw(domain: str) -> str:
    """
    Call the system whois binary and return its full stdout as a string.

    We use the system binary (not a Python whois library) deliberately:
    - Libraries abstract away raw output and sometimes miss non-standard fields
    - The raw response is what we save to disk for false-positive auditing
    - Different whois servers return wildly different formats — the binary
      handles server routing (ARIN, RIPE, APNIC, etc.) for us automatically

    Timeout is 30s — most whois queries complete in 1–5s. If a server hangs
    (common with some TLD registries), we don't block the whole scan.
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,    # capture stdout and stderr separately
            text=True,              # decode bytes → str using system locale
            timeout=30
        )
        return result.stdout

    except subprocess.TimeoutExpired:
        # Whois server didn't respond — return empty so caller can handle it
        print(f"[WARN] whois timed out for {domain}")
        return ""

    except FileNotFoundError:
        # whois binary not installed — fail loudly with the fix
        print("[ERROR] whois binary not found.")
        print("        Install it: sudo apt install whois")
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Parse raw text into structured fields
# ════════════════════════════════════════════════════════════════════════════

def extract_field(raw: str, *keys: str) -> Optional[str]:
    """
    Try multiple key name variations and return the first non-empty match.

    Why multiple keys? Different whois servers use different field names for
    the same data:
      "Creation Date" vs "Created Date" vs "created" vs "Domain Registration Date"

    The regex anchors to line start (^) with multiline flag so we don't
    accidentally match mid-line text. The colon and surrounding whitespace
    are consumed by \\s*:\\s* — handles both "Key: value" and "Key : value".

    Returns None if:
      - No key found
      - Field exists but contains a redaction marker (GDPR / privacy service)
    """
    # Redaction markers we treat as "not available" — return None so the
    # analyzer doesn't flag redacted fields as exposed contact data
    REDACTED_MARKERS = {
        "redacted for privacy",
        "redacted",
        "n/a",
        "not available from registry",
        "data redacted",
        "gdpr redacted",
        "",
    }

    for key in keys:
        # re.escape handles keys with special chars like "." in "Registrar URL"
        pattern = rf"(?i)^{re.escape(key)}\s*:\s*(.+)$"
        match = re.search(pattern, raw, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value.lower() not in REDACTED_MARKERS:
                return value

    return None


def extract_all(raw: str, key: str) -> list:
    """
    Extract every occurrence of a repeated field as a list.

    Used for fields that appear multiple times:
      - "Name Server: ns1.example.com"
      - "Name Server: ns2.example.com"
      - "Domain Status: clientTransferProhibited ..."
      - "Domain Status: serverUpdateProhibited ..."

    Returns empty list if key is not found — callers don't need to null-check.
    """
    pattern = rf"(?i)^{re.escape(key)}\s*:\s*(.+)$"
    return [m.group(1).strip() for m in re.finditer(pattern, raw, re.MULTILINE)]


def parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse a date string into a timezone-aware datetime object.

    Whois servers are notorious for inconsistent date formats. We try a list
    of known formats — first match wins. All results are normalised to UTC
    so age/expiry calculations are timezone-consistent regardless of which
    whois server produced the date string.

    Returns None if the string can't be parsed — callers handle gracefully.
    """
    if not date_str:
        return None

    # Order matters — more specific formats first to avoid partial matches
    FORMATS = [
        "%Y-%m-%dT%H:%M:%SZ",       # 2018-02-21T17:22:52Z  (ISO 8601 UTC)
        "%Y-%m-%dT%H:%M:%S%z",      # 2018-02-21T17:22:52+0000
        "%Y-%m-%dT%H:%M:%S.%fZ",    # 2018-02-21T17:22:52.000Z
        "%Y-%m-%d",                  # 2018-02-21
        "%d-%b-%Y",                  # 21-Feb-2018
        "%Y.%m.%d",                  # 2018.02.21  (some European registrars)
        "%d/%m/%Y",                  # 21/02/2018  (some ccTLD registrars)
    ]

    # Truncate to 25 chars — some servers append timezone offsets like
    # "+0000" after a space which confuses strptime
    clean = date_str.strip()[:25]

    for fmt in FORMATS:
        try:
            dt = datetime.strptime(clean, fmt)
            # Attach UTC if no timezone info — naive datetime causes comparison errors
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue

    return None


def parse_whois(raw: str, domain: str) -> dict:
    """
    Extract every security-relevant field from raw whois text into a dict.

    The output dict is the canonical representation of one whois result.
    Both the risk analyzer and all output adapters (JSON, DB, printer) read
    from this structure — so any new field you add here automatically flows
    through to all outputs.

    Field groups:
      dates       — creation, updated, expiry + calculated age/days-to-expiry
      registrar   — name, url, iana_id, whois_server, reseller
      statuses    — list of EPP codes (lowercased, first word only)
      name_servers — deduplicated list (lowercased)
      dnssec      — raw string value
      contacts    — registrant / admin / tech sub-dicts
    """
    now = datetime.now(timezone.utc)

    # ── Dates ──────────────────────────────────────────────────────────────
    creation_str = extract_field(raw,
        "Creation Date", "Created Date", "created",
        "Domain Registration Date", "Registered on")
    updated_str = extract_field(raw,
        "Updated Date", "Last Updated", "last-modified",
        "Domain Last Updated Date", "Last Modified")
    expiry_str = extract_field(raw,
        "Registry Expiry Date", "Registrar Registration Expiration Date",
        "Expiry Date", "Expiration Date", "Domain Expiration Date",
        "Expires on", "paid-till")

    creation_dt = parse_date(creation_str)
    expiry_dt   = parse_date(expiry_str)
    updated_dt  = parse_date(updated_str)

    # Age in days — None if we couldn't parse creation date
    age_days = (now - creation_dt).days if creation_dt else None

    # Negative value means the domain has already expired
    days_to_expiry = (expiry_dt - now).days if expiry_dt else None

    # ── Name servers ────────────────────────────────────────────────────────
    raw_ns = extract_all(raw, "Name Server")
    # Lowercase + deduplicate — some registries return the same NS twice with
    # different capitalisation (GOOGLE.COM vs google.com)
    name_servers = list({ns.lower() for ns in raw_ns if ns})

    # ── EPP status codes ────────────────────────────────────────────────────
    # Status lines look like:
    #   "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
    # We only want the code word, not the URL — so take the first token
    raw_statuses = extract_all(raw, "Domain Status")
    statuses = [s.lower().split()[0] for s in raw_statuses if s]

    # ── Registrar ───────────────────────────────────────────────────────────
    registrar         = extract_field(raw, "Registrar", "Sponsoring Registrar")
    registrar_url     = extract_field(raw, "Registrar URL")
    registrar_iana_id = extract_field(raw, "Registrar IANA ID")
    registrar_whois   = extract_field(raw, "Registrar WHOIS Server")

    # "Registration Service Provided By" appears when a registrant is itself
    # a PDR/Enom reseller — indicates slower abuse response chain
    reseller = extract_field(raw, "Registration Service Provided By")

    # ── Contacts ────────────────────────────────────────────────────────────
    # We extract all three contact roles — if the same name/email appears in
    # all three, that's a single point of failure (flagged in the analyzer)
    registrant = {
        "name":    extract_field(raw, "Registrant Name"),
        "org":     extract_field(raw, "Registrant Organization",
                                      "Registrant Organisation"),
        "email":   extract_field(raw, "Registrant Email"),
        "phone":   extract_field(raw, "Registrant Phone"),
        "country": extract_field(raw, "Registrant Country"),
        "address": extract_field(raw, "Registrant Street"),
        "city":    extract_field(raw, "Registrant City"),
        "state":   extract_field(raw, "Registrant State/Province"),
    }
    admin = {
        "name":  extract_field(raw, "Admin Name"),
        "org":   extract_field(raw, "Admin Organization", "Admin Organisation"),
        "email": extract_field(raw, "Admin Email"),
    }
    tech = {
        "name":  extract_field(raw, "Tech Name"),
        "org":   extract_field(raw, "Tech Organization", "Tech Organisation"),
        "email": extract_field(raw, "Tech Email"),
    }

    # ── DNSSEC ──────────────────────────────────────────────────────────────
    dnssec = extract_field(raw, "DNSSEC")

    return {
        "domain":     domain,
        "queried_at": now.isoformat(),
        "dates": {
            "creation":      creation_str,
            "updated":       updated_str,
            "expiry":        expiry_str,
            "age_days":      age_days,
            "days_to_expiry": days_to_expiry,
        },
        "registrar": {
            "name":         registrar,
            "url":          registrar_url,
            "iana_id":      registrar_iana_id,
            "whois_server": registrar_whois,
            "reseller":     reseller,
        },
        "statuses":     statuses,
        "name_servers": name_servers,
        "dnssec":       dnssec,
        "contacts": {
            "registrant": registrant,
            "admin":      admin,
            "tech":       tech,
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Classify helper functions
# ════════════════════════════════════════════════════════════════════════════

def classify_ns(name_servers: list) -> str:
    """
    Categorise the name server set into one of several infrastructure types.

    The type drives which follow-on actions are recommended:
      parked       → monitor, not live yet
      cloudflare   → need bypass to find origin IP
      aws/azure    → check cloud misconfigs (S3, IAM, metadata service)
      shared-host  → shared IP, virtual host enum, cPanel default paths
      self-hosted  → attempt zone transfer, subdomain brute-force
      registrar-dns → basic setup, no customisation
      unknown      → investigate ASN

    We join all NS strings into one blob and search for substrings because
    NS values like "ns1.md-114.hostgatorwebservers.com" contain the provider
    name embedded within a longer string.
    """
    if not name_servers:
        return "none"

    ns_blob = " ".join(name_servers)

    if any(p in ns_blob for p in PARKED_NS_PATTERNS):
        return "parked"
    if any(p in ns_blob for p in CLOUDFLARE_NS_PATTERNS):
        return "cloudflare"
    for pattern, label in CLOUD_NS_PATTERNS.items():
        if pattern in ns_blob:
            return label
    if any(p in ns_blob for p in SHARED_HOSTING_NS_PATTERNS):
        return "shared-hosting"

    # Self-hosted: if any NS hostname is a subdomain of the target domain itself
    # e.g. ns1.google.com for google.com — they run their own DNS infrastructure
    # (We can't check this perfectly without the domain, but the analyzer passes
    #  the full parsed dict which includes the domain)
    return "self-hosted"


def classify_registrar(registrar: Optional[str]) -> str:
    """
    Classify registrar into enterprise / budget / unknown tier.

    Tier matters because budget registrar support teams are historically more
    susceptible to social engineering for unauthorised domain transfers.
    Enterprise registrars (MarkMonitor, CSC) use out-of-band verification
    that makes social engineering extremely difficult.
    """
    if not registrar:
        return "unknown"
    r = registrar.lower()
    if any(p in r for p in ENTERPRISE_REGISTRAR_PATTERNS):
        return "enterprise"
    if any(p in r for p in BUDGET_REGISTRAR_PATTERNS):
        return "budget"
    return "unknown"


def extract_server_cluster(name_servers: list) -> Optional[str]:
    """
    Detect embedded server cluster IDs in NS hostnames.

    HostGator and similar shared hosts embed a cluster identifier in their NS
    hostnames: "ns1.md-114.hostgatorwebservers.com"
                         ^^^^^^
    This "md-114" fingerprints the exact physical server cluster without
    sending a single packet to the target — passive infra enumeration.

    Regex matches patterns like: md-114, sv-23, us-east-42, box12
    """
    for ns in name_servers:
        match = re.search(r'([a-z]{1,6}-\d+|box\d+|srv\d+)\.', ns)
        if match:
            return match.group(1)
    return None


# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Risk Analyzer
#
# Reads the parsed dict, applies scoring rules, and returns a list of signals
# plus a numeric risk score (0–100) and a risk level label.
#
# Each signal is a dict:
#   { "field": str, "level": "HIGH|MEDIUM|LOW|INFO", "detail": str }
#
# Signals explain WHY the score is what it is — so when you get a false
# positive you can read the signal list and identify which rule fired.
# ════════════════════════════════════════════════════════════════════════════

def analyze(parsed: dict) -> dict:
    """
    Apply risk scoring rules to a parsed whois dict.

    Score is additive — each rule adds points. Score is capped at 100.
    Rules are ordered from most impactful to least so the signal list reads
    naturally top-to-bottom when printed.
    """
    signals  = []
    score    = 0

    # Unpack for readability — avoids parsed["dates"]["age_days"] everywhere
    age_days       = parsed["dates"]["age_days"]
    days_to_expiry = parsed["dates"]["days_to_expiry"]
    statuses       = parsed["statuses"]
    ns             = parsed["name_servers"]
    contacts       = parsed["contacts"]
    registrar_name = parsed["registrar"]["name"] or ""
    domain         = parsed["domain"]
    dnssec         = (parsed["dnssec"] or "").lower()

    def signal(field, level, detail):
        """Helper to append a signal and return the points to add."""
        signals.append({"field": field, "level": level, "detail": detail})

    # ── TLD check ──────────────────────────────────────────────────────────
    tld = "." + domain.rsplit(".", 1)[-1].lower()
    if tld in ABUSIVE_TLDS:
        signal("tld", "HIGH",
               f"TLD '{tld}' is statistically overrepresented in phishing/spam")
        score += 20

    # ── Domain age ─────────────────────────────────────────────────────────
    if age_days is None:
        signal("age", "MEDIUM", "Could not determine domain age — creation date missing or unparseable")
        score += 5
    elif age_days < 7:
        signal("age", "HIGH",
               f"Domain is {age_days} day(s) old — high probability of phishing/C2/squatting")
        score += 30
    elif age_days < 180:
        signal("age", "MEDIUM", f"Domain is {age_days} days old — monitor")
        score += 10
    else:
        signal("age", "INFO", f"Domain is {age_days} days old ({age_days // 365} years)")

    # ── Expiry window ──────────────────────────────────────────────────────
    if days_to_expiry is None:
        signal("expiry", "LOW", "Expiry date missing — could not assess takeover window")
    elif days_to_expiry < 0:
        signal("expiry", "HIGH",
               f"Domain EXPIRED {abs(days_to_expiry)} days ago — active takeover window")
        score += 25
    elif days_to_expiry < 30:
        signal("expiry", "HIGH",
               f"Domain expires in {days_to_expiry} days — monitor for takeover opportunity")
        score += 15
    elif days_to_expiry < 90:
        signal("expiry", "MEDIUM", f"Domain expires in {days_to_expiry} days")
        score += 5
    else:
        signal("expiry", "INFO", f"Domain expires in {days_to_expiry} days — stable")

    # ── EPP lifecycle states ───────────────────────────────────────────────
    # addPeriod is the most important one — domain is brand new
    if "addperiod" in statuses:
        signal("status", "HIGH",
               "addPeriod: domain registered within the last 5 days (ICANN grace period)")
        score += 20

    if "pendingdelete" in statuses:
        signal("status", "HIGH",
               "pendingDelete: domain will be deleted in ~5 days — monitor for re-registration")
        score += 20

    if "redemptionperiod" in statuses:
        signal("status", "MEDIUM",
               "redemptionPeriod: domain has expired, owner is in 30-day rescue window")
        score += 10

    if "serverhold" in statuses:
        signal("status", "INFO",
               "serverHold: registry has suspended DNS — domain does not resolve")
    if "clienthold" in statuses:
        signal("status", "INFO",
               "clientHold: registrar has suspended DNS — domain does not resolve")

    # ── Domain lock count ──────────────────────────────────────────────────
    lock_count = sum(1 for s in statuses if s in LOCK_EPP_CODES)
    if lock_count == 0:
        signal("locks", "HIGH",
               "No domain locks — transfer/update/delete all possible via registrar social engineering")
        score += 15
    elif lock_count < 3:
        signal("locks", "MEDIUM",
               f"Only {lock_count} lock(s) active — partial protection, gaps remain")
        score += 5
    elif lock_count >= 6:
        signal("locks", "INFO",
               f"All {lock_count} locks active — hijack/transfer not feasible via this vector")
    else:
        signal("locks", "INFO", f"{lock_count} domain lock(s) active")

    # ── Nameserver analysis ────────────────────────────────────────────────
    ns_type = classify_ns(ns)

    if ns_type == "parked":
        signal("nameserver", "MEDIUM",
               "Domain is parked — not live yet, monitor for when it becomes active")
        score += 10
    elif ns_type == "cloudflare":
        signal("nameserver", "INFO",
               "Behind Cloudflare — real origin IP is hidden, bypass techniques needed")
    elif ns_type == "shared-hosting":
        signal("nameserver", "MEDIUM",
               "Shared hosting NS — shared IP environment, virtual host enum and cPanel paths possible")
        score += 5
    elif ns_type == "self-hosted":
        signal("nameserver", "INFO",
               "Self-hosted DNS — attempt zone transfer (AXFR) and subdomain brute-force")
    elif ns_type in ("aws", "azure", "google-dns"):
        signal("nameserver", "INFO",
               f"Cloud-managed DNS ({ns_type}) — check for cloud misconfiguration (IAM, metadata service)")
    elif ns_type == "none":
        signal("nameserver", "MEDIUM", "No nameservers found — domain is inactive")
        score += 5

    # Server cluster fingerprint in NS hostname (e.g. md-114 in HostGator NS)
    cluster = extract_server_cluster(ns)
    if cluster:
        signal("nameserver", "INFO",
               f"Server cluster ID '{cluster}' fingerprinted from NS hostname — passive infra enumeration")

    # Nameserver consistency check — mismatched providers are suspicious
    # (two NS from different companies could expose origin behind a CDN)
    if len(ns) >= 2:
        # Extract the root domain of each NS (last two labels)
        def ns_root(hostname):
            parts = hostname.rstrip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        roots = {ns_root(n) for n in ns}
        if len(roots) > 1:
            signal("nameserver", "MEDIUM",
                   f"Mismatched NS providers detected: {roots} — one may expose real origin IP")
            score += 5

    # ── DNSSEC ────────────────────────────────────────────────────────────
    if not dnssec or "unsigned" in dnssec:
        signal("dnssec", "LOW",
               "DNSSEC unsigned — DNS responses not cryptographically verified, "
               "theoretically vulnerable to cache poisoning")
        score += 3

    # ── Registrar tier ────────────────────────────────────────────────────
    reg_tier = classify_registrar(registrar_name)
    if reg_tier == "budget":
        signal("registrar", "MEDIUM",
               f"Budget registrar ({registrar_name}) — support team more susceptible "
               f"to social engineering for unauthorised domain transfer")
        score += 5
    elif reg_tier == "enterprise":
        signal("registrar", "INFO",
               f"Enterprise registrar ({registrar_name}) — hardened support, hijack unlikely")
    else:
        signal("registrar", "LOW",
               f"Unknown registrar tier ({registrar_name}) — verify abuse response record")
        score += 3

    # Reseller flag — abuse report has to go through an extra layer
    if parsed["registrar"]["reseller"]:
        signal("registrar", "LOW",
               f"Registrar reseller detected: {parsed['registrar']['reseller']} — "
               f"abuse reports slower (goes through reseller before reaching registrar)")

    # ── Contact exposure ───────────────────────────────────────────────────
    reg = contacts["registrant"]
    exposed = {k: v for k, v in reg.items() if v}

    if exposed:
        # List which specific fields are visible — makes it easy to see
        # exactly what an attacker can harvest without running more tools
        exposed_keys = list(exposed.keys())
        signal("contacts", "INFO",
               f"Registrant fields publicly exposed: {', '.join(exposed_keys)}")

        # Physical address exposure — enables physical security assessment
        # and social engineering via physical presence
        if "address" in exposed or "city" in exposed:
            signal("contacts", "MEDIUM",
                   "Physical address exposed — enables physical social engineering")
            score += 5

        # Phone exposure — enables vishing and SIM swap social engineering
        if "phone" in exposed:
            signal("contacts", "MEDIUM",
                   f"Phone number exposed ({exposed.get('phone')}) — vishing / SIM swap vector")
            score += 5
    else:
        signal("contacts", "INFO", "Registrant contact info redacted (GDPR / privacy service)")

    # ── Personal email check (all three contact roles) ────────────────────
    for role in ["registrant", "admin", "tech"]:
        email = contacts[role].get("email")
        if email:
            domain_part = email.split("@")[-1].lower() if "@" in email else ""
            if domain_part in PERSONAL_EMAIL_DOMAINS:
                signal("contacts", "MEDIUM",
                       f"{role} email is personal ({email}) — no org-enforced MFA or email policy")
                score += 10

    # ── Single point of failure ───────────────────────────────────────────
    # Extract names and emails across all three roles, filtering out None
    all_names  = [contacts[r].get("name")  for r in ["registrant", "admin", "tech"]
                  if contacts[r].get("name")]
    all_emails = [contacts[r].get("email") for r in ["registrant", "admin", "tech"]
                  if contacts[r].get("email")]

    # If one person holds all three roles, compromising that one person
    # (via spear phishing) gives full control of domain registration
    if len(all_names) == 3 and len(set(all_names)) == 1:
        signal("contacts", "HIGH",
               f"Single point of failure: '{all_names[0]}' is registrant + admin + tech. "
               f"Compromising this one person = full domain control")
        score += 15
    elif len(all_emails) == 3 and len(set(all_emails)) == 1:
        signal("contacts", "HIGH",
               f"Single point of failure: same email ({all_emails[0]}) across all contact roles")
        score += 15

    # ── Final risk level ──────────────────────────────────────────────────
    score = min(score, 100)  # cap at 100

    if score >= RISK_HIGH_THRESHOLD:
        risk_level = "HIGH"
    elif score >= RISK_MEDIUM_THRESHOLD:
        risk_level = "MEDIUM"
    elif score >= RISK_LOW_THRESHOLD:
        risk_level = "LOW"
    else:
        risk_level = "INFO"

    return {
        "risk_score":     score,
        "risk_level":     risk_level,
        "ns_type":        ns_type,
        "registrar_tier": reg_tier,
        "signals":        signals,
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — Terminal Printer
# ════════════════════════════════════════════════════════════════════════════

# ANSI colour codes — used to make risk levels visually distinct in terminal.
# Falls back to plain text if output is piped (stdout is not a TTY).
COLOURS = {
    "HIGH":   "\033[91m",  # bright red
    "MEDIUM": "\033[93m",  # bright yellow
    "LOW":    "\033[94m",  # bright blue
    "INFO":   "\033[92m",  # bright green
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
}

def c(level_or_key: str, text: str) -> str:
    """Apply ANSI colour to text if stdout is a terminal, otherwise return plain."""
    if not sys.stdout.isatty():
        return text
    colour = COLOURS.get(level_or_key, "")
    return f"{colour}{text}{COLOURS['RESET']}"


def print_result(result: dict):
    """
    Print a human-readable summary to stdout.

    Layout:
      Header  — domain + risk score
      Dates   — age, updated, expiry
      Infra   — registrar, NS, DNSSEC, statuses
      Contacts — exposed registrant fields
      Signals — every fired rule with level and detail
      Pivots  — suggested next commands based on findings
    """
    p = result["parsed"]
    a = result["analysis"]
    ns_type   = a["ns_type"]
    risk_lvl  = a["risk_level"]
    risk_score = a["risk_score"]

    sep = "═" * 65

    print(f"\n{c('BOLD', sep)}")
    print(f"  {c('BOLD', 'WHOIS Analysis')}  →  {c('BOLD', p['domain'])}")
    print(f"  Risk : {c(risk_lvl, f'{risk_score}/100  [{risk_lvl}]')}")
    if result.get("cached"):
        print(f"  {c('DIM', '[cached]')}  queried_at: {result.get('queried_at', 'N/A')}")
    print(sep)

    # ── Dates ──────────────────────────────────────────────────────────────
    d = p["dates"]
    age_label = f"{d['age_days']} days" if d["age_days"] is not None else "unknown"
    exp_label = f"in {d['days_to_expiry']} days" if d["days_to_expiry"] is not None else "unknown"
    print(f"\n  {c('BOLD', 'Dates')}")
    print(f"    Created  : {d['creation'] or 'N/A'}  ({age_label} ago)")
    print(f"    Updated  : {d['updated']  or 'N/A'}")
    print(f"    Expires  : {d['expiry']   or 'N/A'}  ({exp_label})")

    # ── Infrastructure ─────────────────────────────────────────────────────
    r = p["registrar"]
    print(f"\n  {c('BOLD', 'Infrastructure')}")
    print(f"    Registrar  : {r['name'] or 'N/A'}  [{a['registrar_tier']}]")
    print(f"    IANA ID    : {r['iana_id'] or 'N/A'}")
    print(f"    Reseller   : {r['reseller'] or 'none'}")
    print(f"    NS Type    : {ns_type}")
    print(f"    Nameservers: {', '.join(p['name_servers']) or 'none'}")
    print(f"    DNSSEC     : {p['dnssec'] or 'N/A'}")
    print(f"    Statuses   : {', '.join(p['statuses']) or 'none'}")

    # ── Contacts ───────────────────────────────────────────────────────────
    reg = p["contacts"]["registrant"]
    exposed = {k: v for k, v in reg.items() if v}
    print(f"\n  {c('BOLD', 'Registrant')}  ({'exposed' if exposed else 'redacted'})")
    if exposed:
        for k, v in exposed.items():
            print(f"    {k:10}: {v}")
    else:
        print(f"    {c('DIM', '(all fields redacted — GDPR or privacy service)')}")

    # ── Signals ────────────────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'Signals')}  ({len(a['signals'])} total)")
    for s in a["signals"]:
        level_tag = f"[{s['level']:6}]"
        print(f"    {c(s['level'], level_tag)}  {s['field']:12}  {s['detail']}")

    # ── Suggested pivots ───────────────────────────────────────────────────
    # Dynamically generate follow-on commands based on what we found —
    # so the output reads like a mini action plan, not just raw data
    print(f"\n  {c('BOLD', 'Suggested Next Steps')}")
    pivots = []

    if ns_type == "self-hosted":
        ns0 = p["name_servers"][0] if p["name_servers"] else "<ns>"
        pivots.append(f"dig AXFR {p['domain']} @{ns0}   # zone transfer attempt")
        pivots.append(f"subfinder -d {p['domain']}       # passive subdomain enum")

    if ns_type == "cloudflare":
        pivots.append(f"# Bypass Cloudflare: check Shodan/Censys for direct IP with same cert")
        pivots.append(f"dig mail.{p['domain']}            # MX may bypass Cloudflare")

    if ns_type == "shared-hosting":
        pivots.append(f"dig {p['domain']}                 # get shared IP")
        pivots.append(f"gobuster vhost -u http://<IP> -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt")
        pivots.append(f"curl -I https://{p['domain']}     # server banner + headers")

    if ns_type == "parked":
        pivots.append(f"# Domain not live yet — monitor with SecurityTrails alerts")

    reg_email = p["contacts"]["registrant"].get("email")
    if reg_email:
        pivots.append(f"theHarvester -d {p['domain']} -b all")
        pivots.append(f"# Check breach: https://haveibeenpwned.com/  →  {reg_email}")

    reg_name = p["contacts"]["registrant"].get("name")
    if reg_name:
        pivots.append(f"# LinkedIn: search '{reg_name}'")
        pivots.append(f"# Reverse WHOIS: amass intel -whois -d {p['domain']}")

    if not pivots:
        pivots.append(f"subfinder -d {p['domain']}       # passive subdomain enum")
        pivots.append(f"theHarvester -d {p['domain']} -b all")

    for pv in pivots:
        print(f"    {c('DIM', pv)}")

    print()


# ════════════════════════════════════════════════════════════════════════════
# STEP 6 — Orchestrator (single domain)
# ════════════════════════════════════════════════════════════════════════════

def run(domain: str, no_cache: bool, ttl_hours: int,
        output_path: Optional[str]) -> dict:
    """
    Full pipeline for one domain:
      [cache check] → fetch → parse → analyze → print → cache_write [→ --output]

    Cache behaviour:
      - If no_cache is False and a valid cache entry exists: return cached result
      - Otherwise: fetch fresh, run full pipeline, write to cache

    Returns the result dict (always includes "cached": bool and "queried_at").
    Returns empty dict on failure (e.g. whois timeout) — callers skip gracefully.
    """
    print(f"\n[*] Querying whois for: {c('BOLD', domain)}")

    # ── Cache check ────────────────────────────────────────────────────────
    if not no_cache:
        cached = cache_read(domain, ttl_hours)
        if cached is not None:
            print(f"[*] Cache hit (TTL={ttl_hours}h) — using cached result")
            cached["cached"] = True
            print_result(cached)
            if output_path:
                Path(output_path).write_text(
                    json.dumps(cached, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                print(f"[*] JSON written → {output_path}")
            return cached

    # ── Fresh fetch ────────────────────────────────────────────────────────
    raw = fetch_raw(domain)

    if not raw.strip():
        print(f"[!]  No whois response for {domain} — skipping")
        return {}

    parsed   = parse_whois(raw, domain)
    analysis = analyze(parsed)

    queried_at = datetime.now(timezone.utc).isoformat()

    result = {
        "domain":     domain,
        "queried_at": queried_at,
        "cached":     False,
        "parsed":     parsed,
        "analysis":   analysis,
    }

    print_result(result)

    # ── Write to cache ─────────────────────────────────────────────────────
    cache_write(domain, result)
    print(f"[*] Cached → {CACHE_DB}")

    # ── Optional JSON output ───────────────────────────────────────────────
    if output_path:
        Path(output_path).write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"[*] JSON written → {output_path}")

    return result


# ════════════════════════════════════════════════════════════════════════════
# STEP 7 — CLI Entry Point
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="WHOIS Extractor — parse, score, and cache recon findings for a single domain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 whois-extracter.py -d nmap.org
  python3 whois-extracter.py -d nmap.org -o results.json
  python3 whois-extracter.py -d nmap.org --no-cache
  python3 whois-extracter.py -d nmap.org --ttl 6
        """
    )

    parser.add_argument(
        "-d", "--domain", required=True, metavar="DOMAIN",
        help="Domain name to query (no https://, no trailing slash)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Write full JSON result to this file path (optional)"
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass cache read — always fetch fresh (result is still written to cache)"
    )
    parser.add_argument(
        "--ttl", type=int, default=24, metavar="HOURS",
        help="Cache TTL in hours (default: 24)"
    )

    args = parser.parse_args()

    domain = args.domain.strip().lower()

    # Strip accidental protocol prefix — common mistake
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/")[0]
        print(f"[*] Stripped protocol prefix → querying: {domain}")

    run(domain, no_cache=args.no_cache, ttl_hours=args.ttl,
        output_path=args.output)


if __name__ == "__main__":
    main()
