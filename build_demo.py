#!/usr/bin/env python3
"""
build_demo.py — run whois-extracter against nmap.org and write:
  - web/data/demo.json               (for demo.html)
  - web/data/domains/nmap.org.json   (for risk-board + domain.html, adds display metadata)
  - web/data/index.json              (risk board registry)
Called by .github/workflows/build-demo.yml on a daily cron schedule.
"""

import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

DOMAIN       = "nmap.org"
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"
SCRIPT       = Path("whois-extracter.py")
DEMO_OUT     = Path("web/data/demo.json")
DOMAIN_OUT   = Path(f"web/data/domains/{DOMAIN}.json")
INDEX_OUT    = Path("web/data/index.json")


def run_script():
    print(f"[*] Running whois-extracter on {DOMAIN} ...")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "-d", DOMAIN, "-o", str(DEMO_OUT), "--no-cache"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[!] Script failed:\n{result.stderr}")
        sys.exit(1)
    if not DEMO_OUT.exists():
        print(f"[!] Output file not created: {DEMO_OUT}")
        sys.exit(1)
    return json.loads(DEMO_OUT.read_text())


def write_domain_file(data: dict):
    """Write domains/nmap.org.json with display metadata added."""
    DOMAIN_OUT.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    enriched = dict(data)
    enriched["display_name"]   = DISPLAY_NAME
    enriched["display_loc"]    = DISPLAY_LOC
    enriched["last_refreshed"] = now
    DOMAIN_OUT.write_text(json.dumps(enriched, indent=2))
    print(f"[+] Written: {DOMAIN_OUT}")
    return enriched


def update_index(data: dict):
    """Update web/data/index.json with nmap.org entry."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if INDEX_OUT.exists():
        try:
            index = json.loads(INDEX_OUT.read_text())
        except Exception:
            index = {}
    else:
        index = {}

    index.setdefault("total_domains", 0)
    index.setdefault("total_scans", 0)
    index.setdefault("domains", [])

    analysis = data.get("analysis", {})
    parsed   = data.get("parsed", {})
    entry = {
        "domain":         DOMAIN,
        "display_name":   DISPLAY_NAME,
        "display_loc":    DISPLAY_LOC,
        "queried_at":     data.get("queried_at", now),
        "last_refreshed": now,
        "risk_score":     analysis.get("risk_score", 0),
        "risk_level":     analysis.get("risk_level", "INFO"),
        "signals_count":  len(analysis.get("signals", [])),
        "ns_type":        analysis.get("ns_type", ""),
        "registrar_tier": analysis.get("registrar_tier", ""),
        "age_days":       parsed.get("dates", {}).get("age_days", 0),
    }

    domains = [d for d in index["domains"] if d["domain"] != DOMAIN]
    domains.append(entry)
    domains.sort(key=lambda x: x["domain"])

    index["domains"]       = domains
    index["total_domains"] = len(domains)
    index["total_scans"]   = len(domains)
    index["generated_at"]  = now

    INDEX_OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] Updated: {INDEX_OUT} ({len(domains)} domains)")


def main():
    data = run_script()

    risk  = data.get("analysis", {}).get("risk_level", "?")
    score = data.get("analysis", {}).get("risk_score", "?")
    sigs  = len(data.get("analysis", {}).get("signals", []))
    print(f"[+] demo.json written: risk={risk} ({score}/100), {sigs} signals")

    write_domain_file(data)
    update_index(data)
    print("[+] build_demo.py complete")


if __name__ == "__main__":
    main()
