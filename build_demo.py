#!/usr/bin/env python3
"""
build_demo.py — run whois-extracter against nmap.org and write web/data/demo.json
Called by .github/workflows/build-demo.yml on a daily cron schedule.
"""

import subprocess
import sys
import json
from pathlib import Path

DOMAIN  = "nmap.org"
OUTPUT  = Path("web/data/demo.json")
SCRIPT  = Path("whois-extracter.py")

def main():
    print(f"[*] Running whois-extracter on {DOMAIN} ...")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "-d", DOMAIN, "-o", str(OUTPUT), "--no-cache"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[!] Script failed:\n{result.stderr}")
        sys.exit(1)

    if not OUTPUT.exists():
        print(f"[!] Output file not created: {OUTPUT}")
        sys.exit(1)

    try:
        data = json.loads(OUTPUT.read_text())
    except json.JSONDecodeError as e:
        print(f"[!] Output is not valid JSON: {e}")
        sys.exit(1)

    risk = data.get("analysis", {}).get("risk_level", "?")
    score = data.get("analysis", {}).get("risk_score", "?")
    signals = len(data.get("analysis", {}).get("signals", []))
    print(f"[+] demo.json written: risk={risk} ({score}/100), {signals} signals")

if __name__ == "__main__":
    main()
