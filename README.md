# whois-extracter

Parse WHOIS records, score domain hijack risk, and detect infrastructure exposure. Zero pip deps — pure Python stdlib.

---

## Install

```bash
git clone https://github.com/fmfalgun/whois-extracter.git
cd whois-extracter
```

Install the system `whois` binary:

```bash
# Ubuntu/Debian
sudo apt install whois

# macOS
brew install whois

# Arch
sudo pacman -S whois
```

No `pip install` needed. Python 3.8+ stdlib only.

---

## Usage

```bash
python3 whois-extracter.py -d nmap.org
python3 whois-extracter.py -d nmap.org -o results.json
python3 whois-extracter.py -d nmap.org --no-cache
python3 whois-extracter.py -d nmap.org --ttl 6
```

| Flag | Description |
|------|-------------|
| `-d / --domain` | Target domain (required) |
| `-o / --output` | Write JSON result to file |
| `--no-cache` | Bypass cache, always fetch fresh WHOIS data |
| `--ttl N` | Cache TTL in hours (default: 24) |

---

## Output

Results are printed to stdout with colour-coded risk levels. Pass `--output results.json` to also write the full structured result to a JSON file.

Cache is stored in `./cache.db` (SQLite, auto-created on first run, ignored by git). Repeated lookups within the TTL window are served from cache without hitting the WHOIS server.

---

## Risk Scoring

| Level | Score | Meaning |
|-------|-------|---------|
| HIGH | >= 60 | Active threat signal — domain age < 7d, expired, no locks, personal email |
| MEDIUM | >= 30 | Elevated risk — shared hosting, budget registrar, expiring < 90d |
| LOW | >= 10 | Minor risk — DNSSEC unsigned, unknown registrar |
| INFO | < 10 | Clean signal — established domain, enterprise registrar |

Signals are additive. Each risk factor contributes a weighted score; the final level is determined by the total.

---

## Output Schema

```json
{
  "domain": "nmap.org",
  "queried_at": "2026-06-21T02:00:00Z",
  "cached": false,
  "parsed": {
    "dates": { "creation": "1999-08-26", "age_days": 9797, "days_to_expiry": 430 },
    "registrar": { "name": "Network Solutions, LLC", "iana_id": "2" },
    "statuses": ["clienttransferprohibited"],
    "name_servers": ["ns1.seclists.org", "ns2.seclists.org"],
    "dnssec": "unsigned"
  },
  "analysis": {
    "risk_score": 8,
    "risk_level": "INFO",
    "ns_type": "self-hosted",
    "registrar_tier": "enterprise",
    "signals": [
      { "field": "age", "level": "INFO", "detail": "Domain is 9797 days old (26 years)" }
    ]
  }
}
```

---

## Live Demo

[https://fmfalgun.github.io/whois-extracter](https://fmfalgun.github.io/whois-extracter)

---

## License

MIT
