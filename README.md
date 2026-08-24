# Web Application Security Checklist Tool v1.0

An automated scanner for defensive security configuration audits in web applications, mapped to OWASP Top 10 (2021).

**Author:** Dhaval  
**Project:** CIOSE Capstone Project (VAPT Track)  
**Version:** 1.0  

---

## Problem Statement

During VAPT engagements, defensive configuration checks are repetitive and manual — missing security headers, weak cookies, exposed files, permissive CORS. This tool automates the first-pass audit so testers can focus on manual exploitation.

---

## Features

| # | Check | Detects |
|---|-------|---------|
| 1 | Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 2 | Cookie Flags | Missing Secure, HttpOnly, SameSite attributes |
| 3 | SSL/TLS | Weak protocols (TLS 1.0/1.1), certificate expiry |
| 4 | Info Disclosure | Server, X-Powered-By, X-AspNet-Version headers |
| 5 | Clickjacking | X-Frame-Options (DENY/SAMEORIGIN) + CSP frame-ancestors |
| 6 | File Exposure | .git/HEAD, .env, backups, .htaccess, phpinfo.php |
| 7 | CORS Misconfiguration | Wildcard (*) or reflected-origin issues |

**v1.0 Features:**
- **Risk Score** — weighted severity (High=10, Medium=5, Low=1) rolled into MINIMAL/LOW/MEDIUM/HIGH rating
- **Colored output** via colorama (auto-fallback if missing)
- **Authenticated scanning** via --cookie flag
- **Clean error handling** — early exit on unreachable targets
- **HTML + JSON reports** — color-coded, OWASP-mapped

---

## Installation

**Option A — System Command (Recommended)**
```bash
sudo apt install ./security-checklist-tool_1.0-1.deb
security-checklist -u https://target.com
```

**Option B — From Source**
```bash
git clone <repo-url>
cd security-checklist-tool
pip install requests colorama --break-system-packages
python3 security_checklist.py -u https://target.com
```

Tested on Kali Linux, Python 3.11+.

---

## Usage

```bash
# Basic scan
security-checklist -u https://target.com

# With HTML report
security-checklist -u https://target.com --html report.html

# With JSON report
security-checklist -u https://target.com --json report.json

# Authenticated scan
security-checklist -u https://target.com --cookie "PHPSESSID=abc123"
```

**Arguments:**
- `-u, --url` (required) — Target URL
- `--html` — Save HTML report
- `--json` — Save JSON report
- `--cookie` — Session cookie for authenticated scans
- `--timeout` — Request timeout (default: 10s)

---

## Architecture

```
security_checklist.py
├── check_headers()
├── check_cookies()
├── check_ssl()
├── check_info()
├── check_clickjack()
├── check_files()
├── check_cors()
├── risk_score()
└── print_report() / html_report()
```

Single `results` list drives console, HTML, JSON — always in sync.

---

## Limitations

- **Passive tool** — no SQLi, XSS, exploitation
- **Fixed path list** — not full brute-force (use Gobuster/DIRB)
- **CORS** — basic reflected-origin/wildcard only
- **Scope** — only use on systems you own or have written authorization to test

