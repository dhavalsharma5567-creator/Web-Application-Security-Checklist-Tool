# Web Application Security Checklist Tool — Demo Walkthrough Script

A step-by-step walkthrough script for demonstrating the **Web Application Security Checklist Tool v1.0**.

---

## 1. Introduction & Overview

>"This is the **Web Application Security Checklist Tool v1.0**, an automated defensive configuration scanner designed to identify common security misconfigurations mapped directly to the **OWASP Top 10 (2021)**.
>
>During web application penetration testing or baseline audits, a significant portion of findings stem from defensive gaps—missing HTTP security headers, insecure cookie flags, banner leakage, permissive CORS policies, and exposed sensitive files. This tool automates this entire first-pass audit into a single command, producing categorized terminal output, calculated risk ratings, and exportable reports."

---

## 2. Target Setup (Environment Initialization)

> "To demonstrate the tool in action, we launch a locally hosted instance of **DVWA (Damn Vulnerable Web Application)** running inside a Docker container on port 80."

```bash
# Spin up the target test environment
sudo systemctl start docker
sudo systemctl enable docker
sudo systemctl status docker
sudo docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
```

---

## 3. Tool Execution

> "We execute the Python scanner targeting the local instance (`http://localhost`), simultaneously instructing it to export structured reports in both HTML and JSON formats."

```bash
# Execute scanner with HTML and JSON reporting flags
python3 security_checklist.py -u http://localhost --html reports/report_dvwa.html --json reports/report_dvwa.json
```

---

## 4. Analysis of Scan Results

### A. HTTP Security Headers (OWASP A05:2021)
> "The tool evaluates essential hardening headers. Against DVWA, the following are flagged as **FAIL (Medium Severity)**:
> - **Content-Security-Policy (CSP):** Missing (Leaves application open to Cross-Site Scripting / data injection).
> - **X-Frame-Options:** Missing (Lacks legacy clickjacking defense).
> - **Strict-Transport-Security (HSTS):** Missing (No HTTPS enforcement).
> - **X-Content-Type-Options:** Missing (MIME-sniffing prevention disabled).
> - **Referrer-Policy:** Missing (Risk of leaking sensitive URLs/tokens).
> - **Permissions-Policy:** Missing (No browser feature restrictions)."

### B. Information Disclosure & Banner Leakage
> "The scanner checks response headers for backend technological fingerprints:
> - **Server:** `FAIL` — Leaks exact version `Apache/2.4.25 (Debian)`.
> - **X-Powered-By / X-AspNet-Version / X-Generator:** `PASS` — Not disclosed."

### C. Clickjacking Defense
> "The tool performs logic validation on frame defenses:
> - **Clickjacking:** `FAIL` — Neither `X-Frame-Options` (`DENY`/`SAMEORIGIN`) nor CSP `frame-ancestors` directive is implemented."

### D. Sensitive File Probing & CORS Policy
> "The scanner performs lightweight, passive verification against sensitive files and cross-origin resource sharing:
> - **CORS:** `PASS` — Standard same-origin policy is enforced (no wildcard `*` or reflected origins).
> - **Sensitive Files (`.git/HEAD`, `.env`):** `PASS` — Inaccessible (returns HTTP 404).
> - **robots.txt:** `INFO` — Present as expected (logged purely as informational context)."

---

## 5. Risk Scoring & Output Deliverables

> "Upon scan completion, the tool calculates a weighted overall risk score based on the identified vulnerabilities:
> - **Overall Risk Rating:** `MEDIUM` (Weighted Score: 40)
> - **Finding Summary:** 0 High | 7 Medium | 1 Low | 2 Informational
>
> The results are immediately available in two standardized formats:
> 1. **`reports/report_dvwa.html`**: A formatted, client-ready summary table with visual severity badges.
> 2. **`reports/report_dvwa.json`**: Machine-readable JSON output suitable for automated CI/CD pipelines or SIEM ingestion."

---

