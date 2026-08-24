#!/usr/bin/env python3
"""
Web Application Security Checklist Tool v1.0
Automated defensive configuration scanner for web applications.
Author: Dhaval | CIOSE Capstone Project
"""

import argparse, socket, ssl, sys, json
from datetime import datetime
from urllib.parse import urlparse
import requests
requests.packages.urllib3.disable_warnings()

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = {"PASS": Fore.GREEN, "FAIL": Fore.RED, "WARN": Fore.YELLOW, "INFO": Fore.CYAN, "ERROR": Fore.MAGENTA, "RESET": Style.RESET_ALL}
    HAS_COLOR = True
except ImportError:
    COLOR = {k: "" for k in ("PASS", "FAIL", "WARN", "INFO", "ERROR", "RESET")}
    HAS_COLOR = False

results = []

def add_result(check, status, detail, severity, owasp):
    results.append({"check": check, "status": status, "detail": detail, "severity": severity, "owasp_ref": owasp})

def banner():
    print("=" * 60)
    print("  WEB APPLICATION SECURITY CHECKLIST TOOL v1.0")
    print("  Automated Defensive Configuration Scanner")
    print("=" * 60)

def check_headers(url, headers):
    required = {"Content-Security-Policy": "XSS mitigation", "X-Frame-Options": "Clickjacking protection", 
                "Strict-Transport-Security": "HTTPS enforcement", "X-Content-Type-Options": "MIME sniffing prevention",
                "Referrer-Policy": "Referrer leakage control", "Permissions-Policy": "Browser feature restriction"}
    for h, p in required.items():
        if h in headers:
            add_result(f"Header: {h}", "PASS", f"Present -> {headers[h][:80]}", "Low", "OWASP A05:2021")
        else:
            add_result(f"Header: {h}", "FAIL", f"Missing. Purpose: {p}", "Medium", "OWASP A05:2021")

def check_cookies(resp):
    if resp is None or not resp.cookies:
        add_result("Cookie Flags", "INFO", "No cookies set", "Info", "N/A")
        return
    for c in resp.cookies:
        missing = []
        if not c.secure: missing.append("Secure")
        if not c.has_nonstandard_attr("HttpOnly"): missing.append("HttpOnly")
        if not c.has_nonstandard_attr("SameSite"): missing.append("SameSite")
        if missing:
            add_result(f"Cookie: {c.name}", "FAIL", f"Missing: {', '.join(missing)}", "Medium", "OWASP A05:2021")
        else:
            add_result(f"Cookie: {c.name}", "PASS", "All flags present", "Low", "OWASP A05:2021")

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert, proto = ssock.getpeercert(), ssock.version()
                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days = (expiry - datetime.now()).days
                add_result("TLS Version", "FAIL" if proto in ("TLSv1", "TLSv1.1") else "PASS",
                          f"Weak protocol: {proto}" if proto in ("TLSv1", "TLSv1.1") else f"Secure: {proto}",
                          "High" if proto in ("TLSv1", "TLSv1.1") else "Low", "OWASP A02:2021")
                add_result("Certificate Expiry", "WARN" if days < 15 else "PASS",
                          f"Expires in {days} days" if days < 15 else f"Valid {days} days", "Medium" if days < 15 else "Low", "OWASP A02:2021")
    except: add_result("SSL/TLS", "ERROR", "TLS check failed", "Info", "N/A")

def check_info(headers):
    for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if h in headers:
            add_result(f"Info: {h}", "FAIL", f"Reveals: {headers[h]}", "Low", "OWASP A05:2021")
        else:
            add_result(f"Info: {h}", "PASS", "Not disclosed", "Low", "OWASP A05:2021")

def check_clickjack(url, headers, session):
    xfo, csp = headers.get("X-Frame-Options", ""), headers.get("Content-Security-Policy", "")
    if xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower():
        add_result("Clickjacking", "PASS", f"Protected via {xfo if xfo else 'CSP'}", "Low", "OWASP A05:2021")
    else:
        add_result("Clickjacking", "FAIL", "No X-Frame-Options or CSP frame-ancestors", "Medium", "OWASP A05:2021")

def check_files(url, session):
    for path in ["/robots.txt", "/.git/HEAD", "/.env", "/backup.zip", "/config.php.bak", "/.htaccess", "/phpinfo.php"]:
        try:
            r = session.get(url.rstrip("/") + path, timeout=6, verify=False, allow_redirects=False)
            if path == "/robots.txt":
                add_result("robots.txt", "INFO", f"HTTP {r.status_code}" if r.status_code != 200 else "Present (expected)", "Info", "N/A")
            else:
                add_result(f"Exposed: {path}", "FAIL" if r.status_code == 200 else "PASS", 
                          f"Accessible HTTP {r.status_code}" if r.status_code == 200 else f"Not accessible HTTP {r.status_code}",
                          "High" if r.status_code == 200 else "Low", "OWASP A01:2021")
        except: pass

def check_cors(url, session):
    try:
        r = session.get(url, headers={"Origin": "https://evil.com"}, timeout=10, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin")
        if acao == "*":
            add_result("CORS", "FAIL", "Wildcard (*) allows any origin", "High", "OWASP A05:2021")
        elif acao == "https://evil.com":
            add_result("CORS", "FAIL", "Reflects arbitrary origin", "High", "OWASP A05:2021")
        elif acao:
            add_result("CORS", "PASS", f"Restricted to {acao}", "Low", "OWASP A05:2021")
        else:
            add_result("CORS", "PASS", "Default same-origin policy", "Low", "OWASP A05:2021")
    except: add_result("CORS", "ERROR", "Check failed", "Info", "N/A")

def risk_score():
    fails = [r for r in results if r["status"] == "FAIL"]
    score = sum({"High": 10, "Medium": 5, "Low": 1, "Info": 0}.get(r["severity"], 0) for r in fails)
    h = len([r for r in fails if r["severity"] == "High"])
    m = len([r for r in fails if r["severity"] == "Medium"])
    l = len([r for r in fails if r["severity"] == "Low"])
    rating = "HIGH" if h > 0 else "MEDIUM" if m >= 3 else "LOW" if m > 0 or l > 0 else "MINIMAL"
    return {"score": score, "rating": rating, "high": h, "medium": m, "low": l}

def print_report():
    print("\n" + "=" * 60 + "\n  SCAN RESULTS\n" + "=" * 60)
    for r in results:
        symbol = {"PASS": "[+]", "FAIL": "[-]", "WARN": "[!]", "INFO": "[i]", "ERROR": "[x]"}.get(r["status"], "[?]")
        color = COLOR.get(r["status"], "")
        print(f"{color}{symbol} {r['check']:<35} {r['status']:<6} {r['severity']}{COLOR['RESET']}")
        print(f"      -> {r['detail']}")
    risk = risk_score()
    total, failed, passed = len(results), len([r for r in results if r["status"] == "FAIL"]), len([r for r in results if r["status"] == "PASS"])
    print("\n" + "-" * 60)
    print(f"  Total: {total} | Failed: {failed} | Passed: {passed}")
    print(f"  Overall Risk: {risk['rating']} (score: {risk['score']}) | High: {risk['high']} Medium: {risk['medium']} Low: {risk['low']}")
    print("-" * 60)

def html_report(url, filepath):
    risk = risk_score()
    color_map = {"PASS": "#2e7d32", "FAIL": "#c62828", "WARN": "#f9a825", "INFO": "#1565c0"}
    rows = ""
    for r in results:
        color = color_map.get(r["status"], "#000")
        rows += f"<tr><td>{r['check']}</td><td style='color:{color}'>{r['status']}</td><td>{r['severity']}</td><td>{r['detail']}</td><td>{r['owasp_ref']}</td></tr>"
    
    risk_color = {"HIGH": "#c62828", "MEDIUM": "#f9a825", "LOW": "#1565c0", "MINIMAL": "#2e7d32"}.get(risk["rating"], "#000")
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Report</title><style>body{{font-family:Arial;margin:40px;background:#f4f6f8}}h1{{color:#1a237e}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;font-size:13px}}th{{background:#1a237e;color:white}}tr:nth-child(even){{background:#f2f2f2}}.risk-box{{padding:14px;border-radius:8px;color:white;background:{risk_color};font-size:20px;font-weight:bold;margin-bottom:20px}}</style></head><body><h1>Security Checklist Report</h1><p><b>Target:</b> {url}</p><p><b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p><div class="risk-box">Risk: {risk['rating']} (score: {risk['score']})</div><p>Total: {len(results)} | Failed: {len([r for r in results if r['status']=='FAIL'])} | High: {risk['high']} Medium: {risk['medium']}</p><table><tr><th>Check</th><th>Status</th><th>Severity</th><th>Detail</th><th>OWASP</th></tr>{rows}</table></body></html>"""
    with open(filepath, "w") as f: f.write(html)
    print(f"\n[+] HTML saved: {filepath}")

def main():
    parser = argparse.ArgumentParser(description="Web Application Security Checklist v1.0")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--html", help="HTML report path")
    parser.add_argument("--json", help="JSON report path")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    
    url = args.url if args.url.startswith("http") else "https://" + args.url
    hostname = urlparse(url).hostname
    
    banner()
    print(f"[*] Target: {url}\n[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    session = requests.Session()
    if args.cookie:
        for part in args.cookie.split(";"): 
            if "=" in part: k, v = part.strip().split("=", 1); session.cookies.set(k, v)
    
    try:
        resp = session.get(url, timeout=args.timeout, verify=False)
        headers = resp.headers
    except:
        print(f"{COLOR['FAIL']}[x] Cannot reach target. Aborting.{COLOR['RESET']}"); sys.exit(1)
    
    check_headers(url, headers)
    check_cookies(resp)
    check_info(headers)
    check_clickjack(url, headers, session)
    check_cors(url, session)
    check_files(url, session)
    if url.startswith("https"): check_ssl(hostname)
    else: add_result("SSL/TLS", "INFO", "Not HTTPS, skipping", "Medium", "OWASP A02:2021")
    
    print_report()
    if args.html: html_report(url, args.html)
    if args.json:
        with open(args.json, "w") as f: json.dump(results, f, indent=2)
        print(f"[+] JSON saved: {args.json}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Interrupted."); sys.exit(1)
