# 🔒 CyberRecon v5.0 — Complete Security Suite

Full integration of Desktop App + Web App with:
- OWASP Top 10 (2025) Vulnerability Scanner
- Working Nmap Port Scanner
- HTTP/DNS/WHOIS/IP Reconnaissance
- HTML Report Export

---

## 📁 Folder Structure

```
CyberRecon_Final/
├── cyber_recon_desktop.py   ← Desktop GUI (tkinter) — run directly
├── app.py                   ← Web backend (Flask)
├── requirements.txt         ← Python dependencies
├── README.md
└── templates/
    └── index.html           ← Web frontend
```

---

## 🖥️ Option 1 — Desktop App (cyber_recon_desktop.py)

### Install
```bash
pip install -r requirements.txt
```

### Run
```bash
python cyber_recon_desktop.py
```

### Desktop Features
- 🔍 Scanner tab — HTTP recon, DNS, WHOIS, IP intel
- 🛡️ OWASP 2025 tab — standalone vuln scanner with live output
- 🗺️ Network/Nmap tab — dedicated Nmap scanner (TCP/SYN/UDP/Version)
- 🌐 Intelligence tab — IP geolocation with info cards
- 📊 Reports tab — preview & export HTML report
- Checkboxes to include/exclude OWASP scan and Nmap from main scan

---

## 🌐 Option 2 — Web App (app.py + templates/index.html)

### Install
```bash
pip install -r requirements.txt
```

### Run
```bash
python app.py
```

### Open
```
http://localhost:5000
```

Sign up → Log in → Scan

### Deploy Free Online
**Render.com** (recommended):
1. Push to GitHub
2. render.com → New Web Service → connect repo
3. Build: `pip install -r requirements.txt`
4. Start: `gunicorn app:app`
5. Add env var: `SECRET_KEY=your-random-secret`

---

## 🗺️ Nmap Setup (Required for port scanning)

| OS      | Command                              |
|---------|--------------------------------------|
| Windows | Download: https://nmap.org/download.html |
| Linux   | `sudo apt install nmap`              |
| macOS   | `brew install nmap`                  |

Then: `pip install python-nmap`

> **Note:** SYN scan (-sS) requires admin/root. Use TCP Connect for normal users.

---

## ⬡ OWASP Top 10 (2025) Coverage

| ID       | Category                          | Tests |
|----------|-----------------------------------|-------|
| A01:2025 | Broken Access Control             | Admin panels, dir listing, CSRF, IDOR, verb tampering |
| A02:2025 | Cryptographic Failures            | SSL/TLS, ciphers, HTTPS redirect, cookies |
| A03:2025 | Injection                         | SQLi, XSS, SSTI, Command, NoSQL |
| A04:2025 | Insecure Design                   | Stack traces, debug mode, rate limiting |
| A05:2025 | Security Misconfiguration         | Headers, CORS, TRACE, sensitive files |
| A06:2025 | Vulnerable & Outdated Components  | CVE signatures, jQuery/CMS versions |
| A07:2025 | Auth & ID Failures                | Default creds, session cookies, tokens |
| A08:2025 | Software Integrity Failures       | SRI, deserialization, CI/CD configs |
| A09:2025 | Logging & Monitoring Failures     | security.txt, log files, WAF detection |
| A10:2025 | SSRF                              | SSRF, Open Redirect, Path Traversal, XXE |

---

## ⚠️ Legal Disclaimer

**Authorized use only.** Only scan systems you own or have explicit written permission to test.
Unauthorized scanning is illegal. Users assume full responsibility.

© 2025 KAVI & MOKSH — Cyber Security Students
