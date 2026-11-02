"""
CyberRecon Scanning Engine
==========================
Pure scanning and reconnaissance logic separated from GUI interfaces.
Powers both the Tkinter desktop client and the Streamlit web application.

Includes:
- HTTP Reconnaissance (status code, security headers, server fingerprint)
- DNS Resolution (A records, reverse PTR lookups)
- WHOIS Lookup (domain registration details)
- IP Intelligence & Geolocation (ip-api)
- Nmap Port Scanner (TCP Connect, SYN, UDP, Service/Version, Fast Scan)
- OWASP Top 10 (2025) Automated Vulnerability Scanner (A01 - A10)
- Sensitive path probes & risky socket port checks
- Structured HTML & text report generation
"""

import os
import re
import ssl
import json
import socket
import datetime
import ipaddress
import threading
import concurrent.futures
from urllib.parse import urlparse, quote

import requests
import urllib3

# Suppress insecure HTTPS request warnings
urllib3.disable_warnings()

# Optional third-party imports with graceful fallbacks
try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import nmap as python_nmap
    NMAP_OK = True
except ImportError:
    NMAP_OK = False


# Theme Palette
C = {
    'bg_dark': '#0a0e27',
    'bg_darker': '#050810',
    'bg_panel': '#121729',
    'cyan': '#00d9ff',
    'green': '#00ff99',
    'red': '#ff0055',
    'yellow': '#ffcc00',
    'orange': '#ff8800',
    'purple': '#bf00ff',
    'text': '#e0e0e0',
    'muted': '#8892b0',
    'border': '#1e2a47',
}


# ─────────────────────────────────────────────────────────────
# Normalization & Validation
# ─────────────────────────────────────────────────────────────

def norm_domain(t: str) -> str:
    """Extract clean domain/hostname/IP from input."""
    t = t.strip()
    if t.startswith("http://") or t.startswith("https://"):
        parsed = urlparse(t)
        host = parsed.netloc or parsed.path
        return host.split(":")[0]
    return t.split("/")[0].split(":")[0]


def norm_url(t: str) -> str:
    """Ensure target has http:// or https:// scheme."""
    t = t.strip()
    return t if t.startswith("http://") or t.startswith("https://") else "http://" + t


def validate_target(target: str) -> str:
    """
    Validate target string to prevent arbitrary command execution or invalid inputs.
    Returns clean domain/host or raises ValueError.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")
    
    target = target.strip()
    # Reject shell meta-characters
    disallowed = set(";`$&|<>\"'{}()[]!#\n\r\t ")
    if any(c in disallowed for c in target):
        raise ValueError("Target contains illegal characters or whitespace.")

    domain = norm_domain(target)
    if not domain or len(domain) > 253:
        raise ValueError("Invalid target length.")

    # Check if valid IP
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        pass

    # Check hostname regex (RFC 1123 compliant)
    hostname_regex = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|"
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    )
    if not hostname_regex.match(domain):
        raise ValueError(f"Invalid domain or IP format: '{domain}'")

    return domain


def validate_ports(ports_str: str) -> str:
    """
    Validate port range or port list.
    Accepts: '80', '1-1024', '80,443,8080', '21-25,80,443'
    """
    ports_str = (ports_str or "1-1024").strip()
    if not re.match(r"^[0-9,\-]+$", ports_str):
        raise ValueError("Port specification must only contain digits, hyphens, and commas.")

    parts = ports_str.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValueError(f"Invalid port range segment: '{part}'")
            try:
                p1, p2 = int(bounds[0]), int(bounds[1])
                if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2):
                    raise ValueError(f"Port numbers out of valid range (1-65535): '{part}'")
            except ValueError as e:
                raise ValueError(f"Invalid port numbers in '{part}': {e}")
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port number out of valid range (1-65535): '{p}'")
            except ValueError as e:
                raise ValueError(f"Invalid port number: '{part}'")

    return ports_str


def validate_scan_type(scan_type: str) -> str:
    """Whitelist allowed Nmap scan types to prevent arbitrary argument tampering."""
    allowed = ["TCP Connect", "SYN Scan", "UDP Scan", "Service Version", "Fast Scan"]
    if scan_type not in allowed:
        raise ValueError(f"Invalid scan type '{scan_type}'. Allowed: {allowed}")
    return scan_type


def safe_get(url: str, timeout: int = 6, **kw):
    """Safely perform an HTTP GET request with timeouts and error handling."""
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True, **kw)
    except Exception:
        return None


def safe_post(url: str, timeout: int = 6, **kw):
    """Safely perform an HTTP POST request with timeouts and error handling."""
    try:
        return requests.post(url, timeout=timeout, verify=False, **kw)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Signatures & Payload Databases (Preserved from Scanner.py)
# ─────────────────────────────────────────────────────────────

OUTDATED_SIGS = {
    "Apache/2.2": "CVE-2017-7679 — Apache 2.2.x EOL",
    "Apache/2.4.49": "CVE-2021-41773 — Path Traversal RCE",
    "Apache/2.4.50": "CVE-2021-42013 — Path Traversal",
    "nginx/1.14": "nginx 1.14.x — outdated CVEs",
    "nginx/1.16": "nginx 1.16.x — outdated CVEs",
    "PHP/5.": "PHP 5.x — EOL critical vulns",
    "PHP/7.0": "PHP 7.0 — EOL",
    "PHP/7.1": "PHP 7.1 — EOL",
    "PHP/7.2": "PHP 7.2 — EOL",
    "OpenSSL/1.0": "OpenSSL 1.0.x — POODLE/DROWN",
    "IIS/6.0": "IIS 6.0 — CVE-2017-7269 RCE",
    "Tomcat/6.": "Tomcat 6.x — EOL",
    "Tomcat/7.": "Tomcat 7.x — EOL",
    "Struts 2": "Struts 2 — CVE-2017-5638",
}

SENS_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/wp-config.php", "/config.php", "/phpinfo.php", "/admin", "/administrator", "/wp-admin",
    "/backup.zip", "/backup.sql", "/db.sql", "/.htaccess", "/server-status", "/server-info",
    "/robots.txt", "/.DS_Store", "/web.config", "/elmah.axd", "/api/v1/users", "/api/users",
    "/actuator", "/actuator/env", "/.well-known/security.txt", "/package.json", "/composer.json"
]

XSS_P = [
    "<script>alert('XSS')</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>"
]

SQLI_P = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "1 UNION SELECT NULL--",
    "admin'--"
]

SQLI_E = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "microsoft ole db",
    "ora-01756",
    "pg::syntaxerror",
    "sqlite_error",
    "mysql_fetch",
    "syntax error near"
]

SSTI_P = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("{{7*'7'}}", "7777777")
]

CMD_P = [
    (";id", ["uid=", "gid="]),
    ("|id", ["uid=", "gid="]),
    (";whoami", ["root", "www-data"])
]

PATH_T = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd"
]

XXE = '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'

RISKY_PORTS = {
    21: ("FTP", "HIGH", "FTP plaintext"),
    22: ("SSH", "LOW", "SSH open"),
    23: ("Telnet", "CRITICAL", "Telnet plaintext"),
    25: ("SMTP", "MEDIUM", "Open relay?"),
    445: ("SMB", "CRITICAL", "EternalBlue risk"),
    1433: ("MSSQL", "HIGH", "DB exposed"),
    2375: ("Docker", "CRITICAL", "Docker API no TLS"),
    3306: ("MySQL", "HIGH", "DB exposed"),
    3389: ("RDP", "HIGH", "BlueKeep risk"),
    5432: ("PostgreSQL", "HIGH", "DB exposed"),
    5900: ("VNC", "HIGH", "Weak auth"),
    6379: ("Redis", "CRITICAL", "No auth"),
    8888: ("Jupyter", "HIGH", "No auth"),
    9200: ("Elasticsearch", "CRITICAL", "No auth"),
    27017: ("MongoDB", "CRITICAL", "No auth")
}


# ─────────────────────────────────────────────────────────────
# Report Manager
# ─────────────────────────────────────────────────────────────

class ReportManager:
    """Manages sectioned scan output and generates styled HTML reports."""
    SECTIONS = ["HTTP Recon", "DNS", "WHOIS", "IP Lookup", "Nmap", "OWASP Vulnerabilities"]

    def __init__(self):
        self.data = {s: [] for s in self.SECTIONS}

    def log(self, section: str, text: str):
        if section in self.data:
            self.data[section].append(text)

    def clear(self):
        for k in self.data:
            self.data[k].clear()

    def has_data(self) -> bool:
        return any(bool(lines) for lines in self.data.values())

    def get_plain_text(self) -> str:
        out = []
        for s, lines in self.data.items():
            if lines:
                out.append("=" * 60)
                out.append(s)
                out.append("=" * 60)
                out.extend(lines)
                out.append("")
        return "\n".join(out)

    def generate_html(self, target_label: str = "") -> str:
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        shtml = ""
        for sec, lines in self.data.items():
            if not lines:
                continue
            col = "#ff0055" if "OWASP" in sec else ("#00d9ff" if sec == "Nmap" else "#00ff99")
            shtml += f'<div class="sec"><h2 style="color:{col}">{sec}</h2>'
            shtml += f'<pre style="border-left:3px solid {col}">' + "\n".join(lines) + "</pre></div>"

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CyberRecon v5 Report - {target_label or 'Security Scan'}</title>
<style>
body {{
    background:#0a0e27;
    color:#e0e0e0;
    font-family:'Consolas','Segoe UI',monospace;
    padding:28px;
    margin:0;
}}
.container {{
    max-width: 1100px;
    margin: 0 auto;
}}
h1 {{
    color:#00d9ff;
    border-bottom:2px solid #00d9ff;
    padding-bottom:12px;
    letter-spacing:2px;
    margin-top: 0;
}}
h2 {{
    margin-top:28px;
    letter-spacing:1px;
    font-size: 1.25rem;
}}
pre {{
    white-space:pre-wrap;
    background:#121729;
    padding:16px;
    border-radius:6px;
    font-size:.85rem;
    line-height:1.7;
    color:#d8e2fd;
    overflow-x:auto;
}}
.ts {{
    color:#8892b0;
    font-size:.9em;
    margin-bottom:20px;
}}
.sec {{
    margin-bottom:24px;
}}
.footer {{
    margin-top: 40px;
    padding-top: 15px;
    border-top: 1px solid #1e2a47;
    color: #8892b0;
    font-size: 0.8rem;
}}
</style>
</head>
<body>
<div class="container">
<h1>🔒 CyberRecon v5.0 — Full Security Report</h1>
<p class="ts">Target: <strong>{target_label or 'N/A'}</strong> &nbsp;|&nbsp; Generated: {ts}</p>
{shtml}
<div class="footer">CyberRecon Security Framework — For Authorized Testing Only</div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# Reconnaissance Modules
# ─────────────────────────────────────────────────────────────

class ReconBase:
    def __init__(self, lg, rp):
        self.lg = lg
        self.rp = rp

    def info(self, m):
        self.lg("[INFO]", m, C['green'])

    def warn(self, m):
        self.lg("[WARN]", m, C['yellow'])

    def err(self, m):
        self.lg("[ERROR]", m, C['red'])


class HTTPRecon(ReconBase):
    def scan(self, url: str) -> dict:
        data = {"status_code": None, "headers": {}}
        try:
            self.info("HTTP reconnaissance...")
            r = requests.get(url, timeout=5, verify=False)
            data["status_code"] = r.status_code
            data["headers"] = dict(r.headers)
            l = f"Status Code: {r.status_code}"
            self.info(l)
            self.rp.log("HTTP Recon", l)
            for k, v in r.headers.items():
                l = f"  {k}: {v}"
                self.lg("", l, C['muted'])
                self.rp.log("HTTP Recon", l)
        except Exception as e:
            self.err(f"HTTP failed: {e}")
            self.rp.log("HTTP Recon", f"HTTP failed: {e}")
        return data


class DNSRecon(ReconBase):
    def scan(self, target: str) -> list:
        ips = []
        try:
            self.info("DNS resolution...")
            ips = socket.gethostbyname_ex(target)[2]
            l = f"Resolved: {', '.join(ips)}"
            self.info(l)
            self.rp.log("DNS", l)
            for ip in ips:
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                    l = f"  {ip} → {ptr}"
                except Exception:
                    l = f"  {ip} → No PTR"
                self.lg("", l, C['muted'])
                self.rp.log("DNS", l)
            return ips
        except Exception as e:
            self.err(f"DNS failed: {e}")
            self.rp.log("DNS", f"DNS failed: {e}")
            return []


class WHOISRecon(ReconBase):
    def scan(self, target: str) -> dict:
        if not WHOIS_OK:
            msg = "python-whois not installed"
            self.warn(msg)
            self.rp.log("WHOIS", f"[WARN] {msg}")
            return {}
        try:
            self.info("WHOIS lookup...")
            w = whois.whois(target)
            res = {}
            for k, v in w.items():
                if v:
                    res[k] = v
                    l = f"  {k}: {v}"
                    self.lg("", l, C['muted'])
                    self.rp.log("WHOIS", l)
            return res
        except Exception as e:
            self.err(f"WHOIS failed: {e}")
            self.rp.log("WHOIS", f"WHOIS failed: {e}")
            return {}


class IPIntelligence(ReconBase):
    def scan(self, ip: str) -> dict:
        try:
            self.info(f"IP intel: {ip}...")
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if r.get('status') == 'success':
                for f in ['country', 'regionName', 'city', 'isp', 'org', 'as']:
                    if f in r:
                        l = f"  {f}: {r[f]}"
                        self.lg("", l, C['muted'])
                        self.rp.log("IP Lookup", l)
                return r
            else:
                self.warn(f"IP lookup failed: {r.get('message', 'Unknown error')}")
                return {}
        except Exception as e:
            self.err(f"IP failed: {e}")
            self.rp.log("IP Lookup", f"IP failed: {e}")
            return {}


class NmapScanner(ReconBase):
    def scan(self, target: str, ports: str = "1-1024", scan_type: str = "TCP Connect") -> dict:
        result = {
            "available": NMAP_OK,
            "hosts": [],
            "error": None
        }
        if not NMAP_OK:
            err_msg = "python-nmap not installed. Run: pip install python-nmap"
            self.err(err_msg)
            self.rp.log("Nmap", f"[ERROR] {err_msg}")
            result["error"] = err_msg
            return result

        try:
            target = validate_target(target)
            ports = validate_ports(ports)
            scan_type = validate_scan_type(scan_type)

            self.info(f"Nmap scan: {target} ports {ports} ({scan_type})...")
            self.warn("May take 1-3 minutes...")

            nm = python_nmap.PortScanner()
            args_map = {
                "TCP Connect": "-sT -sV -T4",
                "SYN Scan": "-sS -sV -T4",
                "UDP Scan": "-sU -T4",
                "Service Version": "-sV -sC -T4",
                "Fast Scan": "-F -sV -T4"
            }
            args = args_map.get(scan_type, "-sT -sV -T4")
            self.info(f"CMD: nmap {args} -p {ports} {target}")
            self.rp.log("Nmap", f"Command: nmap {args} -p {ports} {target}")

            nm.scan(hosts=target, ports=ports, arguments=args)

            if not nm.all_hosts():
                self.warn("No hosts — target down or blocking")
                self.rp.log("Nmap", "[!] No hosts found")
                return result

            for hst in nm.all_hosts():
                h = nm[hst]
                hn = h.hostname() or hst
                st = h.state()
                self.info(f"Host: {hst} ({hn}) — {st}")
                self.rp.log("Nmap", f"Host : {hst} ({hn})")
                self.rp.log("Nmap", f"State: {st}")

                host_data = {
                    "ip": hst,
                    "hostname": hn,
                    "state": st,
                    "protocols": {}
                }

                for proto in h.all_protocols():
                    self.lg("", f"  Protocol: {proto.upper()}", C['cyan'])
                    self.rp.log("Nmap", f"Protocol: {proto.upper()}")
                    self.rp.log("Nmap", "-" * 55)
                    host_data["protocols"][proto] = []

                    for port in sorted(h[proto].keys()):
                        pi = h[proto][port]
                        pst = pi.get("state", "?")
                        svc = pi.get("name", "?")
                        prod = pi.get("product", "")
                        ver = pi.get("version", "")
                        extra = pi.get("extrainfo", "")
                        vs = " ".join(filter(None, [prod, ver, extra])).strip()

                        icon = "[+]" if pst == "open" else ("[-]" if pst == "closed" else "[?]")
                        line = f"  {icon} {port:5}/{proto}  {pst:10}  {svc:15}  {vs}"
                        col = C['green'] if pst == "open" else C['muted']
                        self.lg("", line, col)
                        self.rp.log("Nmap", line)

                        host_data["protocols"][proto].append({
                            "port": port,
                            "proto": proto,
                            "state": pst,
                            "service": svc,
                            "version": vs
                        })

                result["hosts"].append(host_data)

            oc = sum(
                sum(1 for p in nm[h][pr] if nm[h][pr][p]['state'] == 'open')
                for h in nm.all_hosts()
                for pr in nm[h].all_protocols()
            )
            s = f"\n[✓] Nmap done. {len(nm.all_hosts())} host(s), {oc} open port(s)."
            self.info(s.strip())
            self.rp.log("Nmap", s)

        except python_nmap.PortScannerError as e:
            msg = str(e)
            self.err(f"Nmap error: {msg}")
            self.rp.log("Nmap", f"[ERROR] {msg}")
            self.rp.log("Nmap", "Install nmap: https://nmap.org/download.html  |  sudo apt install nmap")
            result["error"] = msg
        except PermissionError:
            msg = "Permission denied. Use TCP Connect (no admin/root needed)."
            self.err(msg)
            self.rp.log("Nmap", f"[ERROR] {msg}")
            result["error"] = msg
        except Exception as e:
            self.err(f"Nmap failed: {e}")
            self.rp.log("Nmap", f"[ERROR] {e}")
            result["error"] = str(e)

        return result


# ─────────────────────────────────────────────────────────────
# OWASP Top 10 (2025) Vulnerability Scanner
# ─────────────────────────────────────────────────────────────

class OWASPScanner:
    """Automated vulnerability checker covering OWASP Top 10 (2025)."""

    def __init__(self, logger, reporter):
        self.logger = logger
        self.reporter = reporter
        self.findings = []

    def _add(self, sev: str, owasp: str, title: str, detail: str = ""):
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "PASS": "✅"}
        line = f"{icons.get(sev, '⚪')} [{sev}] [{owasp}:2025] {title}"
        if detail:
            line += f"\n        → {detail}"
        self.findings.append({"severity": sev, "owasp": owasp, "title": title, "detail": detail})
        col = C['red'] if sev in ("CRITICAL", "HIGH") else (
            C['orange'] if sev == "MEDIUM" else (C['yellow'] if sev == "LOW" else C['green'])
        )
        self.logger("[VULN]", line, col)
        self.reporter.log("OWASP Vulnerabilities", line)

    def _ok(self, owasp: str, msg: str):
        line = f"✅ [PASS] [{owasp}:2025] {msg}"
        self.logger("[OK]", line, C['green'])
        self.reporter.log("OWASP Vulnerabilities", line)

    def check_a01(self, url: str, domain: str):
        self.logger("[A01]", "Broken Access Control...", C['cyan'])
        found = False
        for path in ["/admin", "/admin/", "/wp-admin/", "/administrator/", "/dashboard", "/cpanel", "/phpmyadmin"]:
            r = safe_get(url.rstrip("/") + path, allow_redirects=False)
            if r and r.status_code == 200 and len(r.content) > 200:
                self._add("CRITICAL", "A01", f"Admin panel accessible: {path}")
                found = True
        for path in ["/images/", "/uploads/", "/files/", "/static/", "/backup/"]:
            r = safe_get(url.rstrip("/") + path)
            if r and r.status_code == 200 and any(s in r.text.lower() for s in ["index of /", "parent directory"]):
                self._add("HIGH", "A01", f"Directory listing: {path}")
                found = True
        for path in ["/api/users", "/api/v1/users", "/api/admin", "/api/config"]:
            r = safe_get(url.rstrip("/") + path)
            if r and r.status_code == 200:
                b = r.text.strip()
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or b.startswith("{") or b.startswith("["):
                    self._add("HIGH", "A01", f"Unauthenticated API: {path}")
                    found = True
        for m in ["PUT", "DELETE", "TRACE"]:
            try:
                r = requests.request(m, url, timeout=5, verify=False)
                if r and r.status_code not in (405, 403, 501, 404, 400):
                    self._add("MEDIUM", "A01", f"HTTP {m} allowed", f"Status {r.status_code}")
                    found = True
                    break
            except Exception:
                pass
        r = safe_get(url)
        if r:
            body = r.text.lower()
            if "<form" in body:
                has_csrf = any(t in body for t in ["csrf", "_token", "xsrf", "antiforgery"])
                if not has_csrf:
                    self._add("HIGH", "A01", "CSRF protection missing")
                    found = True
                else:
                    self._ok("A01", "CSRF token detected")
        for path in ["/api/user/1", "/profile/1", "/user/1"]:
            r1 = safe_get(url.rstrip("/") + path)
            r2 = safe_get(url.rstrip("/") + path.replace("/1", "/2"))
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200 and len(r1.text) > 20:
                self._add("HIGH", "A01", f"Potential IDOR: {path}", "Sequential IDs return data")
                found = True
                break
        if not found:
            self._ok("A01", "No broken access control issues")

    def check_a02(self, url: str, domain: str):
        self.logger("[A02]", "Cryptographic Failures...", C['cyan'])
        found = False
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(6)
                s.connect((domain, 443))
                cert = s.getpeercert()
                ver = s.version()
                cipher = s.cipher()[0] if s.cipher() else "?"
                es = cert.get("notAfter", "")
                if es:
                    exp = datetime.datetime.strptime(es, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                    if days < 0:
                        self._add("CRITICAL", "A02", "SSL Cert EXPIRED", f"Expired {abs(days)} days ago")
                        found = True
                    elif days < 14:
                        self._add("HIGH", "A02", "SSL Cert expiring soon", f"{days} days")
                        found = True
                    elif days < 30:
                        self._add("MEDIUM", "A02", "SSL Cert expiring", f"{days} days")
                        found = True
                    else:
                        self._ok("A02", f"SSL cert valid ({days} days)")
                if ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    self._add("HIGH", "A02", f"Deprecated TLS: {ver}")
                    found = True
                else:
                    self._ok("A02", f"TLS OK: {ver}")
                for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ADH"]:
                    if w in cipher.upper():
                        self._add("HIGH", "A02", f"Weak cipher: {cipher}")
                        found = True
                        break
                else:
                    self._ok("A02", f"Cipher OK: {cipher}")
        except ConnectionRefusedError:
            self._add("HIGH", "A02", "HTTPS unavailable", "Port 443 closed")
            found = True
        except ssl.SSLCertVerificationError as e:
            self._add("HIGH", "A02", "SSL cert failed", str(e)[:100])
            found = True
        except Exception:
            pass

        try:
            r = requests.get(f"http://{domain}", timeout=5, allow_redirects=False, verify=False)
            if r.status_code in (301, 302, 307, 308) and r.headers.get("Location", "").startswith("https://"):
                self._ok("A02", "HTTP→HTTPS redirect OK")
            else:
                self._add("MEDIUM", "A02", "No HTTP→HTTPS redirect")
                found = True
        except Exception:
            pass

        r = safe_get(url)
        if r:
            for ck in r.cookies:
                issues = []
                if not ck.secure:
                    issues.append("missing Secure")
                if not ck.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly")
                if issues:
                    self._add("MEDIUM", "A02", f"Insecure cookie: {ck.name}", " | ".join(issues))
                    found = True
        if not found:
            self._ok("A02", "No crypto failures")

    def check_a03(self, url: str, domain: str):
        self.logger("[A03]", "Injection...", C['cyan'])
        sqli = False
        for param in ["id", "page", "search", "q", "user"]:
            for p in SQLI_P:
                r = safe_get(f"{url}/?{param}={quote(p)}")
                if r:
                    for sig in SQLI_E:
                        if sig in r.text.lower():
                            self._add("CRITICAL", "A03", "SQL Injection", f"'{sig}' via '{param}'")
                            sqli = True
                            break
                if sqli:
                    break
            if sqli:
                break
        if not sqli:
            for p in SQLI_P[:3]:
                r = safe_post(url, data={"id": p, "user": p, "search": p})
                if r:
                    for sig in SQLI_E:
                        if sig in r.text.lower():
                            self._add("CRITICAL", "A03", "SQL Injection (POST)")
                            sqli = True
                            break
                if sqli:
                    break
        if not sqli:
            self._ok("A03", "No SQLi detected")

        xss = False
        for p in XSS_P:
            r = safe_get(f"{url}/?q={quote(p)}&search={quote(p)}")
            if r and p.lower() in r.text.lower():
                self._add("HIGH", "A03", "Reflected XSS", p[:40])
                xss = True
                break
        if not xss:
            self._ok("A03", "No XSS detected")

        ssti = False
        for payload, expected in SSTI_P:
            r = safe_get(f"{url}/?q={quote(payload)}&name={quote(payload)}")
            if r and expected in r.text:
                self._add("CRITICAL", "A03", "SSTI detected", f"'{payload}'→'{expected}' RCE possible")
                ssti = True
                break
        if not ssti:
            self._ok("A03", "No SSTI detected")

        cmd = False
        for payload, sigs in CMD_P:
            r = safe_get(f"{url}/?cmd={quote(payload)}&exec={quote(payload)}")
            if r:
                for sig in sigs:
                    if sig in r.text:
                        self._add("CRITICAL", "A03", "Command Injection", f"OS output '{sig}'")
                        cmd = True
                        break
            if cmd:
                break
        if not cmd:
            self._ok("A03", "No command injection")

        nosql = False
        for p in ['{"$gt":""}', '{"$ne":null}']:
            r = safe_post(url, json={"username": p, "password": p})
            if r and r.status_code == 200 and any(k in r.text.lower() for k in ["welcome", "dashboard", "token"]):
                self._add("CRITICAL", "A03", "NoSQL Injection")
                nosql = True
                break
        if not nosql:
            self._ok("A03", "No NoSQL injection")

    def check_a04(self, url: str, domain: str):
        self.logger("[A04]", "Insecure Design...", C['cyan'])
        found = False
        for trigger in [f"{url}/?id=INVALID@@99", f"{url}/nonexistent_xyz_99"]:
            r = safe_get(trigger)
            if r and r.status_code in (500, 400):
                for sig in ["traceback", "stack trace", "at java.", "werkzeug", "django debug"]:
                    if sig in r.text.lower():
                        self._add("MEDIUM", "A04", "Stack trace exposed")
                        found = True
                        break
                break
        for path in ["/?debug=1", "/?debug=true", "/?XDEBUG_SESSION_START=1"]:
            full = url + path if path.startswith("?") else url.rstrip("/") + path
            r = safe_get(full)
            if r and r.status_code == 200:
                if any(s in r.text.lower() for s in ["debug mode", "xdebug", "werkzeug debugger"]):
                    self._add("HIGH", "A04", f"Debug mode exposed at {path}")
                    found = True
        r = safe_get(url)
        if r:
            rl = ["x-ratelimit-limit", "ratelimit-limit", "retry-after"]
            if not any(h in {k.lower() for k in r.headers} for h in rl):
                self._add("LOW", "A04", "No rate limiting headers")
                found = True
            else:
                self._ok("A04", "Rate limiting headers present")
        if not found:
            self._ok("A04", "No insecure design issues")

    def check_a05(self, url: str, domain: str):
        self.logger("[A05]", "Security Misconfiguration...", C['cyan'])
        found = False
        r = safe_get(url)
        if not r:
            return
        h = {k.lower(): v for k, v in r.headers.items()}
        for hdr, sev, title, detail in [
            ("strict-transport-security", "HIGH", "Missing HSTS", "Protocol downgrade risk"),
            ("content-security-policy", "HIGH", "Missing CSP", "XSS risk"),
            ("x-frame-options", "MEDIUM", "Missing X-Frame-Options", "Clickjacking"),
            ("x-content-type-options", "MEDIUM", "Missing X-Content-Type-Options", "MIME sniffing"),
            ("referrer-policy", "LOW", "Missing Referrer-Policy", "URL leakage"),
        ]:
            if hdr not in h:
                self._add(sev, "A05", title, detail)
                found = True
            else:
                self._ok("A05", f"{hdr} present")
        for disc in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if disc in h:
                self._add("LOW", "A05", f"Tech disclosure: {disc}", h[disc][:80])
                found = True
        cr = safe_get(url, headers={"Origin": "https://evil.com"})
        if cr:
            acao = cr.headers.get("Access-Control-Allow-Origin", "")
            acac = cr.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "*" and acac == "true":
                self._add("CRITICAL", "A05", "CORS wildcard+credentials")
                found = True
            elif acao == "https://evil.com":
                self._add("HIGH", "A05", "CORS reflects Origin")
                found = True
            elif acao == "*":
                self._add("MEDIUM", "A05", "CORS wildcard (*)")
                found = True
        try:
            rt = requests.request("TRACE", url, timeout=5, verify=False)
            if rt and rt.status_code == 200 and "TRACE" in rt.text:
                self._add("MEDIUM", "A05", "HTTP TRACE enabled")
                found = True
        except Exception:
            pass
        if not found:
            self._ok("A05", "No misconfigurations")

    def check_a06(self, url: str, domain: str):
        self.logger("[A06]", "Vulnerable Components...", C['cyan'])
        found = False
        r = safe_get(url)
        if not r:
            return
        combined = str(r.headers) + r.text[:8000]
        for sig, cve in OUTDATED_SIGS.items():
            if sig.lower() in combined.lower():
                self._add("HIGH", "A06", f"Outdated: {sig}", cve)
                found = True
        jq = re.search(r'jquery[/-v]([0-9]+\.[0-9]+\.[0-9]+)', combined.lower())
        if jq:
            ver, pts = jq.group(1), jq.group(1).split(".")
            try:
                if int(pts[0]) < 3 or (int(pts[0]) == 3 and int(pts[1]) < 5):
                    self._add("MEDIUM", "A06", f"Old jQuery v{ver}", "CVE-2020-11022/11023")
                    found = True
                else:
                    self._ok("A06", f"jQuery v{ver} OK")
            except Exception:
                pass
        wp = re.search(r'content="WordPress ([0-9.]+)"', r.text)
        if wp:
            self._add("MEDIUM", "A06", f"WordPress version: {wp.group(1)}")
            found = True
        for f in ["/package.json", "/composer.json", "/requirements.txt"]:
            r2 = safe_get(url.rstrip("/") + f)
            if r2 and r2.status_code == 200 and len(r2.content) > 20:
                self._add("MEDIUM", "A06", f"Dep file exposed: {f}")
                found = True
        if not found:
            self._ok("A06", "No outdated components")

    def check_a07(self, url: str, domain: str):
        self.logger("[A07]", "Auth Failures...", C['cyan'])
        found = False
        default_creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"), ("test", "test")]
        for lpath in ["/login", "/wp-login.php", "/admin/login", "/signin"]:
            full = url.rstrip("/") + lpath
            rck = safe_get(full, allow_redirects=False)
            if not rck or rck.status_code == 404:
                continue
            for user, pwd in default_creds:
                r = safe_post(full, data={"username": user, "password": pwd, "email": user, "pass": pwd})
                if r and r.status_code in (200, 302):
                    if any(k in r.text.lower() for k in ["dashboard", "welcome", "logout", "my account"]):
                        self._add("CRITICAL", "A07", f"Default creds: {user}:{pwd} at {lpath}")
                        found = True
                        break
            if found:
                break
        r = safe_get(url)
        if r:
            for ck in r.cookies:
                issues = []
                if not ck.secure:
                    issues.append("missing Secure")
                if not ck.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly")
                if issues:
                    self._add("MEDIUM", "A07", f"Insecure cookie: {ck.name}", " | ".join(issues))
                    found = True
                if len(ck.value) < 16:
                    self._add("HIGH", "A07", f"Weak token: {ck.name}", f"{len(ck.value)} chars")
                    found = True
        if not found:
            self._ok("A07", "No auth failures")

    def check_a08(self, url: str, domain: str):
        self.logger("[A08]", "Software Integrity...", C['cyan'])
        found = False
        r = safe_get(url)
        if not r:
            return
        body = r.text
        ext = re.findall(r'<script[^>]+src=["\']https?://(?!' + re.escape(domain) + r')[^"\']+["\'][^>]*>', body, re.I)
        miss = [s for s in ext if "integrity=" not in s.lower()]
        if miss:
            self._add("MEDIUM", "A08", f"{len(miss)} CDN scripts without SRI", "Supply chain risk")
            found = True
        else:
            self._ok("A08", "SRI OK or no external scripts")
        for p in ["java.io.serializable", "objectinputstream", "unserialize(", "pickle.loads"]:
            if p in body.lower():
                self._add("HIGH", "A08", f"Deser indicator: {p}")
                found = True
                break
        for f in ["/.travis.yml", "/Jenkinsfile", "/.gitlab-ci.yml", "/docker-compose.yml", "/Dockerfile"]:
            r2 = safe_get(url.rstrip("/") + f)
            if r2 and r2.status_code == 200 and len(r2.content) > 10:
                self._add("MEDIUM", "A08", f"CI/CD exposed: {f}")
                found = True
        if not found:
            self._ok("A08", "No integrity failures")

    def check_a09(self, url: str, domain: str):
        self.logger("[A09]", "Logging & Monitoring...", C['cyan'])
        found = False
        sec = False
        for path in ["/.well-known/security.txt", "/security.txt"]:
            r = safe_get(url.rstrip("/") + path)
            if r and r.status_code == 200 and len(r.content) > 10:
                self._ok("A09", f"security.txt at {path}")
                sec = True
                break
        if not sec:
            self._add("LOW", "A09", "No security.txt")
            found = True
        for path in ["/app.log", "/error.log", "/access.log", "/debug.log", "/logs/error.log"]:
            r = safe_get(url.rstrip("/") + path)
            if r and r.status_code == 200 and len(r.content) > 50:
                self._add("HIGH", "A09", f"Log file exposed: {path}")
                found = True
        r = safe_get(f"{url}/?q=<script>alert(1)</script>")
        if r and r.status_code == 200:
            waf = ["blocked", "403 forbidden", "security violation", "cloudflare", "incapsula"]
            if not any(s in r.text.lower() for s in waf):
                self._add("LOW", "A09", "No WAF detected")
                found = True
            else:
                self._ok("A09", "WAF/protection active")

    def check_a10(self, url: str, domain: str):
        self.logger("[A10]", "SSRF / Redirect / Traversal...", C['cyan'])
        found = False
        ssrf_params = ["url", "redirect", "link", "src", "source", "fetch", "load", "callback", "proxy", "uri"]
        ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/"]
        ssrf = False
        for param in ssrf_params[:4]:
            for payload in ssrf_payloads[:2]:
                r = safe_get(f"{url}/?{param}={quote(payload)}")
                if r:
                    for sig in ["ami-id", "instance-id", "local-hostname", "meta-data", "iam/security"]:
                        if sig.lower() in r.text.lower():
                            self._add("CRITICAL", "A10", "SSRF detected", f"Metadata via '{param}'")
                            ssrf = found = True
                            break
                if ssrf:
                    break
            if ssrf:
                break
        if not ssrf:
            self._ok("A10", "No SSRF detected")

        redir = False
        for param in ["redirect", "url", "next", "return", "goto", "destination", "forward", "redir"]:
            r = safe_get(f"{url}/?{param}=https://evil.com", allow_redirects=False)
            if r and r.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in r.headers.get("Location", ""):
                    self._add("HIGH", "A10", f"Open Redirect via ?{param}=")
                    redir = found = True
                    break
        if not redir:
            self._ok("A10", "No open redirect")

        trav = False
        for payload in PATH_T[:3]:
            r = safe_get(f"{url}/?file={payload}&path={payload}&filename={payload}")
            if r and "root:" in r.text:
                self._add("CRITICAL", "A10", "Path Traversal", "/etc/passwd found")
                trav = found = True
                break
        if not trav:
            self._ok("A10", "No path traversal")

        r = safe_post(url, data=XXE, headers={"Content-Type": "application/xml"})
        if r and "root:" in r.text:
            self._add("CRITICAL", "A10", "XXE Injection")
            found = True
        else:
            self._ok("A10", "No XXE")

    def check_sensitive(self, url: str, domain: str):
        self.logger("[FILES]", "Sensitive file probe...", C['cyan'])
        exposed = []

        def probe(path):
            try:
                r = requests.get(url.rstrip("/") + path, timeout=4, allow_redirects=False, verify=False)
                if r.status_code == 200 and len(r.content) > 0:
                    return path
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            for res in ex.map(probe, SENS_PATHS):
                if res:
                    exposed.append(res)

        crit = ["/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/wp-config.php", "/config.php", "/phpinfo.php"]
        if exposed:
            for p in exposed:
                self._add("CRITICAL" if p in crit else "HIGH", "A05", f"Sensitive path: {p}", "No auth required")
        else:
            self._ok("A05", "No sensitive files exposed")

    def check_risky_ports(self, ip: str):
        self.logger("[PORTS]", f"Risky port check on {ip}...", C['cyan'])
        open_r = []
        for port, (svc, sev, reason) in RISKY_PORTS.items():
            try:
                s = socket.socket()
                s.settimeout(0.8)
                if s.connect_ex((ip, port)) == 0:
                    self._add(sev, "A05", f"Risky port {port}/{svc}", reason)
                    open_r.append(port)
                s.close()
            except Exception:
                pass
        if not open_r:
            self._ok("A05", "No risky ports open")

    def run(self, target: str) -> list:
        self.findings.clear()
        target = validate_target(target)
        domain = norm_domain(target)
        url = norm_url(target)

        self.logger("[OWASP]", "=" * 55, C['red'])
        self.logger("[OWASP]", f"OWASP TOP 10 (2025): {domain}", C['red'])
        self.logger("[OWASP]", "=" * 55, C['red'])
        self.reporter.log("OWASP Vulnerabilities", "=" * 55)
        self.reporter.log("OWASP Vulnerabilities", f"Target: {domain} | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        checks = [
            lambda: self.check_a01(url, domain),
            lambda: self.check_a02(url, domain),
            lambda: self.check_a03(url, domain),
            lambda: self.check_a04(url, domain),
            lambda: self.check_a05(url, domain),
            lambda: self.check_a06(url, domain),
            lambda: self.check_a07(url, domain),
            lambda: self.check_a08(url, domain),
            lambda: self.check_a09(url, domain),
            lambda: self.check_a10(url, domain),
            lambda: self.check_sensitive(url, domain),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(fn) for fn in checks]
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        try:
            ips = socket.gethostbyname_ex(domain)[2]
            if ips:
                self.check_risky_ports(ips[0])
        except Exception:
            pass

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "PASS": 0}
        for v in self.findings:
            s = v.get("severity", "INFO")
            if s in counts:
                counts[s] += 1

        summary = (
            f"\n{'=' * 55}\nOWASP 2025 COMPLETE\n"
            f"🔴 CRITICAL:{counts['CRITICAL']}  🟠 HIGH:{counts['HIGH']}  "
            f"🟡 MEDIUM:{counts['MEDIUM']}  🟢 LOW:{counts['LOW']}  ✅ PASS:{counts['PASS']}\n{'=' * 55}"
        )
        self.logger("[OWASP]", summary, C['red'])
        self.reporter.log("OWASP Vulnerabilities", summary)
        return self.findings


# ─────────────────────────────────────────────────────────────
# Orchestration Engine
# ─────────────────────────────────────────────────────────────

class ScanEngine:
    """Master scan coordinator."""

    def __init__(self, lg, rp):
        self.lg = lg
        self.rp = rp
        self.http = HTTPRecon(lg, rp)
        self.dns = DNSRecon(lg, rp)
        self.whois = WHOISRecon(lg, rp)
        self.ip = IPIntelligence(lg, rp)
        self.nmap = NmapScanner(lg, rp)
        self.owasp = OWASPScanner(lg, rp)

    def scan(self, target: str, run_vuln: bool = True, run_nmap: bool = False,
             nmap_ports: str = "1-1024", nmap_type: str = "TCP Connect") -> dict:
        target = validate_target(target)
        self.lg("[SCAN]", f"Full scan: {target}", C['cyan'])
        domain = norm_domain(target)
        url = norm_url(target)

        results = {
            "target": target,
            "domain": domain,
            "url": url,
            "http": {},
            "dns": [],
            "whois": {},
            "ip": {},
            "nmap": {},
            "owasp": []
        }

        results["http"] = self.http.scan(url)
        ips = self.dns.scan(domain)
        results["dns"] = ips
        results["whois"] = self.whois.scan(domain)

        for ip_addr in ips[:1]:
            results["ip"] = self.ip.scan(ip_addr)

        if run_nmap:
            t = ips[0] if ips else domain
            results["nmap"] = self.nmap.scan(t, nmap_ports, nmap_type)

        if run_vuln:
            results["owasp"] = self.owasp.run(target)

        self.lg("[DONE]", "Scan complete!", C['green'])
        return results

