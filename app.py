"""
CyberRecon Framework v5.0
=========================
- Full OWASP Top 10 (2025 Draft / latest published mapping)
- Working Nmap port scan with service/version detection
- Nmap results included in JSON response & HTML report
- Auth: signup / login / logout
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from functools import wraps
import hashlib, os, json, datetime, socket, ssl, re, requests
import concurrent.futures
from urllib.parse import urlparse, quote

# ── optional nmap import (graceful if missing) ─────────────────
try:
    import nmap as python_nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

import urllib3
urllib3.disable_warnings()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cyberrecon-secret-2025-change-in-prod")
CORS(app)

# ══════════════════════════════════════════════════════════════════
# USER STORE  (file-based — swap with SQLite/Postgres in prod)
# ══════════════════════════════════════════════════════════════════
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(u):
    with open(USERS_FILE, "w") as f:
        json.dump(u, f)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return f(*a, **kw)
    return dec

# ══════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/signup", methods=["POST"])
def signup():
    d = request.json
    username = d.get("username","").strip().lower()
    password = d.get("password","")
    email    = d.get("email","").strip().lower()
    if not all([username, password, email]):
        return jsonify({"error":"All fields required"}), 400
    if len(username) < 3:
        return jsonify({"error":"Username min 3 chars"}), 400
    if len(password) < 6:
        return jsonify({"error":"Password min 6 chars"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error":"Username already taken"}), 409
    users[username] = {"email":email,"password":hash_pw(password),
                       "created":datetime.datetime.now().isoformat(),"scans":0}
    save_users(users)
    session["user"] = username
    return jsonify({"success":True,"username":username})

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    username = d.get("username","").strip().lower()
    password = d.get("password","")
    users = load_users()
    u = users.get(username)
    if not u or u["password"] != hash_pw(password):
        return jsonify({"error":"Invalid credentials"}), 401
    session["user"] = username
    return jsonify({"success":True,"username":username})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"success":True})

@app.route("/api/me")
def me():
    if "user" not in session:
        return jsonify({"logged_in":False})
    users = load_users()
    u = users.get(session["user"],{})
    return jsonify({"logged_in":True,"username":session["user"],
                    "email":u.get("email",""),"scans":u.get("scans",0)})

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def normalize_target(t):
    return urlparse(t).netloc if t.startswith("http") else t

def normalize_url(t):
    return t if t.startswith("http") else "http://" + t

def safe_get(url, timeout=6, **kw):
    try:
        return requests.get(url, timeout=timeout, verify=False,
                            allow_redirects=True, **kw)
    except:
        return None

def safe_post(url, timeout=6, **kw):
    try:
        return requests.post(url, timeout=timeout, verify=False, **kw)
    except:
        return None

def add_vuln(vulns, severity, owasp, title, detail=""):
    vulns.append({"severity":severity,"owasp":owasp,"title":title,"detail":detail})

def add_pass(vulns, owasp, title):
    vulns.append({"severity":"PASS","owasp":owasp,"title":title,"detail":""})

# ══════════════════════════════════════════════════════════════════
# SIGNATURE DATABASES
# ══════════════════════════════════════════════════════════════════
OUTDATED_SIGNATURES = {
    "Apache/2.2":    "CVE-2017-7679 — Apache 2.2.x EOL, multiple critical vulns",
    "Apache/2.4.49": "CVE-2021-41773 — Path Traversal & RCE (CRITICAL)",
    "Apache/2.4.50": "CVE-2021-42013 — Path Traversal bypass (CRITICAL)",
    "nginx/1.14":    "nginx 1.14.x — outdated, multiple CVEs",
    "nginx/1.16":    "nginx 1.16.x — outdated, multiple CVEs",
    "PHP/5.":        "PHP 5.x — EOL, many critical vulns",
    "PHP/7.0":       "PHP 7.0 — EOL Dec 2018",
    "PHP/7.1":       "PHP 7.1 — EOL Dec 2019",
    "PHP/7.2":       "PHP 7.2 — EOL Nov 2020",
    "OpenSSL/1.0":   "OpenSSL 1.0.x — EOL, POODLE/DROWN vulnerable",
    "IIS/6.0":       "IIS 6.0 — CVE-2017-7269 Buffer Overflow RCE (CRITICAL)",
    "IIS/7.0":       "IIS 7.0 — EOL, multiple CVEs",
    "Tomcat/6.":     "Apache Tomcat 6.x — EOL",
    "Tomcat/7.":     "Apache Tomcat 7.x — EOL Mar 2021",
    "Struts 2":      "Apache Struts 2 — CVE-2017-5638 RCE (CRITICAL)",
}

SENSITIVE_PATHS = [
    "/.git/HEAD","/.git/config","/.env","/.env.local","/.env.production",
    "/wp-config.php","/config.php","/phpinfo.php","/info.php",
    "/admin","/admin/login","/administrator","/wp-admin",
    "/backup.zip","/backup.tar.gz","/backup.sql","/db.sql","/dump.sql",
    "/.htaccess","/server-status","/server-info","/robots.txt",
    "/.DS_Store","/web.config","/elmah.axd","/trace.axd","/crossdomain.xml",
    "/api/v1/users","/api/users","/api/admin","/.svn/entries","/CVS/Root",
    "/actuator","/actuator/env","/actuator/health","/.well-known/security.txt",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>","'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>","<svg onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "1' ORDER BY 1--", "1 UNION SELECT NULL--", "admin'--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax","warning: mysql",
    "unclosed quotation mark","microsoft ole db",
    "ora-01756","ora-00933","pg::syntaxerror","sqlite_error",
    "mysql_fetch","syntax error near","invalid query",
    "mysql_num_rows","odbc sql server","supplied argument is not a valid mysql",
]

SSTI_PAYLOADS = [
    ("{{7*7}}","49"),("${7*7}","49"),("<%= 7*7 %>","49"),("{{7*'7'}}","7777777"),
]

CMD_PAYLOADS = [
    (";id",["uid=","gid="]),
    ("|id",["uid=","gid="]),
    ("&&id",["uid=","gid="]),
    (";whoami",["root","www-data","apache"]),
]

PATH_TRAVERSAL = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
]

# ══════════════════════════════════════════════════════════════════
# NMAP SCANNER  (the fix — proper error handling + result parsing)
# ══════════════════════════════════════════════════════════════════
def run_nmap_scan(target, ports="1-1024"):
    """
    Returns a dict:
    {
      "available": bool,
      "error": str or None,
      "hosts": [
        {
          "ip": "x.x.x.x",
          "hostname": "...",
          "state": "up",
          "ports": [
            {"port": 80, "proto": "tcp", "state": "open",
             "service": "http", "product": "Apache", "version": "2.4.51",
             "extrainfo": "..."}
          ]
        }
      ],
      "raw_lines": ["..."]   ← shown verbatim in UI
    }
    """
    result = {"available": NMAP_AVAILABLE, "error": None, "hosts": [], "raw_lines": []}

    if not NMAP_AVAILABLE:
        result["error"] = "python-nmap not installed. Run: pip install python-nmap"
        result["raw_lines"] = ["[ERROR] python-nmap not installed.",
                               "Fix: pip install python-nmap",
                               "Also install nmap binary: https://nmap.org/download.html"]
        return result

    try:
        nm = python_nmap.PortScanner()
        result["raw_lines"].append(f"[*] Scanning {target} ports {ports} ...")
        result["raw_lines"].append("[*] This may take 1-3 minutes for -sV scan ...")

        # -sV = version detection, -T4 = aggressive timing, --open = only open ports
        nm.scan(hosts=target, ports=ports, arguments="-sV -T4 --open")

        if not nm.all_hosts():
            result["raw_lines"].append(f"[!] No hosts found. Target may be down or blocking scans.")
            result["raw_lines"].append(f"[!] Nmap command info: {nm.command_line()}")
            return result

        for host_ip in nm.all_hosts():
            h = nm[host_ip]
            hostname = h.hostname() or host_ip
            state    = h.state()
            host_entry = {
                "ip": host_ip,
                "hostname": hostname,
                "state": state,
                "ports": []
            }

            result["raw_lines"].append(f"")
            result["raw_lines"].append(f"Host : {host_ip} ({hostname})")
            result["raw_lines"].append(f"State: {state}")

            for proto in h.all_protocols():
                port_list = sorted(h[proto].keys())
                result["raw_lines"].append(f"Protocol: {proto.upper()}")
                result["raw_lines"].append(f"{'─'*55}")

                for port in port_list:
                    pinfo   = h[proto][port]
                    pstate  = pinfo.get("state","?")
                    service = pinfo.get("name","unknown")
                    product = pinfo.get("product","")
                    version = pinfo.get("version","")
                    extra   = pinfo.get("extrainfo","")
                    cpe     = pinfo.get("cpe","")

                    version_str = " ".join(filter(None,[product, version, extra])).strip()
                    display_line = f"  {port:5}/{proto}  {pstate:10}  {service:15}  {version_str}"
                    result["raw_lines"].append(display_line)

                    host_entry["ports"].append({
                        "port": port, "proto": proto,
                        "state": pstate, "service": service,
                        "product": product, "version": version,
                        "extrainfo": extra, "cpe": cpe,
                        "version_str": version_str
                    })

            result["hosts"].append(host_entry)

        # summary
        total_open = sum(len(h["ports"]) for h in result["hosts"])
        result["raw_lines"].append(f"")
        result["raw_lines"].append(f"[✓] Scan complete. {len(result['hosts'])} host(s), {total_open} open port(s) found.")
        result["raw_lines"].append(f"[*] Command: {nm.command_line()}")

    except python_nmap.PortScannerError as e:
        msg = str(e)
        result["error"] = msg
        result["raw_lines"] = [
            f"[ERROR] Nmap binary not found or permission denied.",
            f"[ERROR] {msg}",
            "",
            "FIXES:",
            "  Windows : Download nmap from https://nmap.org/download.html",
            "  Linux   : sudo apt install nmap",
            "  macOS   : brew install nmap",
            "",
            "  For SYN scan (-sS) you need to run as Administrator/root.",
            "  Use TCP Connect scan (-sT) without admin rights.",
        ]
    except PermissionError:
        result["error"] = "Permission denied"
        result["raw_lines"] = [
            "[ERROR] Permission denied — SYN scan needs admin/root.",
            "Run as Administrator (Windows) or sudo (Linux/Mac).",
            "Or change scan type to TCP Connect (-sT) which needs no privileges.",
        ]
    except Exception as e:
        result["error"] = str(e)
        result["raw_lines"] = [f"[ERROR] Nmap scan failed: {e}"]

    return result

# ══════════════════════════════════════════════════════════════════
# OWASP TOP 10  — 2025  (published Nov 2024 / effective 2025)
# ══════════════════════════════════════════════════════════════════
#
#  A01:2025 — Broken Access Control
#  A02:2025 — Cryptographic Failures
#  A03:2025 — Injection
#  A04:2025 — Insecure Design
#  A05:2025 — Security Misconfiguration
#  A06:2025 — Vulnerable and Outdated Components
#  A07:2025 — Identification and Authentication Failures
#  A08:2025 — Software and Data Integrity Failures
#  A09:2025 — Security Logging and Monitoring Failures
#  A10:2025 — Server-Side Request Forgery (SSRF)
#
# (Same 10 categories as 2021 — OWASP reaffirmed for 2025 with updated sub-tests)
# ══════════════════════════════════════════════════════════════════

def check_a01(url, domain, vulns):
    """A01:2025 — Broken Access Control"""
    found = False

    # 1. Unauthenticated admin panel access
    for path in ["/admin","/admin/","/wp-admin/","/administrator/",
                 "/dashboard","/control-panel","/manage","/cpanel","/phpmyadmin"]:
        r = safe_get(url.rstrip("/")+path, allow_redirects=False)
        if r and r.status_code == 200 and len(r.content) > 200:
            add_vuln(vulns,"CRITICAL","A01",f"Admin panel accessible without auth: {path}",
                     "HTTP 200 returned — no authentication wall detected")
            found = True

    # 2. Directory listing
    for path in ["/images/","/uploads/","/files/","/static/","/assets/","/backup/"]:
        r = safe_get(url.rstrip("/")+path)
        if r and r.status_code == 200:
            if any(s in r.text.lower() for s in ["index of /","parent directory","directory listing"]):
                add_vuln(vulns,"HIGH","A01",f"Directory listing enabled: {path}",
                         "Server exposes full directory contents to anyone")
                found = True

    # 3. Unauthenticated API endpoints
    for path in ["/api/users","/api/v1/users","/api/admin","/api/config","/api/keys","/v1/users"]:
        r = safe_get(url.rstrip("/")+path)
        if r and r.status_code == 200:
            ct   = r.headers.get("Content-Type","")
            body = r.text.strip()
            if "json" in ct or body.startswith("{") or body.startswith("["):
                add_vuln(vulns,"HIGH","A01",f"API endpoint open without auth: {path}",
                         "JSON data returned without authentication")
                found = True

    # 4. HTTP verb tampering
    for method in ["PUT","DELETE","TRACE"]:
        try:
            r = requests.request(method, url, timeout=5, verify=False)
            if r and r.status_code not in (405,403,501,404,400):
                add_vuln(vulns,"MEDIUM","A01",f"HTTP {method} method allowed on root",
                         f"Server returned {r.status_code} — verb tampering possible")
                found = True; break
        except: pass

    # 5. CSRF token check
    r = safe_get(url)
    if r:
        body = r.text.lower()
        if "<form" in body:
            has_csrf = any(t in body for t in ["csrf","_token","xsrf","antiforgery","requestverification"])
            if not has_csrf:
                add_vuln(vulns,"HIGH","A01","CSRF protection missing",
                         "Forms detected without CSRF tokens — state-changing requests unprotected")
                found = True
            else:
                add_pass(vulns,"A01","CSRF token pattern detected in forms")

    # 6. IDOR probe — sequential IDs
    for path in ["/api/user/1","/api/order/1","/profile/1","/user/1"]:
        r1 = safe_get(url.rstrip("/")+path)
        r2 = safe_get(url.rstrip("/")+path.replace("/1","/2"))
        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
            if len(r1.text) > 20 and len(r2.text) > 20:
                add_vuln(vulns,"HIGH","A01",f"Potential IDOR: {path}",
                         "Sequential IDs return data — may allow horizontal privilege escalation")
                found = True; break

    if not found:
        add_pass(vulns,"A01","No obvious broken access control issues")


def check_a02(url, domain, vulns):
    """A02:2025 — Cryptographic Failures"""
    found = False

    # SSL/TLS
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(6); s.connect((domain,443))
            cert   = s.getpeercert()
            ver    = s.version()
            cipher = s.cipher()[0] if s.cipher() else "?"

            expire_str = cert.get("notAfter","")
            if expire_str:
                exp  = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                if days < 0:
                    add_vuln(vulns,"CRITICAL","A02","SSL Certificate EXPIRED",
                             f"Expired {abs(days)} days ago"); found = True
                elif days < 14:
                    add_vuln(vulns,"HIGH","A02","SSL Certificate expiring very soon",
                             f"{days} days left"); found = True
                elif days < 30:
                    add_vuln(vulns,"MEDIUM","A02","SSL Certificate expiring soon",
                             f"{days} days remaining"); found = True
                else:
                    add_pass(vulns,"A02",f"SSL cert valid ({days} days remaining)")

            if ver in ("SSLv2","SSLv3","TLSv1","TLSv1.1"):
                add_vuln(vulns,"HIGH","A02",f"Deprecated TLS protocol: {ver}",
                         "TLS 1.0/1.1 deprecated — POODLE/BEAST attack risk"); found = True
            else:
                add_pass(vulns,"A02",f"TLS protocol OK: {ver}")

            for w in ["RC4","DES","3DES","NULL","EXPORT","MD5","ADH"]:
                if w in cipher.upper():
                    add_vuln(vulns,"HIGH","A02",f"Weak cipher suite: {cipher}",
                             "Vulnerable to known cryptographic attacks"); found = True; break
            else:
                add_pass(vulns,"A02",f"Cipher OK: {cipher}")

    except ConnectionRefusedError:
        add_vuln(vulns,"HIGH","A02","HTTPS not available (port 443 closed)",
                 "All data transmitted unencrypted over HTTP"); found = True
    except ssl.SSLCertVerificationError as e:
        add_vuln(vulns,"HIGH","A02","SSL Certificate verification failed", str(e)[:120]); found = True
    except Exception:
        pass

    # HTTP → HTTPS redirect
    try:
        r = requests.get(f"http://{domain}", timeout=5, allow_redirects=False, verify=False)
        loc = r.headers.get("Location","")
        if r.status_code in (301,302,307,308) and loc.startswith("https://"):
            add_pass(vulns,"A02","HTTP→HTTPS redirect in place")
        else:
            add_vuln(vulns,"MEDIUM","A02","No HTTP→HTTPS redirect",
                     "Plain HTTP requests are not upgraded to HTTPS"); found = True
    except: pass

    # Cookie security flags
    r = safe_get(url)
    if r:
        for ck in r.cookies:
            issues = []
            if not ck.secure:             issues.append("missing Secure flag")
            if not ck.has_nonstandard_attr("HttpOnly"): issues.append("missing HttpOnly (JS-readable)")
            if issues:
                add_vuln(vulns,"MEDIUM","A02",f"Insecure cookie: {ck.name}",
                         " | ".join(issues)); found = True

    # Sensitive data in URL parameters
    r2 = safe_get(url)
    if r2:
        for link in re.findall(r'href=["\']([^"\']+)["\']', r2.text)[:30]:
            for param in ["password","token","secret","api_key","apikey","auth","session"]:
                if param in link.lower():
                    add_vuln(vulns,"HIGH","A02","Sensitive data in URL parameter",
                             f"'{param}' appears in a link URL — logged by servers/proxies"); found = True; break

    if not found:
        add_pass(vulns,"A02","No cryptographic failures detected")


def check_a03(url, domain, vulns):
    """A03:2025 — Injection (SQL, XSS, SSTI, Cmd, NoSQL)"""
    found = False

    # SQL Injection
    sqli_found = False
    for param in ["id","page","search","q","query","user","cat"]:
        for payload in SQLI_PAYLOADS:
            r = safe_get(f"{url}/?{param}={quote(payload)}")
            if r:
                for sig in SQLI_ERRORS:
                    if sig in r.text.lower():
                        add_vuln(vulns,"CRITICAL","A03","SQL Injection detected",
                                 f"DB error '{sig}' via param '{param}' — payload: {payload[:40]}")
                        sqli_found = found = True; break
            if sqli_found: break
        if sqli_found: break
    if not sqli_found:
        for payload in SQLI_PAYLOADS[:3]:
            r = safe_post(url, data={"id":payload,"user":payload,"search":payload})
            if r:
                for sig in SQLI_ERRORS:
                    if sig in r.text.lower():
                        add_vuln(vulns,"CRITICAL","A03","SQL Injection (POST) detected",
                                 f"DB error '{sig}' via POST"); sqli_found = found = True; break
            if sqli_found: break
    if not sqli_found:
        add_pass(vulns,"A03","No SQL Injection signatures found")

    # XSS
    xss_found = False
    for payload in XSS_PAYLOADS:
        r = safe_get(f"{url}/?q={quote(payload)}&search={quote(payload)}")
        if r and payload.lower() in r.text.lower():
            add_vuln(vulns,"HIGH","A03","Reflected XSS detected",
                     f"Payload reflected: {payload[:50]}"); xss_found = found = True; break
        r2 = safe_post(url, data={"q":payload,"search":payload,"input":payload})
        if r2 and payload.lower() in r2.text.lower():
            add_vuln(vulns,"HIGH","A03","Reflected XSS (POST) detected",
                     f"Payload reflected via POST: {payload[:50]}"); xss_found = found = True; break
    if not xss_found:
        add_pass(vulns,"A03","No reflected XSS detected")

    # SSTI
    ssti_found = False
    for payload, expected in SSTI_PAYLOADS:
        r = safe_get(f"{url}/?q={quote(payload)}&name={quote(payload)}")
        if r and expected in r.text:
            add_vuln(vulns,"CRITICAL","A03","Server-Side Template Injection (SSTI)",
                     f"'{payload}' evaluated to '{expected}' — RCE possible")
            ssti_found = found = True; break
    if not ssti_found:
        add_pass(vulns,"A03","No SSTI detected")

    # Command Injection
    cmd_found = False
    for payload, sigs in CMD_PAYLOADS:
        r = safe_get(f"{url}/?cmd={quote(payload)}&exec={quote(payload)}")
        if r:
            for sig in sigs:
                if sig in r.text:
                    add_vuln(vulns,"CRITICAL","A03","Command Injection detected",
                             f"OS output '{sig}' in response — RCE confirmed")
                    cmd_found = found = True; break
        if cmd_found: break
    if not cmd_found:
        add_pass(vulns,"A03","No Command Injection detected")

    # NoSQL Injection
    nosql_found = False
    for payload in ['{"$gt":""}','{"$ne":null}']:
        r = safe_post(url, json={"username":payload,"password":payload})
        if r and r.status_code == 200:
            if any(k in r.text.lower() for k in ["welcome","dashboard","logged in","token","success"]):
                add_vuln(vulns,"CRITICAL","A03","NoSQL Injection possible",
                         "JSON operator payload returned success — auth bypass possible")
                nosql_found = found = True; break
    if not nosql_found:
        add_pass(vulns,"A03","No NoSQL Injection indicators")

    # LDAP Injection
    ldap_found = False
    for payload in ["*","*)(&","*)(uid=*))(|(uid=*","admin)(&"]:
        r = safe_get(f"{url}/?user={quote(payload)}&username={quote(payload)}")
        if r and r.status_code == 200:
            if any(s in r.text.lower() for s in ["ldap","invalid dn","ldap_bind","active directory"]):
                add_vuln(vulns,"HIGH","A03","LDAP Injection possible",
                         f"LDAP-related error with payload: {payload}")
                ldap_found = found = True; break
    if not ldap_found:
        add_pass(vulns,"A03","No LDAP Injection indicators")


def check_a04(url, domain, vulns):
    """A04:2025 — Insecure Design"""
    found = False

    # Stack trace / verbose error
    for trigger in [f"{url}/?id=INVALID_@@99", f"{url}/nonexistent_xyz_page"]:
        r = safe_get(trigger)
        if r and r.status_code in (500,400):
            for sig in ["traceback","stack trace","at java.","exception in thread",
                        "syntaxerror","nameerror","werkzeug","django debug","rails"]:
                if sig in r.text.lower():
                    add_vuln(vulns,"MEDIUM","A04","Stack trace exposed in error response",
                             "Error reveals internal paths/code — aids attacker fingerprinting")
                    found = True; break
            break

    # Debug mode
    for path in ["/?debug=1","/?debug=true","/?XDEBUG_SESSION_START=1","/debug","/_debug"]:
        full = url + path if path.startswith("?") else url.rstrip("/")+path
        r = safe_get(full)
        if r and r.status_code == 200:
            if any(s in r.text.lower() for s in ["debug mode","xdebug","werkzeug debugger","django debug"]):
                add_vuln(vulns,"HIGH","A04","Debug mode / developer console exposed",
                         f"Debug interface at {path} — may allow arbitrary code execution")
                found = True

    # Rate limiting
    r = safe_get(url)
    if r:
        rl = ["x-ratelimit-limit","ratelimit-limit","retry-after","x-ratelimit-remaining"]
        if not any(h in {k.lower() for k in r.headers} for h in rl):
            add_vuln(vulns,"LOW","A04","No rate limiting headers detected",
                     "Brute-force attacks on login/reset endpoints may not be throttled"); found = True
        else:
            add_pass(vulns,"A04","Rate limiting headers present")

    # Account enumeration
    try:
        r1 = safe_post(f"{url}/login", data={"username":"admin","password":"BADPASS99999"})
        r2 = safe_post(f"{url}/login", data={"username":"nouser_xyz_99","password":"BADPASS99999"})
        if r1 and r2:
            t1,t2 = r1.text.lower(), r2.text.lower()
            for phrase in ["user not found","invalid username","no account with that email"]:
                if phrase in t1 or phrase in t2:
                    add_vuln(vulns,"MEDIUM","A04","Account enumeration via login response",
                             "Different error messages reveal valid vs invalid usernames")
                    found = True; break
    except: pass

    # Mass assignment hints
    r3 = safe_get(url)
    if r3:
        mass_patterns = ['"isAdmin"','\"role\":','\"admin\":','\"permissions\":','"is_staff"']
        for p in mass_patterns:
            if p.lower() in r3.text.lower():
                add_vuln(vulns,"MEDIUM","A04","Potential mass assignment — privilege fields in response",
                         f"Field '{p}' visible in page — may be assignable via API")
                found = True; break

    if not found:
        add_pass(vulns,"A04","No insecure design issues detected")


def check_a05(url, domain, vulns):
    """A05:2025 — Security Misconfiguration"""
    found = False
    r = safe_get(url)
    if not r: return
    h = {k.lower():v for k,v in r.headers.items()}

    # Security headers
    header_checks = [
        ("strict-transport-security","HIGH","Missing HSTS",
         "Enables protocol downgrade & cookie hijacking"),
        ("content-security-policy","HIGH","Missing Content-Security-Policy",
         "No CSP — XSS and data injection risk"),
        ("x-frame-options","MEDIUM","Missing X-Frame-Options",
         "Site may be vulnerable to Clickjacking"),
        ("x-content-type-options","MEDIUM","Missing X-Content-Type-Options",
         "MIME-sniffing attacks possible"),
        ("referrer-policy","LOW","Missing Referrer-Policy",
         "Sensitive URLs may leak via Referer header"),
        ("permissions-policy","LOW","Missing Permissions-Policy",
         "Browser APIs (camera/mic/geo) not restricted"),
    ]
    for hdr,sev,title,detail in header_checks:
        if hdr not in h:
            add_vuln(vulns,sev,"A05",title,detail); found = True
        else:
            add_pass(vulns,"A05",f"{hdr} header present")

    # Server info disclosure
    for disc in ["server","x-powered-by","x-aspnet-version","x-generator","x-aspnetmvc-version"]:
        if disc in h:
            add_vuln(vulns,"LOW","A05",f"Technology disclosure via '{disc}' header",
                     f"Value: {h[disc][:80]}"); found = True

    # CORS misconfiguration
    cr = safe_get(url, headers={"Origin":"https://evil.com"})
    if cr:
        acao = cr.headers.get("Access-Control-Allow-Origin","")
        acac = cr.headers.get("Access-Control-Allow-Credentials","").lower()
        if acao == "*" and acac == "true":
            add_vuln(vulns,"CRITICAL","A05","CORS wildcard + credentials — critical",
                     "ACAO:* + Allow-Credentials:true = cross-origin data theft"); found = True
        elif acao == "https://evil.com":
            add_vuln(vulns,"HIGH","A05","CORS reflects arbitrary Origin",
                     "Any attacker domain can read cross-origin responses"); found = True
        elif acao == "*":
            add_vuln(vulns,"MEDIUM","A05","CORS wildcard (*) origin",
                     "Any domain can make cross-origin requests"); found = True

    # TRACE method
    try:
        rt = requests.request("TRACE", url, timeout=5, verify=False)
        if rt and rt.status_code == 200 and "TRACE" in rt.text:
            add_vuln(vulns,"MEDIUM","A05","HTTP TRACE method enabled",
                     "Cross-Site Tracing (XST) attack possible"); found = True
    except: pass

    # Default test pages
    for path in ["/test.php","/test.html","/example.php","/sample.php","/default.asp"]:
        r2 = safe_get(url.rstrip("/")+path)
        if r2 and r2.status_code == 200 and len(r2.content) > 100:
            add_vuln(vulns,"LOW","A05",f"Default/test page accessible: {path}",
                     "Leftover test files may expose info or functionality"); found = True

    if not found:
        add_pass(vulns,"A05","No security misconfigurations detected")


def check_a06(url, domain, vulns):
    """A06:2025 — Vulnerable & Outdated Components"""
    found = False
    r = safe_get(url)
    if not r: return
    combined = str(r.headers) + r.text[:8000]

    for sig, cve in OUTDATED_SIGNATURES.items():
        if sig.lower() in combined.lower():
            add_vuln(vulns,"HIGH","A06",f"Outdated component: {sig}", cve); found = True

    # jQuery
    jq = re.search(r'jquery[/-v]([0-9]+\.[0-9]+\.[0-9]+)', combined.lower())
    if jq:
        ver, pts = jq.group(1), jq.group(1).split(".")
        try:
            if int(pts[0]) < 3 or (int(pts[0])==3 and int(pts[1])<5):
                add_vuln(vulns,"MEDIUM","A06",f"Outdated jQuery v{ver}",
                         "CVE-2020-11022/11023 XSS"); found = True
            else:
                add_pass(vulns,"A06",f"jQuery v{ver} — no critical CVEs")
        except: pass

    # Angular
    ng = re.search(r'angular[/ ]([0-9]+\.[0-9]+)', combined.lower())
    if ng:
        try:
            if int(ng.group(1).split(".")[0]) < 12:
                add_vuln(vulns,"MEDIUM","A06",f"Outdated Angular v{ng.group(1)}",
                         "Angular < 12 has XSS/prototype pollution vulns"); found = True
        except: pass

    # Bootstrap
    bs = re.search(r'bootstrap[/ -]([0-9]+\.[0-9]+\.[0-9]+)', combined.lower())
    if bs:
        try:
            pts = bs.group(1).split(".")
            if int(pts[0]) < 4 or (int(pts[0])==4 and int(pts[1])<3):
                add_vuln(vulns,"LOW","A06",f"Outdated Bootstrap v{bs.group(1)}",
                         "Bootstrap < 4.3.1 has XSS vulnerabilities"); found = True
        except: pass

    # CMS version disclosure
    wp = re.search(r'content="WordPress ([0-9.]+)"', r.text)
    if wp:
        add_vuln(vulns,"MEDIUM","A06",f"WordPress version disclosed: {wp.group(1)}",
                 "Version disclosure enables targeted CVE attacks"); found = True
    drupal = re.search(r'Drupal ([0-9.]+)', r.text)
    if drupal:
        add_vuln(vulns,"MEDIUM","A06",f"Drupal version disclosed: {drupal.group(1)}",
                 "Check for Drupalgeddon vulnerabilities"); found = True

    # Exposed dependency files
    for f in ["/package.json","/composer.json","/requirements.txt","/Gemfile","/package-lock.json"]:
        r2 = safe_get(url.rstrip("/")+f)
        if r2 and r2.status_code == 200 and len(r2.content) > 20:
            add_vuln(vulns,"MEDIUM","A06",f"Dependency file exposed: {f}",
                     "Reveals exact versions — targeted CVE attacks possible"); found = True

    if not found:
        add_pass(vulns,"A06","No outdated/vulnerable components detected")


def check_a07(url, domain, vulns):
    """A07:2025 — Identification & Authentication Failures"""
    found = False

    # Default credentials
    default_creds = [("admin","admin"),("admin","password"),("admin","123456"),
                     ("root","root"),("test","test"),("admin","")]
    for lpath in ["/login","/wp-login.php","/admin/login","/signin","/api/login"]:
        full = url.rstrip("/")+lpath
        r_check = safe_get(full, allow_redirects=False)
        if not r_check or r_check.status_code == 404: continue
        for user, pwd in default_creds:
            r = safe_post(full, data={"username":user,"password":pwd,"email":user,"pass":pwd})
            if r and r.status_code in (200,302):
                if any(k in r.text.lower() for k in ["dashboard","welcome","logout","my account","profile"]):
                    add_vuln(vulns,"CRITICAL","A07",f"Default credentials accepted: {user}:{pwd} at {lpath}",
                             "Admin login works with default credentials — change immediately")
                    found = True; break
        if found: break

    # Session cookie flags
    r = safe_get(url)
    if r:
        for ck in r.cookies:
            issues = []
            if not ck.secure:                              issues.append("missing Secure")
            if not ck.has_nonstandard_attr("HttpOnly"):    issues.append("missing HttpOnly (XSS risk)")
            if not ck.has_nonstandard_attr("SameSite"):    issues.append("missing SameSite (CSRF risk)")
            if issues:
                add_vuln(vulns,"MEDIUM","A07",f"Insecure session cookie: {ck.name}",
                         " | ".join(issues)); found = True
            if len(ck.value) < 16:
                add_vuln(vulns,"HIGH","A07",f"Weak session token: {ck.name}",
                         f"Only {len(ck.value)} chars — predictable/brutable"); found = True

    # Auth token in URLs
    r2 = safe_get(url)
    if r2:
        for link in re.findall(r'href=["\']([^"\']+)["\']', r2.text)[:30]:
            for pat in [r'[?&]token=',r'[?&]session=',r'[?&]auth=',r'[?&]key=']:
                if re.search(pat, link, re.I):
                    add_vuln(vulns,"HIGH","A07","Auth token in URL",
                             "Session tokens in URLs get logged by servers and browser history"); found = True; break

    # Password reset endpoint enumeration
    for rpath in ["/forgot-password","/reset-password","/api/reset","/password/reset"]:
        r3 = safe_post(url.rstrip("/")+rpath,
                       data={"email":"nonexistent_test_99@example.com"})
        r4 = safe_post(url.rstrip("/")+rpath,
                       data={"email":"admin@"+domain})
        if r3 and r4 and r3.status_code == 200 and r4.status_code == 200:
            if r3.text != r4.text:
                add_vuln(vulns,"MEDIUM","A07","User enumeration via password reset",
                         "Different responses for valid vs invalid emails reveal account existence")
                found = True; break

    if not found:
        add_pass(vulns,"A07","No authentication failures detected")


def check_a08(url, domain, vulns):
    """A08:2025 — Software & Data Integrity Failures"""
    found = False
    r = safe_get(url)
    if not r: return
    body = r.text

    # SRI on external scripts
    ext_scripts = re.findall(
        r'<script[^>]+src=["\']https?://(?!' + re.escape(domain) + r')[^"\']+["\'][^>]*>',
        body, re.I)
    missing_sri = [s for s in ext_scripts if "integrity=" not in s.lower()]
    if missing_sri:
        add_vuln(vulns,"MEDIUM","A08",
                 f"{len(missing_sri)} external script(s) without Subresource Integrity (SRI)",
                 "CDN-hosted scripts without integrity hash — supply chain attack risk"); found = True
    else:
        add_pass(vulns,"A08","External scripts have SRI or none from CDN")

    # Deserialization indicators
    for p in ["java.io.serializable","objectinputstream","unserialize(",
              "pickle.loads","yaml.load(","__reduce__"]:
        if p in body.lower():
            add_vuln(vulns,"HIGH","A08","Possible insecure deserialization",
                     f"Pattern '{p}' in page — review deserialization code"); found = True; break

    # Exposed CI/CD files
    for f in ["/.travis.yml","/.github/workflows/main.yml","/Jenkinsfile",
              "/.gitlab-ci.yml","/docker-compose.yml","/.circleci/config.yml","/Dockerfile"]:
        r2 = safe_get(url.rstrip("/")+f)
        if r2 and r2.status_code == 200 and len(r2.content) > 10:
            add_vuln(vulns,"MEDIUM","A08",f"CI/CD config exposed: {f}",
                     "Build pipeline file may contain secrets or reveal infrastructure"); found = True

    # Update mechanism hints (auto-update without signature verification)
    update_patterns = ["autoupdate","auto_update","checkupdate","update_url","updateserver"]
    for p in update_patterns:
        if p in body.lower():
            add_vuln(vulns,"LOW","A08","Possible unsigned update mechanism",
                     f"'{p}' pattern found — ensure updates are integrity-verified"); found = True; break

    if not found:
        add_pass(vulns,"A08","No software integrity failures detected")


def check_a09(url, domain, vulns):
    """A09:2025 — Security Logging & Monitoring Failures"""
    found = False

    # security.txt
    sec_found = False
    for path in ["/.well-known/security.txt","/security.txt"]:
        r = safe_get(url.rstrip("/")+path)
        if r and r.status_code == 200 and len(r.content) > 10:
            add_pass(vulns,"A09",f"security.txt present at {path}")
            sec_found = True; break
    if not sec_found:
        add_vuln(vulns,"LOW","A09","No security.txt found",
                 "No responsible disclosure policy published"); found = True

    # Exposed log files
    for path in ["/app.log","/error.log","/access.log","/debug.log",
                 "/logs/error.log","/application.log","/server.log","/system.log"]:
        r = safe_get(url.rstrip("/")+path)
        if r and r.status_code == 200 and len(r.content) > 50:
            add_vuln(vulns,"HIGH","A09",f"Log file exposed: {path}",
                     "Logs may contain credentials, IPs, errors and internal paths"); found = True

    # No WAF / IDS indicator (check if malicious payload triggers any protection)
    r_test = safe_get(f"{url}/?q=<script>alert(1)</script>")
    if r_test and r_test.status_code == 200:
        body_test = r_test.text.lower()
        waf_sigs = ["blocked","403 forbidden","access denied","security violation",
                    "waf","cloudflare","sucuri","akamai","incapsula","imperva"]
        has_waf = any(s in body_test for s in waf_sigs)
        if not has_waf:
            add_vuln(vulns,"LOW","A09","No WAF/IDS protection detected",
                     "Malicious payload not blocked — monitoring may be insufficient"); found = True
        else:
            add_pass(vulns,"A09","WAF/security protection appears active")

    if not found:
        add_pass(vulns,"A09","No logging/monitoring failures detected")


def check_a10(url, domain, vulns):
    """A10:2025 — Server-Side Request Forgery (SSRF)"""
    found = False

    # SSRF via URL parameters
    ssrf_params = ["url","redirect","link","src","source","fetch","load","callback","proxy","uri","target"]
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",   # AWS
        "http://metadata.google.internal/",            # GCP
        "http://localhost/",
        "http://127.0.0.1/",
    ]
    ssrf_found = False
    for param in ssrf_params[:5]:
        for payload in ssrf_payloads[:2]:
            r = safe_get(f"{url}/?{param}={quote(payload)}")
            if r:
                for sig in ["ami-id","instance-id","local-hostname","meta-data","iam/security","computeMetadata"]:
                    if sig.lower() in r.text.lower():
                        add_vuln(vulns,"CRITICAL","A10","SSRF detected",
                                 f"Internal metadata via '{param}' — cloud credentials at risk")
                        ssrf_found = found = True; break
            if ssrf_found: break
        if ssrf_found: break
    if not ssrf_found:
        add_pass(vulns,"A10","No SSRF indicators detected")

    # Open redirect
    redirect_found = False
    for param in ["redirect","url","next","return","returnUrl","goto","destination","forward","redir","continue"]:
        r = safe_get(f"{url}/?{param}=https://evil.com", allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308):
            if "evil.com" in r.headers.get("Location",""):
                add_vuln(vulns,"HIGH","A10",f"Open Redirect via ?{param}=",
                         "Redirect to attacker-controlled URL — phishing & SSRF chain risk")
                redirect_found = found = True; break
    if not redirect_found:
        add_pass(vulns,"A10","No Open Redirect detected")

    # Path traversal
    traversal_found = False
    for payload in PATH_TRAVERSAL[:3]:
        r = safe_get(f"{url}/?file={payload}&path={payload}&filename={payload}&page={payload}")
        if r and r.status_code == 200:
            if "root:" in r.text or "/bin/bash" in r.text:
                add_vuln(vulns,"CRITICAL","A10","Path Traversal detected",
                         "/etc/passwd content in response — full filesystem read possible")
                traversal_found = found = True; break
    if not traversal_found:
        add_pass(vulns,"A10","No Path Traversal detected")

    # XXE
    xxe_found = False
    for payload in XXE_PAYLOADS:
        r = safe_post(url, data=payload, headers={"Content-Type":"application/xml"})
        if r and "root:" in r.text:
            add_vuln(vulns,"CRITICAL","A10","XXE Injection detected",
                     "XML parser processes external entities — file read/SSRF possible")
            xxe_found = found = True; break
    if not xxe_found:
        add_pass(vulns,"A10","No XXE indicators detected")

    # DNS rebinding / blind SSRF hint
    ssrf_blind_params = ["webhook","callback_url","ping_url","notify_url","hook"]
    for param in ssrf_blind_params:
        r = safe_get(f"{url}/?{param}=http://localhost:8080/")
        if r and r.status_code not in (400,404,405):
            add_vuln(vulns,"MEDIUM","A10",f"Potential blind SSRF via '{param}'",
                     "Parameter accepts internal URLs — may be used for SSRF without direct response"); found = True; break

    if not found:
        add_pass(vulns,"A10","No SSRF/redirect/traversal issues found")


def check_sensitive_files(url, domain, vulns):
    """Sensitive file exposure — feeds into A05"""
    exposed = []
    def probe(path):
        try:
            r = requests.get(url.rstrip("/")+path, timeout=4,
                             allow_redirects=False, verify=False)
            if r.status_code == 200 and len(r.content) > 0:
                return path
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        for res in ex.map(probe, SENSITIVE_PATHS):
            if res: exposed.append(res)
    critical_paths = ["/.git/HEAD","/.git/config","/.env","/.env.local",
                      "/wp-config.php","/config.php","/phpinfo.php","/info.php"]
    if exposed:
        for p in exposed:
            sev = "CRITICAL" if p in critical_paths else "HIGH"
            add_vuln(vulns, sev, "A05", f"Sensitive path exposed: {p}",
                     "Accessible without auth — may contain secrets/credentials")
    else:
        add_pass(vulns,"A05","No common sensitive files exposed")


def check_risky_ports_socket(ip, vulns):
    """Quick socket-based risky port check (no nmap needed)"""
    RISKY = {
        21:("FTP","HIGH","FTP transmits credentials in plaintext"),
        22:("SSH","LOW","SSH open — ensure key-auth only, no weak passwords"),
        23:("Telnet","CRITICAL","Telnet — fully plaintext protocol"),
        25:("SMTP","MEDIUM","SMTP — check for open relay"),
        110:("POP3","MEDIUM","POP3 — plaintext email"),
        143:("IMAP","MEDIUM","IMAP — plaintext email"),
        445:("SMB","CRITICAL","SMB exposed — EternalBlue/WannaCry risk"),
        1433:("MSSQL","HIGH","MSSQL DB exposed to internet"),
        1521:("Oracle","HIGH","Oracle DB exposed to internet"),
        2375:("Docker API","CRITICAL","Docker API without TLS — container escape"),
        3306:("MySQL","HIGH","MySQL DB exposed to internet"),
        3389:("RDP","HIGH","RDP — brute-force & BlueKeep risk"),
        5432:("PostgreSQL","HIGH","PostgreSQL DB exposed"),
        5900:("VNC","HIGH","VNC — often weak/no auth"),
        6379:("Redis","CRITICAL","Redis — often no auth by default"),
        8080:("HTTP-Alt","LOW","Alt HTTP port — may expose dev panel"),
        8888:("Jupyter","HIGH","Jupyter Notebook — often no auth"),
        9200:("Elasticsearch","CRITICAL","Elasticsearch — often no auth"),
        27017:("MongoDB","CRITICAL","MongoDB — often no auth"),
    }
    open_risky = []
    for port,(svc,sev,reason) in RISKY.items():
        try:
            s = socket.socket()
            s.settimeout(0.8)
            if s.connect_ex((ip,port)) == 0:
                add_vuln(vulns,sev,"A05",f"Risky port open: {port}/{svc}", reason)
                open_risky.append(port)
            s.close()
        except: pass
    if not open_risky:
        add_pass(vulns,"A05","No high-risk ports found open")


# ══════════════════════════════════════════════════════════════════
# MAIN SCAN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════
def run_full_scan(target, nmap_ports="1-1024"):
    results = {
        "recon": [], "dns": [], "ip_info": [],
        "vulnerabilities": [], "summary": {},
        "owasp_coverage": {},
        "nmap": {}         # ← NEW: nmap results live here
    }

    domain = normalize_target(target)
    url    = normalize_url(target)

    # ── HTTP Recon ──────────────────────────────────────────────
    try:
        r = requests.get(url, timeout=6, verify=False)
        results["recon"] += [
            f"Status Code  : {r.status_code}",
            f"Final URL    : {r.url}",
            f"Server       : {r.headers.get('Server','Not disclosed')}",
            f"Content-Type : {r.headers.get('Content-Type','?')}",
            "─── Full Response Headers ───",
        ] + [f"  {k}: {v}" for k,v in r.headers.items()]
    except Exception as e:
        results["recon"].append(f"HTTP recon failed: {e}")

    # ── DNS ─────────────────────────────────────────────────────
    ips = []
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        results["dns"].append(f"Resolved IPs : {', '.join(ips)}")
        for ip in ips:
            try:    results["dns"].append(f"  {ip}  →  {socket.gethostbyaddr(ip)[0]}")
            except: results["dns"].append(f"  {ip}  →  No PTR record")
    except Exception as e:
        results["dns"].append(f"DNS failed: {e}")

    # ── IP Intelligence ──────────────────────────────────────────
    for ip in ips[:1]:
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if geo.get("status") == "success":
                for field in ["country","regionName","city","isp","org","as"]:
                    if field in geo:
                        results["ip_info"].append(f"  {field:12}: {geo[field]}")
        except: pass

    # ── Nmap scan ────────────────────────────────────────────────
    results["nmap"] = run_nmap_scan(ips[0] if ips else domain, nmap_ports)

    # ── OWASP Top 10 2025 — parallel ────────────────────────────
    vulns  = []
    checks = [
        lambda: check_a01(url, domain, vulns),
        lambda: check_a02(url, domain, vulns),
        lambda: check_a03(url, domain, vulns),
        lambda: check_a04(url, domain, vulns),
        lambda: check_a05(url, domain, vulns),
        lambda: check_a06(url, domain, vulns),
        lambda: check_a07(url, domain, vulns),
        lambda: check_a08(url, domain, vulns),
        lambda: check_a09(url, domain, vulns),
        lambda: check_a10(url, domain, vulns),
        lambda: check_sensitive_files(url, domain, vulns),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(fn) for fn in checks]
        for f in concurrent.futures.as_completed(futs):
            try: f.result()
            except: pass

    # ── Socket-based risky port check ───────────────────────────
    if ips:
        check_risky_ports_socket(ips[0], vulns)

    # ── Summary ──────────────────────────────────────────────────
    results["vulnerabilities"] = vulns
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"PASS":0}
    owasp_counts = {}
    for v in vulns:
        sev   = v.get("severity","INFO")
        owasp = v.get("owasp","")
        if sev in counts: counts[sev] += 1
        if owasp and sev != "PASS":
            owasp_counts[owasp] = owasp_counts.get(owasp,0) + 1
    results["summary"]        = counts
    results["owasp_coverage"] = owasp_counts
    return results


# ══════════════════════════════════════════════════════════════════
# SCAN API
# ══════════════════════════════════════════════════════════════════
@app.route("/api/scan", methods=["POST"])
@login_required
def scan():
    data   = request.json
    target = data.get("target","").strip()
    ports  = data.get("ports","1-1024").strip() or "1-1024"
    if not target:
        return jsonify({"error":"Target required"}), 400
    users = load_users()
    if session["user"] in users:
        users[session["user"]]["scans"] = users[session["user"]].get("scans",0) + 1
        save_users(users)
    try:
        results = run_full_scan(target, nmap_ports=ports)
        return jsonify({"success":True,"results":results,"target":target,
                        "timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:
        return jsonify({"error":str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
