"""
CyberRecon v5.0 — Streamlit Web Security Suite
==============================================
Web-based Cybersecurity Reconnaissance & Vulnerability Scanner.
Converted from Desktop Tkinter GUI to Streamlit while preserving
100% of the underlying scanning logic and features:
- HTTP Reconnaissance & Header Analysis
- DNS Resolution & PTR Lookups
- WHOIS Domain Information
- IP Intelligence & Geolocation
- Nmap Network Port Scanning
- OWASP Top 10 (2025) Automated Vulnerability Checks (A01 - A10)
- Styled HTML Security Report Generation & Export
"""

import os
import shutil
import datetime
import pandas as pd
import streamlit as st

from scanner_engine import (
    C,
    WHOIS_OK,
    NMAP_OK,
    norm_domain,
    norm_url,
    validate_target,
    validate_ports,
    validate_scan_type,
    ReportManager,
    OWASPScanner,
    NmapScanner,
    IPIntelligence,
    ScanEngine,
)

# ─────────────────────────────────────────────────────────────
# Page Configuration & Styling
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CyberRecon v5.0 | Security Suite",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    /* Dark cyber theme accents */
    .stApp {
        background-color: #0a0e27;
        color: #e0e0e0;
    }
    .css-1d391kg, [data-testid="stSidebar"] {
        background-color: #121729 !important;
        border-right: 1px solid #1e2a47;
    }
    /* Metric styling */
    [data-testid="stMetricValue"] {
        font-family: 'Consolas', monospace;
        color: #00d9ff !important;
    }
    [data-testid="stMetricLabel"] {
        color: #8892b0 !important;
    }
    /* Buttons */
    .stButton > button {
        border-radius: 4px;
        font-weight: bold;
        transition: all 0.2s;
    }
    /* Alert / info cards */
    .cyber-card {
        background-color: #121729;
        border: 1px solid #1e2a47;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 16px;
    }
    .cyber-card-header {
        color: #00d9ff;
        font-size: 1.1rem;
        font-weight: bold;
        margin-bottom: 8px;
    }
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78rem;
        font-weight: bold;
        margin-right: 6px;
    }
    .badge-critical { background: #ff0055; color: white; }
    .badge-high { background: #ff8800; color: white; }
    .badge-medium { background: #ffcc00; color: black; }
    .badge-low { background: #00ff99; color: black; }
    .badge-pass { background: #00d9ff; color: black; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────────────────────

if "full_results" not in st.session_state:
    st.session_state.full_results = None
if "full_report" not in st.session_state:
    st.session_state.full_report = None
if "full_logs" not in st.session_state:
    st.session_state.full_logs = []

if "vuln_results" not in st.session_state:
    st.session_state.vuln_results = None
if "vuln_report" not in st.session_state:
    st.session_state.vuln_report = None
if "vuln_logs" not in st.session_state:
    st.session_state.vuln_logs = []

if "nmap_results" not in st.session_state:
    st.session_state.nmap_results = None
if "nmap_report" not in st.session_state:
    st.session_state.nmap_report = None
if "nmap_logs" not in st.session_state:
    st.session_state.nmap_logs = []

if "intel_results" not in st.session_state:
    st.session_state.intel_results = None


# ─────────────────────────────────────────────────────────────
# System Capability Helpers
# ─────────────────────────────────────────────────────────────

def get_nmap_status():
    """Detect if nmap executable and python-nmap are operational."""
    nmap_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if not NMAP_OK:
        return False, "python-nmap package is not installed."
    if not nmap_path:
        return False, "Nmap binary not found on system PATH."
    return True, f"Nmap available: {nmap_path}"


# ─────────────────────────────────────────────────────────────
# Sidebar Navigation
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🔒 CYBERRECON v5.0")
    st.caption("OWASP 2025 + Nmap Security Suite")
    st.markdown("---")

    nav_choice = st.radio(
        "Navigation",
        [
            "🔍 Reconnaissance Scanner",
            "🛡️ OWASP 2025 Vuln Scanner",
            "🗺️ Network / Nmap Scanner",
            "🌐 IP Intelligence",
            "📊 Reports & Export",
            "ℹ️ About"
        ],
        index=0
    )

    st.markdown("---")
    st.markdown("#### ⚡ System Status")
    nmap_ok, nmap_msg = get_nmap_status()
    if nmap_ok:
        st.success("🟢 Nmap Binary: Ready", icon="✅")
    else:
        st.warning("🟡 Nmap: Not on PATH", icon="⚠️")

    if WHOIS_OK:
        st.success("🟢 WHOIS Engine: Ready", icon="✅")
    else:
        st.warning("🟡 WHOIS: Missing library", icon="⚠️")

    st.markdown("---")
    st.caption("⚠️ **Authorization Warning:** This tool is for authorized penetration testing and educational auditing only.")


# ─────────────────────────────────────────────────────────────
# View 1: Full Reconnaissance Scanner
# ─────────────────────────────────────────────────────────────

if nav_choice == "🔍 Reconnaissance Scanner":
    st.title("🔍 Reconnaissance & Security Scanner")
    st.markdown("Execute unified reconnaissance (HTTP headers, DNS, WHOIS, IP Geolocation) with optional OWASP Top 10 (2025) vulnerability tests and Nmap port scanning.")

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        col1, col2 = st.columns([3, 1])

        with col1:
            target_input = st.text_input(
                "Target URL / Domain / IP:",
                placeholder="example.com or https://example.com or 192.168.1.1",
                help="Enter domain, IPv4/IPv6, or full web URL without shell characters."
            )

        with col2:
            st.write("") # spacing
            st.write("")
            auth_check = st.checkbox("Authorized Target", help="Confirm you have permission to scan this host.")

        col_opt1, col_opt2, col_opt3, col_opt4 = st.columns(4)
        with col_opt1:
            inc_owasp = st.checkbox("Include OWASP 2025 Scan", value=True)
        with col_opt2:
            inc_nmap = st.checkbox("Include Nmap Scan", value=False)
        with col_opt3:
            nmap_ports = st.text_input("Nmap Ports:", value="1-1024", disabled=not inc_nmap)
        with col_opt4:
            nmap_type = st.selectbox(
                "Nmap Scan Type:",
                ["TCP Connect", "SYN Scan", "UDP Scan", "Service Version", "Fast Scan"],
                index=0,
                disabled=not inc_nmap
            )

        btn_col1, btn_col2, _ = st.columns([1, 1, 4])
        with btn_col1:
            start_btn = st.button("▶ START SCAN", type="primary", use_container_width=True)
        with btn_col2:
            clear_btn = st.button("🗑️ CLEAR RESULTS", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if clear_btn:
        st.session_state.full_results = None
        st.session_state.full_report = None
        st.session_state.full_logs = []
        st.rerun()

    if start_btn:
        if not target_input.strip():
            st.error("Please enter a target domain, IP, or URL.")
        elif not auth_check:
            st.error("Please confirm that you are authorized to scan this target by checking 'Authorized Target'.")
        else:
            try:
                clean_target = validate_target(target_input)
                clean_ports = validate_ports(nmap_ports) if inc_nmap else "1-1024"
                clean_type = validate_scan_type(nmap_type) if inc_nmap else "TCP Connect"

                logs = []
                log_placeholder = st.empty()
                progress_bar = st.progress(0, text="Initializing scan engine...")

                rm = ReportManager()

                def streamlit_logger(prefix, text, color):
                    logs.append((prefix, text, color))
                    # Show recent log entries in the live output area
                    tail_text = "\n".join(f"{p} {t}".strip() for p, t, c in logs[-15:])
                    log_placeholder.code(tail_text, language="bash")

                engine = ScanEngine(streamlit_logger, rm)

                with st.spinner(f"Scanning target: {clean_target}..."):
                    progress_bar.progress(15, text="Running HTTP & DNS reconnaissance...")
                    results = engine.scan(
                        target=clean_target,
                        run_vuln=inc_owasp,
                        run_nmap=inc_nmap,
                        nmap_ports=clean_ports,
                        nmap_type=clean_type
                    )
                    progress_bar.progress(100, text="Scan complete!")

                st.session_state.full_results = results
                st.session_state.full_report = rm
                st.session_state.full_logs = logs
                st.success("Scan completed successfully!")
                st.rerun()

            except Exception as e:
                st.error(f"Scan validation or execution error: {e}")

    # Display Results if available
    if st.session_state.full_results:
        res = st.session_state.full_results
        rm = st.session_state.full_report

        st.markdown("### 📊 Scan Summary")
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Target", res.get("domain", "N/A"))
        with m2:
            st.metric("HTTP Status", res.get("http", {}).get("status_code", "N/A") or "N/A")
        with m3:
            st.metric("Resolved IPs", len(res.get("dns", [])))
        with m4:
            vulns = res.get("owasp", [])
            crit_high = sum(1 for v in vulns if v.get("severity") in ("CRITICAL", "HIGH"))
            st.metric("Vulnerabilities", len(vulns), delta=f"{crit_high} Critical/High" if crit_high else None, delta_color="inverse")
        with m5:
            hosts = res.get("nmap", {}).get("hosts", [])
            open_ports = 0
            for h in hosts:
                for pr in h.get("protocols", {}).values():
                    open_ports += sum(1 for p in pr if p.get("state") == "open")
            st.metric("Open Ports", open_ports)

        # Tabbed Details
        t_vuln, t_nmap, t_http, t_dns, t_whois, t_ip, t_con = st.tabs([
            "🛡️ OWASP Findings", "🗺️ Nmap Scan", "🔍 HTTP Recon",
            "🔗 DNS Info", "📋 WHOIS", "🌐 IP Intel", "💻 Console Output"
        ])

        with t_vuln:
            vulns = res.get("owasp", [])
            if not vulns:
                st.info("No OWASP vulnerability scan was executed or no findings recorded.")
            else:
                sev_filter = st.selectbox("Filter by Severity:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"], key="full_sev_filter")
                filtered = vulns if sev_filter == "ALL" else [v for v in vulns if v.get("severity") == sev_filter]

                for v in filtered:
                    sev = v.get("severity", "INFO")
                    col = "#ff0055" if sev in ("CRITICAL", "HIGH") else ("#ff8800" if sev == "MEDIUM" else ("#ffcc00" if sev == "LOW" else "#00ff99"))
                    with st.expander(f"[{sev}] [{v.get('owasp')}:2025] {v.get('title')}"):
                        st.markdown(f"**Severity:** <span style='color:{col};font-weight:bold'>{sev}</span>", unsafe_allow_html=True)
                        st.markdown(f"**OWASP Category:** {v.get('owasp')}:2025")
                        if v.get("detail"):
                            st.markdown(f"**Details:** `{v.get('detail')}`")

        with t_nmap:
            nmap_data = res.get("nmap", {})
            if not nmap_data or not nmap_data.get("hosts"):
                if nmap_data.get("error"):
                    st.error(f"Nmap Error: {nmap_data.get('error')}")
                else:
                    st.info("Nmap scan was not included or no open ports were discovered.")
            else:
                for host in nmap_data.get("hosts", []):
                    st.markdown(f"#### Host: `{host.get('ip')}` ({host.get('hostname')}) — State: **{host.get('state')}**")
                    rows = []
                    for proto, p_list in host.get("protocols", {}).items():
                        for p in p_list:
                            rows.append({
                                "Port": p.get("port"),
                                "Protocol": proto.upper(),
                                "State": p.get("state"),
                                "Service": p.get("service"),
                                "Version": p.get("version")
                            })
                    if rows:
                        st.dataframe(pd.DataFrame(rows), use_container_width=True)
                    else:
                        st.caption("No open ports found on this host.")

        with t_http:
            http_data = res.get("http", {})
            st.markdown(f"**Status Code:** `{http_data.get('status_code', 'N/A')}`")
            if http_data.get("headers"):
                st.markdown("#### Response Headers")
                st.json(http_data.get("headers"))
            else:
                st.caption("No HTTP headers captured.")

        with t_dns:
            dns_ips = res.get("dns", [])
            if dns_ips:
                st.markdown("#### Resolved IP Addresses")
                for ip in dns_ips:
                    st.markdown(f"- `{ip}`")
            else:
                st.caption("No DNS records resolved.")

        with t_whois:
            whois_data = res.get("whois", {})
            if whois_data:
                st.markdown("#### Domain WHOIS Details")
                st.json({k: str(v) for k, v in whois_data.items()})
            else:
                st.caption("WHOIS data not available or lookup skipped.")

        with t_ip:
            ip_data = res.get("ip", {})
            if ip_data:
                st.markdown("#### Geolocation & Provider Details")
                st.json(ip_data)
            else:
                st.caption("No IP geolocation data available.")

        with t_con:
            if st.session_state.full_logs:
                raw_log = "\n".join(f"{p} {t}".strip() for p, t, c in st.session_state.full_logs)
                st.code(raw_log, language="bash")

        # HTML Download
        if rm and rm.has_data():
            st.markdown("---")
            html_content = rm.generate_html(target_label=res.get("domain", "Target"))
            st.download_button(
                label="💾 Download Full HTML Report",
                data=html_content,
                file_name=f"CyberRecon_Report_{res.get('domain','scan')}.html",
                mime="text/html",
                type="primary"
            )


# ─────────────────────────────────────────────────────────────
# View 2: Standalone OWASP 2025 Vuln Scanner
# ─────────────────────────────────────────────────────────────

elif nav_choice == "🛡️ OWASP 2025 Vuln Scanner":
    st.title("🛡️ OWASP Top 10 (2025) Vulnerability Scanner")
    st.markdown("Dedicated automated vulnerability inspection addressing draft and published OWASP Top 10 categories (A01–A10).")

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        col1, col2 = st.columns([3, 1])
        with col1:
            vuln_target = st.text_input("Target URL / Hostname:", value="https://example.com")
        with col2:
            st.write("")
            st.write("")
            v_auth = st.checkbox("Authorized Target", key="v_auth")

        col_b1, col_b2, _ = st.columns([1, 1, 4])
        with col_b1:
            scan_vuln_btn = st.button("🔍 SCAN VULNERABILITIES", type="primary", use_container_width=True)
        with col_b2:
            clear_vuln_btn = st.button("🗑️ CLEAR", key="v_clear", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if clear_vuln_btn:
        st.session_state.vuln_results = None
        st.session_state.vuln_report = None
        st.session_state.vuln_logs = []
        st.rerun()

    if scan_vuln_btn:
        if not vuln_target.strip() or vuln_target == "https://example.com":
            st.error("Please enter a valid target URL.")
        elif not v_auth:
            st.error("Please confirm authorization before scanning.")
        else:
            try:
                clean_target = validate_target(vuln_target)
                v_logs = []
                log_box = st.empty()

                def v_logger(prefix, text, color):
                    v_logs.append((prefix, text, color))
                    tail = "\n".join(f"{p} {t}".strip() for p, t, c in v_logs[-12:])
                    log_box.code(tail, language="bash")

                v_rm = ReportManager()
                scanner = OWASPScanner(v_logger, v_rm)

                with st.spinner(f"Testing {clean_target} across OWASP Top 10 (2025)..."):
                    findings = scanner.run(clean_target)

                st.session_state.vuln_results = findings
                st.session_state.vuln_report = v_rm
                st.session_state.vuln_logs = v_logs
                st.success("OWASP scan completed!")
                st.rerun()
            except Exception as e:
                st.error(f"Error during vulnerability scan: {e}")

    # Metrics Legend
    st.markdown("#### Severity Summary")
    c1, c2, c3, c4, c5 = st.columns(5)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "PASS": 0}
    if st.session_state.vuln_results:
        for f in st.session_state.vuln_results:
            s = f.get("severity", "INFO")
            if s in counts:
                counts[s] += 1

    c1.metric("🔴 CRITICAL", counts["CRITICAL"])
    c2.metric("🟠 HIGH", counts["HIGH"])
    c3.metric("🟡 MEDIUM", counts["MEDIUM"])
    c4.metric("🟢 LOW", counts["LOW"])
    c5.metric("✅ PASS", counts["PASS"])

    # Detailed Findings
    if st.session_state.vuln_results:
        st.markdown("### 📋 Findings")
        filter_sev = st.selectbox("Filter Findings:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"])
        display_findings = (
            st.session_state.vuln_results
            if filter_sev == "ALL"
            else [f for f in st.session_state.vuln_results if f.get("severity") == filter_sev]
        )

        for item in display_findings:
            sev = item.get("severity", "INFO")
            badge_class = f"badge-{sev.lower()}"
            st.markdown(
                f"<div class='cyber-card'>"
                f"<span class='badge {badge_class}'>{sev}</span> "
                f"<strong>[{item.get('owasp')}:2025] {item.get('title')}</strong>"
                f"{'<br><small style=\"color:#8892b0\">→ ' + item.get('detail') + '</small>' if item.get('detail') else ''}"
                f"</div>",
                unsafe_allow_html=True
            )

        if st.session_state.vuln_report:
            html = st.session_state.vuln_report.generate_html(target_label=vuln_target)
            st.download_button(
                "💾 Download OWASP HTML Report",
                data=html,
                file_name="OWASP_2025_Report.html",
                mime="text/html"
            )

    st.markdown("---")
    with st.expander("ℹ️ OWASP Top 10 (2025) Coverage Reference"):
        owasp_ref = [
            {"ID": "A01:2025", "Category": "Broken Access Control", "Tests": "Admin panels, directory listing, CSRF protection, IDOR, verb tampering"},
            {"ID": "A02:2025", "Category": "Cryptographic Failures", "Tests": "SSL/TLS validity, weak ciphers, HTTP→HTTPS redirect, cookie flags"},
            {"ID": "A03:2025", "Category": "Injection", "Tests": "SQLi (GET/POST), reflected XSS, SSTI, command injection, NoSQL"},
            {"ID": "A04:2025", "Category": "Insecure Design", "Tests": "Stack trace disclosure, debug mode flags, rate limiting headers"},
            {"ID": "A05:2025", "Category": "Security Misconfiguration", "Tests": "HSTS, CSP, X-Frame-Options, CORS reflection/wildcards, HTTP TRACE, sensitive files"},
            {"ID": "A06:2025", "Category": "Vulnerable Components", "Tests": "Known CVE signatures, outdated jQuery, WordPress versions, exposed dependency files"},
            {"ID": "A07:2025", "Category": "Auth & ID Failures", "Tests": "Default credential testing, weak session token length, insecure cookies"},
            {"ID": "A08:2025", "Category": "Software Integrity", "Tests": "External script Subresource Integrity (SRI), deserialization markers, CI/CD exposure"},
            {"ID": "A09:2025", "Category": "Logging & Monitoring", "Tests": "security.txt detection, exposed server logs, basic WAF validation"},
            {"ID": "A10:2025", "Category": "SSRF & Traversal", "Tests": "Cloud metadata SSRF (AWS/GCP), open redirects, path traversal (/etc/passwd), XXE"}
        ]
        st.dataframe(pd.DataFrame(owasp_ref), use_container_width=True)


# ─────────────────────────────────────────────────────────────
# View 3: Dedicated Network / Nmap Scanner
# ─────────────────────────────────────────────────────────────

elif nav_choice == "🗺️ Network / Nmap Scanner":
    st.title("🗺️ Network Port Scanner (Nmap)")
    st.markdown("Detailed port scanning powered by the native Nmap engine with service and version detection.")

    nmap_ready, nmap_details = get_nmap_status()
    if not nmap_ready:
        st.warning(f"⚠️ {nmap_details} See the About section for deployment instructions.")

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            n_target = st.text_input("Target IP / Hostname:", placeholder="scanme.nmap.org or 192.168.1.1")
        with col2:
            n_ports = st.text_input("Port Range:", value="1-1024", help="e.g. 80,443 or 1-1024 or 21-25,80,443")
        with col3:
            n_type = st.selectbox(
                "Scan Type:",
                ["TCP Connect", "SYN Scan", "UDP Scan", "Service Version", "Fast Scan"],
                index=0,
                help="SYN & UDP scans require administrator/root privileges."
            )

        n_auth = st.checkbox("Authorized Target", key="n_auth", help="Confirm you are authorized to port scan this host.")

        b1, b2, _ = st.columns([1, 1, 4])
        with b1:
            run_nmap_btn = st.button("🚀 START NMAP SCAN", type="primary", use_container_width=True)
        with b2:
            clear_nmap_btn = st.button("🗑️ CLEAR", key="n_clear", use_container_width=True)

        st.caption("💡 **Tip:** 'TCP Connect' is unprivileged and works on standard user accounts and cloud containers without root.")
        st.markdown('</div>', unsafe_allow_html=True)

    if clear_nmap_btn:
        st.session_state.nmap_results = None
        st.session_state.nmap_report = None
        st.session_state.nmap_logs = []
        st.rerun()

    if run_nmap_btn:
        if not n_target.strip():
            st.error("Please enter a target IP or hostname.")
        elif not n_auth:
            st.error("Please confirm authorization before executing port scans.")
        else:
            try:
                target_clean = validate_target(n_target)
                ports_clean = validate_ports(n_ports)
                type_clean = validate_scan_type(n_type)

                n_logs = []
                log_view = st.empty()

                def n_logger(prefix, text, color):
                    n_logs.append((prefix, text, color))
                    tail = "\n".join(f"{p} {t}".strip() for p, t, c in n_logs[-12:])
                    log_view.code(tail, language="bash")

                n_rm = ReportManager()
                scanner = NmapScanner(n_logger, n_rm)

                with st.spinner(f"Running {type_clean} on {target_clean} (ports: {ports_clean})..."):
                    res = scanner.scan(target_clean, ports=ports_clean, scan_type=type_clean)

                st.session_state.nmap_results = res
                st.session_state.nmap_report = n_rm
                st.session_state.nmap_logs = n_logs

                if res.get("error"):
                    st.error(f"Nmap Error: {res.get('error')}")
                else:
                    st.success("Nmap scan completed!")
                st.rerun()

            except Exception as e:
                st.error(f"Input validation or scan failure: {e}")

    # Show Nmap Results
    if st.session_state.nmap_results:
        res = st.session_state.nmap_results
        hosts = res.get("hosts", [])

        if not hosts:
            st.info("No active hosts discovered or no open ports found in specified range.")
        else:
            for h in hosts:
                st.markdown(f"### Host: `{h.get('ip')}` ({h.get('hostname')}) — State: **{h.get('state')}**")
                table_rows = []
                for proto, p_list in h.get("protocols", {}).items():
                    for p in p_list:
                        table_rows.append({
                            "Port": p.get("port"),
                            "Protocol": proto.upper(),
                            "State": p.get("state"),
                            "Service": p.get("service"),
                            "Version": p.get("version")
                        })
                if table_rows:
                    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
                else:
                    st.caption("No open ports found on this protocol.")

        with st.expander("💻 Raw Terminal Output"):
            if st.session_state.nmap_logs:
                raw_text = "\n".join(f"{p} {t}".strip() for p, t, c in st.session_state.nmap_logs)
                st.code(raw_text, language="bash")


# ─────────────────────────────────────────────────────────────
# View 4: IP Intelligence
# ─────────────────────────────────────────────────────────────

elif nav_choice == "🌐 IP Intelligence":
    st.title("🌐 IP Intelligence & Geolocation")
    st.markdown("Query global IP intelligence databases for geolocation, ASN, ISP, and risk assessment.")

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        col1, col2 = st.columns([3, 1])
        with col1:
            ip_query = st.text_input("IP Address to Query:", placeholder="8.8.8.8 or 1.1.1.1")
        with col2:
            st.write("")
            st.write("")
            lookup_btn = st.button("🔍 LOOKUP IP", type="primary", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if lookup_btn:
        if not ip_query.strip():
            st.error("Please enter a valid IP address.")
        else:
            try:
                ip_clean = validate_target(ip_query)
                rm_dummy = ReportManager()
                intel = IPIntelligence(lambda p, t, c: None, rm_dummy)

                with st.spinner(f"Querying intelligence for {ip_clean}..."):
                    info = intel.scan(ip_clean)

                st.session_state.intel_results = info
                if info:
                    st.success("IP details retrieved!")
                else:
                    st.warning("No data returned or query rate-limited.")
            except Exception as e:
                st.error(f"Invalid IP address: {e}")

    if st.session_state.intel_results:
        data = st.session_state.intel_results
        loc_str = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
        isp_str = data.get('isp', 'Unknown')
        risk_str = "Medium (Proxy/Hosting)" if (data.get('proxy') or data.get('hosting')) else "Low"

        c1, c2, c3 = st.columns(3)
        c1.metric("📍 Location", loc_str)
        c2.metric("🌐 ISP", isp_str)
        c3.metric("⚠️ Risk Level", risk_str)

        st.markdown("### Full Geolocation & Network Attributes")
        st.json(data)


# ─────────────────────────────────────────────────────────────
# View 5: Reports & Export
# ─────────────────────────────────────────────────────────────

elif nav_choice == "📊 Reports & Export":
    st.title("📊 Security Reports & Export")
    st.markdown("Review, copy, and download HTML formatted reports from the most recent scan.")

    active_rm = st.session_state.full_report or st.session_state.vuln_report or st.session_state.nmap_report

    if not active_rm or not active_rm.has_data():
        st.info("No scan data available yet. Run a scan from the Reconnaissance, OWASP, or Network tabs to populate this report.")
    else:
        html_doc = active_rm.generate_html(target_label="CyberRecon Audit")
        plain_text = active_rm.get_plain_text()

        col_d1, col_d2, _ = st.columns([1, 1, 3])
        with col_d1:
            st.download_button(
                "📄 Download HTML Report",
                data=html_doc,
                file_name="CyberRecon_Report.html",
                mime="text/html",
                type="primary",
                use_container_width=True
            )
        with col_d2:
            st.download_button(
                "📋 Download Plaintext Report",
                data=plain_text,
                file_name="CyberRecon_Report.txt",
                mime="text/plain",
                use_container_width=True
            )

        st.markdown("### Report Preview")
        st.code(plain_text, language="text")


# ─────────────────────────────────────────────────────────────
# View 6: About & Deployment Guide
# ─────────────────────────────────────────────────────────────

elif nav_choice == "ℹ️ About":
    st.title("ℹ️ About CyberRecon v5.0")
    st.markdown("""
CyberRecon v5.0 is an integrated cybersecurity reconnaissance and automated vulnerability scanning suite designed for security auditors, penetration testers, and cybersecurity students.

### 🌟 Key Capabilities
- **🔍 HTTP Reconnaissance:** Response codes, server fingerprinting, and security header evaluation.
- **🔗 DNS Analysis:** IPv4/IPv6 resolution, canonical name tracking, and PTR reverse DNS lookup.
- **📋 Domain WHOIS:** Registrar identification, registration timestamps, and domain owner contacts.
- **📍 IP Intelligence:** IP geolocation, Autonomous System Numbers (ASN), and ISP identification.
- **🗺️ Nmap Network Scanning:** Integration with the native Nmap engine (TCP Connect, SYN, UDP, Service Version detection).
- **🛡️ OWASP Top 10 (2025):** Automated probes covering categories A01 through A10.
- **📊 Security Reporting:** Standalone HTML report export with styling and timestamped findings.

---

### 🚀 Deploying to Streamlit Community Cloud
To deploy this application to Streamlit Community Cloud and showcase it on your CV:

1. **Repository Structure:**
   Ensure your GitHub repository contains:
   ```text
   CyberRecon/
   ├── web_app.py           ← Main Streamlit application
   ├── scanner_engine.py    ← Unified scanning engine
   ├── requirements.txt     ← Python libraries (streamlit, python-nmap, etc.)
   ├── packages.txt         ← Linux system packages (nmap, whois)
   └── README.md            ← Documentation
   ```

2. **System Dependencies via `packages.txt`:**
   Streamlit Community Cloud runs on Debian-based Linux containers. By having `packages.txt` with:
   ```text
   nmap
   whois
   ```
   Streamlit Cloud automatically installs the native `nmap` binary into the container at build time.

3. **Cloud Privileges & Scan Types:**
   In cloud containers, apps execute without root/sudo privileges.
   - Use **`TCP Connect`** scan mode (`-sT`) for network scans on Streamlit Cloud.
   - SYN scans (`-sS`) require raw socket root access, which cloud container environments restrict for security.

---

### ⚖️ Legal Disclaimer
*This tool is intended strictly for authorized security auditing, educational research, and defensive assessment of systems you own or have explicit written permission to test. Unauthorized port scanning or vulnerability probing of third-party networks may violate applicable local and international computer crime legislation.*
""")
