"""
CyberRecon Desktop v5.0 (Tkinter GUI)
====================================
Integrated: HTTP Recon + DNS + WHOIS + IP Intel
           + Nmap Port Scanner
           + OWASP Top 10 (2025) Vulnerability Scanner
           + HTML Report Export

The core scanning logic is decoupled into scanner_engine.py,
enabling unified scanning functionality across Desktop (Tkinter)
and Web (Streamlit) interfaces without duplication.
"""

import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import datetime
import threading
import requests
import webbrowser

from scanner_engine import (
    C,
    WHOIS_OK,
    NMAP_OK,
    norm_domain,
    norm_url,
    ReportManager,
    OWASPScanner,
    NmapScanner,
    ScanEngine,
)


class ColoredConsole(scrolledtext.ScrolledText):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        for name, col in [
            ('green', C['green']), ('cyan', C['cyan']), ('yellow', C['yellow']),
            ('red', C['red']), ('orange', C['orange']), ('muted', C['muted']), ('white', C['text'])
        ]:
            self.tag_config(name, foreground=col)
        self.config(state='disabled')

    def write(self, prefix, text, color):
        def _w():
            self.config(state='normal')
            if prefix:
                self.insert(tk.END, f"{prefix} ", 'cyan')
            tag = 'muted'
            if color == C['green']:
                tag = 'green'
            elif color == C['cyan']:
                tag = 'cyan'
            elif color == C['yellow']:
                tag = 'yellow'
            elif color == C['red']:
                tag = 'red'
            elif color == C['orange']:
                tag = 'orange'
            elif color == C['text']:
                tag = 'white'
            self.insert(tk.END, f"{text}\n", tag)
            self.see(tk.END)
            self.config(state='disabled')
        self.after(0, _w)

    def clear(self):
        self.config(state='normal')
        self.delete(1.0, tk.END)
        self.config(state='disabled')


class FlatBtn(tk.Button):
    def __init__(self, parent, text, cmd=None, bg='cyan', **kw):
        self._bg = C.get(bg, bg)
        cfg = dict(
            text=text, command=cmd, bg=self._bg, fg=C['bg_dark'],
            font=('Segoe UI', 10, 'bold'), relief=tk.FLAT, cursor='hand2',
            padx=16, pady=7, activebackground=self._bg, activeforeground=C['bg_dark']
        )
        cfg.update(kw)
        super().__init__(parent, **cfg)
        self.bind('<Enter>', lambda e: self.config(bg=self._lx(self._bg)))
        self.bind('<Leave>', lambda e: self.config(bg=self._bg))

    def _lx(self, h):
        h = h.lstrip('#')
        r, g, b = (int(h[i:i+2], 16) for i in (0, 2, 4))
        return f'#{min(255, int(r*1.2)):02x}{min(255, int(g*1.2)):02x}{min(255, int(b*1.2)):02x}'


class InfoCard(tk.Frame):
    def __init__(self, parent, title, val="N/A", icon="📊"):
        super().__init__(parent, bg=C['bg_panel'])
        tk.Label(self, text=icon, font=('Segoe UI', 20), bg=C['bg_panel'], fg=C['cyan']).pack(pady=(7, 3))
        tk.Label(self, text=title, font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['muted']).pack()
        self.v = tk.Label(self, text=val, font=('Segoe UI', 12, 'bold'), bg=C['bg_panel'], fg=C['green'])
        self.v.pack(pady=(3, 7))

    def update(self, v):
        self.v.config(text=v)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberRecon v5.0 — OWASP 2025 + Nmap Suite")
        self.geometry("1440x900")
        self.minsize(1100, 700)
        self.configure(bg=C['bg_dark'])
        self.scanning = False
        self.net_scanning = False
        self.rm = ReportManager()
        self._ui()
        self.engine = ScanEngine(self.log, self.rm)

    def _ui(self):
        hdr = tk.Frame(self, bg=C['bg_darker'], height=68)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        tf = tk.Frame(hdr, bg=C['bg_darker'])
        tf.pack(side='left', padx=18, pady=10)
        tk.Label(tf, text="🔒 CYBERRECON v5.0", font=('Segoe UI', 17, 'bold'), bg=C['bg_darker'], fg=C['cyan']).pack(side='left')
        tk.Label(tf, text="  OWASP 2025 + Nmap Security Suite", font=('Segoe UI', 9), bg=C['bg_darker'], fg=C['muted']).pack(side='left')
        sf = tk.Frame(hdr, bg=C['bg_darker'])
        sf.pack(side='right', padx=18)
        self.sl = tk.Label(sf, text="● IDLE", font=('Segoe UI', 12, 'bold'), bg=C['bg_darker'], fg=C['cyan'])
        self.sl.pack()
        main = tk.Frame(self, bg=C['bg_dark'])
        main.pack(fill='both', expand=True, padx=14, pady=14)
        self._sidebar(main)
        c = tk.Frame(main, bg=C['bg_dark'])
        c.pack(side='right', fill='both', expand=True, padx=(10, 0))
        self.pnl = {}
        self._p_scanner(c)
        self._p_owasp(c)
        self._p_network(c)
        self._p_intel(c)
        self._p_reports(c)
        self._p_about(c)
        self._p_dev(c)
        self._show("Scanner")

    def _sidebar(self, parent):
        sb = tk.Frame(parent, bg=C['bg_panel'], width=208)
        sb.pack(side='left', fill='y')
        sb.pack_propagate(False)
        tk.Label(sb, text="NAVIGATION", font=('Segoe UI', 9, 'bold'), bg=C['bg_panel'], fg=C['muted'], anchor='w').pack(fill='x', padx=16, pady=(16, 8))
        nav = [
            ("🔍 Scanner", "Scanner"),
            ("🛡️ OWASP 2025", "OWASP"),
            ("🗺️ Network/Nmap", "Network"),
            ("🌐 Intelligence", "Intel"),
            ("📊 Reports", "Reports"),
            ("ℹ️ About", "About"),
            ("👨‍💻 Developer", "Dev")
        ]
        for lbl, sec in nav:
            fg = C['red'] if sec == "OWASP" else C['text']
            b = tk.Button(
                sb, text=lbl, bg=C['bg_panel'], fg=fg, font=('Segoe UI', 11), relief=tk.FLAT,
                cursor='hand2', anchor='w', padx=16, pady=10, command=lambda s=sec: self._show(s)
            )
            b.pack(fill='x', padx=7, pady=2)
            b.bind('<Enter>', lambda e, bb=b: bb.config(bg=C['bg_dark'], fg=C['cyan']))
            b.bind('<Leave>', lambda e, bb=b, f=fg: bb.config(bg=C['bg_panel'], fg=f))

    def _show(self, name):
        for p in self.pnl.values():
            p.pack_forget()
        if name in self.pnl:
            self.pnl[name].pack(fill='both', expand=True)

    def _lbl(self, p, t, sz=10, bold=False, fg=None):
        return tk.Label(p, text=t, font=('Segoe UI', sz, 'bold' if bold else 'normal'), bg=C['bg_dark'], fg=fg or C['text'])

    def _pl(self, p, t):
        tk.Label(p, text=t, font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['muted']).pack(anchor='w', padx=14, pady=(10, 4))

    def _con(self, parent):
        f = tk.Frame(parent, bg=C['bg_panel'])
        f.pack(fill='both', expand=True)
        c = ColoredConsole(f, bg=C['bg_darker'], fg=C['text'], font=('Consolas', 10), relief=tk.FLAT, padx=10, pady=10)
        c.pack(fill='both', expand=True, padx=2, pady=2)
        return c

    def _p_scanner(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["Scanner"] = p
        self._lbl(p, "Reconnaissance Scanner", 16, True).pack(anchor='w', pady=(0, 14))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x', pady=(0, 14))
        self._pl(card, "Target URL / Domain / IP")
        self.te = tk.Entry(card, font=('Consolas', 12), bg=C['bg_darker'], fg=C['muted'], relief=tk.FLAT, insertbackground=C['cyan'])
        self.te.pack(fill='x', padx=14, pady=(0, 8), ipady=8)
        self.te.insert(0, "Enter domain, IP, or URL...")
        self.te.bind('<FocusIn>', lambda e: (self.te.delete(0, tk.END), self.te.config(fg=C['text'])) if self.te.get().startswith("Enter") else None)
        self.te.bind('<FocusOut>', lambda e: (self.te.insert(0, "Enter domain, IP, or URL..."), self.te.config(fg=C['muted'])) if not self.te.get() else None)
        opt = tk.Frame(card, bg=C['bg_panel'])
        opt.pack(fill='x', padx=14, pady=(0, 8))
        self.rv = tk.BooleanVar(value=True)
        self.rn = tk.BooleanVar(value=False)
        for t, v, fg in [("  Include OWASP 2025", self.rv, C['red']), ("  Include Nmap Scan", self.rn, C['cyan'])]:
            tk.Checkbutton(
                opt, text=t, variable=v, bg=C['bg_panel'], fg=fg, font=('Segoe UI', 10, 'bold'),
                selectcolor=C['bg_darker'], activebackground=C['bg_panel']
            ).pack(side='left', padx=(0, 18))
        ns = tk.Frame(card, bg=C['bg_panel'])
        ns.pack(fill='x', padx=14, pady=(0, 8))
        tk.Label(ns, text="Ports:", font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['muted']).pack(side='left')
        self.np = tk.Entry(ns, font=('Consolas', 10), bg=C['bg_darker'], fg=C['text'], relief=tk.FLAT, insertbackground=C['cyan'], width=12)
        self.np.pack(side='left', padx=(4, 14), ipady=3)
        self.np.insert(0, "1-1024")
        tk.Label(ns, text="Type:", font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['muted']).pack(side='left')
        self.nt = tk.StringVar(value="TCP Connect")
        ttk.Combobox(
            ns, textvariable=self.nt, values=["TCP Connect", "SYN Scan", "UDP Scan", "Service Version", "Fast Scan"],
            state='readonly', font=('Consolas', 9), width=15
        ).pack(side='left', padx=(4, 0), ipady=3)
        br = tk.Frame(card, bg=C['bg_panel'])
        br.pack(fill='x', padx=14, pady=(0, 12))
        self.sb2 = FlatBtn(br, "▶ START SCAN", cmd=self.start_scan, bg='green')
        self.sb2.pack(side='left', padx=(0, 7))
        FlatBtn(br, "🗑️ CLEAR", cmd=self.clear_out, bg='red').pack(side='left', padx=(0, 7))
        FlatBtn(br, "💾 SAVE REPORT", cmd=self.save_report, bg='cyan').pack(side='left')
        self.pb = ttk.Progressbar(card, mode='indeterminate')
        self.pb.pack(fill='x', padx=14, pady=(0, 12))
        self._lbl(p, "Console Output", 12, True).pack(anchor='w', pady=(0, 7))
        self.con = self._con(p)

    def _p_owasp(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["OWASP"] = p
        tk.Label(p, text="🛡️ OWASP Top 10 (2025) Vulnerability Scanner", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['red']).pack(anchor='w', pady=(0, 12))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x', pady=(0, 10))
        self._pl(card, "Quick Standalone Scan:")
        qr = tk.Frame(card, bg=C['bg_panel'])
        qr.pack(fill='x', padx=14, pady=(0, 10))
        self.vte = tk.Entry(qr, font=('Consolas', 11), bg=C['bg_darker'], fg=C['text'], relief=tk.FLAT, insertbackground=C['red'])
        self.vte.pack(side='left', fill='x', expand=True, ipady=6)
        self.vte.insert(0, "https://example.com")
        FlatBtn(qr, "🔍 SCAN VULNS", cmd=self.vuln_standalone, bg='red').pack(side='left', padx=(7, 0))
        FlatBtn(qr, "🗑️ CLEAR", cmd=lambda: self.vc.clear(), bg='yellow').pack(side='left', padx=(6, 0))
        self.vp = ttk.Progressbar(card, mode='indeterminate')
        self.vp.pack(fill='x', padx=14, pady=(0, 10))
        leg = tk.Frame(p, bg=C['bg_darker'])
        leg.pack(fill='x', pady=(0, 8))
        for lbl, fg in [("🔴 CRITICAL", C['red']), ("🟠 HIGH", C['orange']), ("🟡 MEDIUM", C['yellow']), ("🟢 LOW", C['green']), ("✅ PASS", C['cyan'])]:
            tk.Label(leg, text=lbl, font=('Segoe UI', 9, 'bold'), bg=C['bg_darker'], fg=fg).pack(side='left', padx=12, pady=5)
        cc = tk.Frame(p, bg=C['bg_panel'])
        cc.pack(fill='x', pady=(0, 8))
        tk.Label(cc, text="OWASP 2025 Checks:", font=('Segoe UI', 10, 'bold'), bg=C['bg_panel'], fg=C['cyan']).pack(anchor='w', padx=14, pady=(10, 6))
        chks = [
            ("A01", "Broken Access Control", "Admin paths, dir listing, CSRF, IDOR, verb tampering"),
            ("A02", "Crypto Failures", "SSL/TLS, weak ciphers, HTTP→HTTPS, insecure cookies"),
            ("A03", "Injection", "SQLi, XSS, SSTI, Command Injection, NoSQL"),
            ("A04", "Insecure Design", "Stack traces, debug mode, rate limiting, enumeration"),
            ("A05", "Misconfiguration", "HSTS/CSP/XFO, CORS, TRACE, tech disclosure, sensitive files"),
            ("A06", "Outdated Components", "CVE sigs, jQuery/Bootstrap/CMS, dependency files"),
            ("A07", "Auth Failures", "Default creds, session cookies, weak tokens, token-in-URL"),
            ("A08", "Integrity Failures", "SRI, deserialization, CI/CD configs"),
            ("A09", "Logging Failures", "security.txt, log files, WAF detection"),
            ("A10", "SSRF", "SSRF, Open Redirect, Path Traversal, XXE")
        ]
        cf = tk.Frame(cc, bg=C['bg_panel'])
        cf.pack(fill='x', padx=14, pady=(0, 10))
        for aid, name, desc in chks:
            row = tk.Frame(cf, bg=C['bg_panel'])
            row.pack(fill='x', pady=1)
            tk.Label(row, text=f"{aid}:2025", font=('Consolas', 9, 'bold'), bg=C['bg_panel'], fg=C['cyan'], width=10, anchor='w').pack(side='left')
            tk.Label(row, text=name, font=('Segoe UI', 9, 'bold'), bg=C['bg_panel'], fg=C['text'], width=26, anchor='w').pack(side='left')
            tk.Label(row, text=desc, font=('Segoe UI', 8), bg=C['bg_panel'], fg=C['muted'], anchor='w').pack(side='left')
        tk.Label(p, text="Vulnerability Findings", font=('Segoe UI', 12, 'bold'), bg=C['bg_dark'], fg=C['red']).pack(anchor='w', pady=(0, 6))
        self.vc = self._con(p)
        self.vc.write("[INFO]", "Run a scan from Scanner tab or use Quick Scan above.", C['cyan'])

    def _p_network(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["Network"] = p
        tk.Label(p, text="🗺️ Network Port Scanner (Nmap)", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 14))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x', pady=(0, 14))
        self._pl(card, "Target IP / Hostname")
        self.ntt = tk.Entry(card, font=('Consolas', 11), bg=C['bg_darker'], fg=C['text'], relief=tk.FLAT, insertbackground=C['cyan'])
        self.ntt.pack(fill='x', padx=14, pady=(0, 8), ipady=7)
        self._pl(card, "Port Range")
        self.npt = tk.Entry(card, font=('Consolas', 11), bg=C['bg_darker'], fg=C['text'], relief=tk.FLAT, insertbackground=C['cyan'])
        self.npt.pack(fill='x', padx=14, pady=(0, 8), ipady=7)
        self.npt.insert(0, "1-1024")
        self._pl(card, "Scan Type")
        self.nst = tk.StringVar(value="TCP Connect")
        ttk.Combobox(
            card, textvariable=self.nst, values=["TCP Connect", "SYN Scan", "UDP Scan", "Service Version", "Fast Scan"],
            state='readonly', font=('Consolas', 10)
        ).pack(fill='x', padx=14, pady=(0, 12), ipady=4)
        br = tk.Frame(card, bg=C['bg_panel'])
        br.pack(fill='x', padx=14, pady=(0, 12))
        self.nb = FlatBtn(br, "🚀 START NMAP SCAN", cmd=self.net_scan, bg='green')
        self.nb.pack(side='left', padx=(0, 7))
        FlatBtn(br, "🗑️ CLEAR", cmd=lambda: self.nr.clear(), bg='red').pack(side='left')
        tk.Label(
            card, text="💡 SYN scan needs admin/root. TCP Connect works for normal users.",
            font=('Segoe UI', 8), bg=C['bg_darker'], fg=C['muted']
        ).pack(fill='x', padx=14, pady=(0, 10))
        tk.Label(p, text="Nmap Results", font=('Segoe UI', 12, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 7))
        self.nr = self._con(p)
        self.nr.write("[INFO]", "Enter target above and click START NMAP SCAN.", C['cyan'])

    def _p_intel(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["Intel"] = p
        tk.Label(p, text="🌐 IP Intelligence & Geolocation", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 14))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x', pady=(0, 14))
        self._pl(card, "IP Address")
        ir = tk.Frame(card, bg=C['bg_panel'])
        ir.pack(fill='x', padx=14, pady=(0, 12))
        self.iie = tk.Entry(ir, font=('Consolas', 11), bg=C['bg_darker'], fg=C['text'], relief=tk.FLAT, insertbackground=C['cyan'])
        self.iie.pack(side='left', fill='x', expand=True, ipady=7)
        self.iie.insert(0, "Enter IP...")
        FlatBtn(ir, "🔍 LOOKUP", cmd=self.ip_lookup, bg='cyan').pack(side='left', padx=(8, 0))
        cr = tk.Frame(p, bg=C['bg_dark'])
        cr.pack(fill='x', pady=(0, 14))
        self.ic_loc = InfoCard(cr, "Location", "Unknown", "📍")
        self.ic_loc.pack(side='left', padx=(0, 8), ipadx=14, ipady=6)
        self.ic_isp = InfoCard(cr, "ISP", "Unknown", "🌐")
        self.ic_isp.pack(side='left', padx=(0, 8), ipadx=14, ipady=6)
        self.ic_risk = InfoCard(cr, "Risk", "Unknown", "⚠️")
        self.ic_risk.pack(side='left', ipadx=14, ipady=6)
        tk.Label(p, text="Full Details", font=('Segoe UI', 12, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 7))
        df = tk.Frame(p, bg=C['bg_panel'])
        df.pack(fill='both', expand=True)
        self.iid = scrolledtext.ScrolledText(df, bg=C['bg_darker'], fg=C['text'], font=('Consolas', 10), relief=tk.FLAT, padx=10, pady=10)
        self.iid.pack(fill='both', expand=True, padx=2, pady=2)

    def _p_reports(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["Reports"] = p
        tk.Label(p, text="📊 Reports & Export", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 14))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x', pady=(0, 14))
        tk.Label(card, text="Export Options", font=('Segoe UI', 10), bg=C['bg_panel'], fg=C['muted']).pack(anchor='w', padx=14, pady=(12, 8))
        br = tk.Frame(card, bg=C['bg_panel'])
        br.pack(fill='x', padx=14, pady=(0, 12))
        FlatBtn(br, "📄 Export HTML", cmd=self.save_report, bg='cyan').pack(side='left', padx=(0, 7))
        FlatBtn(br, "📋 Copy to Clipboard", cmd=self.copy_report, bg='green').pack(side='left', padx=(0, 7))
        FlatBtn(br, "🔄 Refresh", cmd=self.refresh_report, bg='yellow').pack(side='left')
        tk.Label(p, text="Report Preview", font=('Segoe UI', 12, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 7))
        pf = tk.Frame(p, bg=C['bg_panel'])
        pf.pack(fill='both', expand=True)
        self.rp_view = scrolledtext.ScrolledText(pf, bg=C['bg_darker'], fg=C['text'], font=('Consolas', 9), relief=tk.FLAT, padx=10, pady=10)
        self.rp_view.pack(fill='both', expand=True, padx=2, pady=2)
        self.rp_view.insert('1.0', "No scan data yet.\n\nRun a scan to populate.")

    def _p_about(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["About"] = p
        tk.Label(p, text="ℹ️ About CyberRecon v5.0", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 14))
        af = tk.Frame(p, bg=C['bg_panel'])
        af.pack(fill='both', expand=True)
        at = scrolledtext.ScrolledText(af, bg=C['bg_darker'], fg=C['muted'], font=('Consolas', 9), relief=tk.FLAT, padx=14, pady=14)
        at.pack(fill='both', expand=True, padx=12, pady=12)
        at.insert('1.0', """CyberRecon v5.0 — Integrated Security Suite

FEATURES:
  🔍 HTTP Recon        Status codes, headers, server fingerprinting
  🔗 DNS               A records, PTR lookups
  📋 WHOIS             Domain registration info
  📍 IP Intelligence   Geolocation, ISP, ASN
  🗺️ Nmap             TCP/SYN/UDP/Version port scanning
  🛡️ OWASP 2025       Full A01–A10 automated vulnerability scan
  📊 HTML Report       Complete formatted export

OWASP TOP 10 (2025):
  A01 Broken Access Control    A02 Cryptographic Failures
  A03 Injection                A04 Insecure Design
  A05 Security Misconfiguration A06 Vulnerable Components
  A07 Auth Failures            A08 Software Integrity
  A09 Logging Failures         A10 SSRF

INSTALL:
  pip install requests python-whois python-nmap urllib3
  nmap binary: https://nmap.org/download.html

DISCLAIMER: For authorized testing only. © 2025 KAVI & MOKSH""")
        at.config(state='disabled')

    def _p_dev(self, c):
        p = tk.Frame(c, bg=C['bg_dark'])
        self.pnl["Dev"] = p
        tk.Label(p, text="👨‍💻 Developer Info", font=('Segoe UI', 15, 'bold'), bg=C['bg_dark'], fg=C['text']).pack(anchor='w', pady=(0, 14))
        card = tk.Frame(p, bg=C['bg_panel'])
        card.pack(fill='x')
        pf = tk.Frame(card, bg=C['bg_panel'])
        pf.pack(fill='x', padx=26, pady=26)
        tk.Label(pf, text="👨‍💻", font=('Segoe UI', 40), bg=C['bg_panel'], fg=C['cyan']).pack(pady=(0, 10))
        tk.Label(pf, text="KAVI AND MOKSH", font=('Segoe UI', 17, 'bold'), bg=C['bg_panel'], fg=C['text']).pack()
        tk.Label(pf, text="CYBER SECURITY STUDENTS", font=('Segoe UI', 10), bg=C['bg_panel'], fg=C['muted']).pack(pady=(4, 16))
        tk.Frame(card, bg=C['border'], height=1).pack(fill='x', padx=26)
        cf = tk.Frame(card, bg=C['bg_panel'])
        cf.pack(fill='x', padx=26, pady=16)
        tk.Label(cf, text="📧 Contact:", font=('Segoe UI', 11, 'bold'), bg=C['bg_panel'], fg=C['cyan']).pack(anchor='w', pady=(0, 8))
        for em in ["PATELKAVI060@GMAIL.COM", "PMOKSH1850@GMAIL.COM"]:
            r = tk.Frame(cf, bg=C['bg_panel'])
            r.pack(fill='x', pady=2)
            tk.Label(r, text="Email:", font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['muted'], width=8, anchor='w').pack(side='left')
            tk.Label(r, text=em, font=('Segoe UI', 9), bg=C['bg_panel'], fg=C['text']).pack(side='left')
        br = tk.Frame(card, bg=C['bg_panel'])
        br.pack(fill='x', padx=26, pady=(0, 18))
        FlatBtn(br, "📧 Email", cmd=lambda: webbrowser.open('mailto:PATELKAVI060@GMAIL.COM'), bg='cyan').pack(side='left', padx=(0, 7))
        FlatBtn(br, "🐙 GitHub", cmd=lambda: webbrowser.open('https://github.com'), bg='green').pack(side='left')

    def log(self, prefix, text, color):
        self.con.write(prefix, text, color)
        if prefix in (
            "[VULN]", "[OK]", "[A01]", "[A02]", "[A03]", "[A04]", "[A05]",
            "[A06]", "[A07]", "[A08]", "[A09]", "[A10]", "[OWASP]", "[FILES]", "[PORTS]"
        ):
            self.vc.write(prefix, text, color)

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Busy", "Scan in progress")
            return
        t = self.te.get().strip()
        if not t or t.startswith("Enter"):
            messagebox.showerror("Error", "Enter a target")
            return
        self.rm.clear()
        self.con.clear()
        self.vc.clear()
        self.scanning = True
        self.sl.config(text="● SCANNING", fg=C['green'])
        self.sb2.config(state='disabled')
        self.pb.start(10)
        threading.Thread(
            target=self._scan_thread,
            args=(t, self.rv.get(), self.rn.get(), self.np.get().strip() or "1-1024", self.nt.get()),
            daemon=True
        ).start()

    def _scan_thread(self, t, rv, rn, ports, ntype):
        try:
            self.engine.scan(t, run_vuln=rv, run_nmap=rn, nmap_ports=ports, nmap_type=ntype)
        except Exception as e:
            self.log("[ERROR]", f"Scan failed: {e}", C['red'])
        finally:
            self.after(0, self._scan_done)

    def _scan_done(self):
        self.scanning = False
        self.sl.config(text="● IDLE", fg=C['cyan'])
        self.sb2.config(state='normal')
        self.pb.stop()

    def vuln_standalone(self):
        t = self.vte.get().strip()
        if not t or t == "https://example.com":
            messagebox.showerror("Error", "Enter a target")
            return
        if getattr(self, '_vbusy', False):
            messagebox.showwarning("Busy", "Vuln scan in progress")
            return
        self._vbusy = True
        self.vp.start(10)
        self.vc.clear()
        rp = ReportManager()
        sc = OWASPScanner(lambda p, t, c: self.vc.write(p, t, c), rp)

        def run():
            try:
                sc.run(t)
                for line in rp.data.get("OWASP Vulnerabilities", []):
                    self.rm.log("OWASP Vulnerabilities", line)
            except Exception as e:
                self.vc.write("[ERROR]", str(e), C['red'])
            finally:
                self._vbusy = False
                self.after(0, self.vp.stop)

        threading.Thread(target=run, daemon=True).start()

    def net_scan(self):
        if self.net_scanning:
            messagebox.showwarning("Busy", "Nmap scan in progress")
            return
        t = self.ntt.get().strip()
        if not t:
            messagebox.showerror("Error", "Enter a target")
            return
        ports = self.npt.get().strip() or "1-1024"
        stype = self.nst.get()
        self.net_scanning = True
        self.nb.config(state='disabled', text="⏳ SCANNING...")
        self.nr.clear()
        self.nr.write("[INFO]", f"Nmap scan: {t} — ports {ports} — {stype}", C['cyan'])
        rp = ReportManager()
        sc = NmapScanner(lambda p, t, c: self.nr.write(p, t, c), rp)

        def run():
            try:
                sc.scan(t, ports, stype)
                for line in rp.data.get("Nmap", []):
                    self.rm.log("Nmap", line)
            except Exception as e:
                self.nr.write("[ERROR]", str(e), C['red'])
            finally:
                self.net_scanning = False
                self.after(0, lambda: self.nb.config(state='normal', text="🚀 START NMAP SCAN"))

        threading.Thread(target=run, daemon=True).start()

    def ip_lookup(self):
        ip = self.iie.get().strip()
        if not ip or ip.startswith("Enter"):
            messagebox.showerror("Error", "Enter an IP")
            return
        self.iid.delete(1.0, tk.END)
        self.iid.insert(tk.END, f"[*] Looking up {ip}...\n\n")

        def run():
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if r.get('status') == 'success':
                    self.after(0, lambda: self.ic_loc.update(f"{r.get('city','?')}, {r.get('country','?')}"))
                    self.after(0, lambda: self.ic_isp.update(r.get('isp', '?')))
                    risk = "Medium" if r.get('proxy') or r.get('hosting') else "Low"
                    self.after(0, lambda: self.ic_risk.update(risk))
                    self.iid.delete(1.0, tk.END)
                    for k, v in r.items():
                        self.iid.insert(tk.END, f"{k}: {v}\n")
                else:
                    self.iid.insert(tk.END, "[!] Lookup failed\n")
            except Exception as e:
                self.iid.insert(tk.END, f"[!] Error: {e}\n")

        threading.Thread(target=run, daemon=True).start()

    def clear_out(self):
        self.con.clear()
        self.rm.clear()

    def copy_report(self):
        if not self.rm.has_data():
            messagebox.showerror("Error", "No data")
            return
        txt = ""
        for s, lines in self.rm.data.items():
            if lines:
                txt += f"\n{'='*60}\n{s}\n{'='*60}\n" + "\n".join(lines) + "\n"
        self.clipboard_clear()
        self.clipboard_append(txt)
        messagebox.showinfo("Copied", "Report copied!")

    def refresh_report(self):
        self.rp_view.delete(1.0, tk.END)
        if not self.rm.has_data():
            self.rp_view.insert(tk.END, "No data.\nRun a scan first.")
            return
        for s, lines in self.rm.data.items():
            if lines:
                self.rp_view.insert(tk.END, f"\n{'='*60}\n{s}\n{'='*60}\n" + "\n".join(lines) + "\n")

    def save_report(self):
        if not self.rm.has_data():
            messagebox.showerror("Error", "No data")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML", "*.html"), ("All", "*.*")], title="Save Report"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.rm.generate_html())
            messagebox.showinfo("Saved", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed:\n{e}")


if __name__ == "__main__":
    App().mainloop()
