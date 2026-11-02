# 🔒 CyberRecon v5.0 — Cybersecurity Vulnerability & Reconnaissance Suite

An integrated security auditing and reconnaissance suite offering both a modern **Streamlit Web Application** and a **Desktop Tkinter GUI**, powered by a decoupled core scanning engine.

---

## 🌟 Key Features

- **🔍 Full Reconnaissance:** HTTP header inspection, server fingerprinting, DNS resolution (A records + PTR), and WHOIS domain queries.
- **🌐 IP Intelligence & Geolocation:** Country, city, ISP, ASN, and proxy/hosting risk score.
- **🗺️ Integrated Nmap Port Scanner:** Native Nmap engine support (TCP Connect, SYN Scan, UDP Scan, Service & Version detection, Fast Scan).
- **🛡️ OWASP Top 10 (2025) Vulnerability Scanner:** Automated auditing for A01 through A10 (Access Control, Cryptographic Failures, Injection, Insecure Design, Misconfigurations, Outdated Components, Auth Failures, Software Integrity, Logging & Monitoring, SSRF).
- **📊 Formatted HTML & Text Reports:** One-click download of timestamped, styled security assessment reports.

---

## 📁 Project Structure

```text
CyberRecon_Final/
├── web_app.py           ← Streamlit Web Application (recommended for Cloud & CV)
├── Scanner.py           ← Desktop Tkinter Application
├── scanner_engine.py    ← Decoupled core scanning & vulnerability engine
├── packages.txt         ← Linux system dependencies (nmap, whois) for Streamlit Cloud
├── requirements.txt     ← Python package dependencies
├── README.md            ← Project documentation
├── app.py               ← Flask web alternative
└── templates/
    └── index.html       ← Flask frontend template
```

---

## 🚀 Running the Streamlit Web Application (Option 1 - Recommended)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Streamlit App
```bash
streamlit run web_app.py
```
The browser will automatically open at `http://localhost:8501`.

---

## 🖥️ Running the Desktop Tkinter Application (Option 2)

```bash
python Scanner.py
```

---

## ☁️ Deployment on Streamlit Community Cloud

This project is configured for one-click deployment on **Streamlit Community Cloud**:

1. **Push this repository to GitHub.**
2. Go to [share.streamlit.io](https://share.streamlit.io) and log in.
3. Click **New app** and select your repository and branch.
4. Set the **Main file path** to:
   ```text
   web_app.py
   ```
5. Click **Deploy**.

### How Nmap is configured in Streamlit Cloud:
- Streamlit Cloud runs on Debian-based Linux containers.
- The `packages.txt` file in the root directory instructs the build system to automatically install:
  - `nmap`
  - `whois`
- Because cloud containers run in unprivileged user mode without `root`/`sudo`, use **TCP Connect** (`-sT`) for network port scans in the cloud.

---

## 🗺️ Nmap Setup for Local Testing

| Operating System | Installation Instructions |
| :--- | :--- |
| **Windows** | Download and install from [https://nmap.org/download.html](https://nmap.org/download.html) and ensure `nmap.exe` is added to your system `PATH`. |
| **Linux (Debian/Ubuntu)** | `sudo apt update && sudo apt install nmap whois` |
| **macOS** | `brew install nmap whois` |

---

## ⚖️ Legal & Ethical Disclaimer
This project is developed for authorized security research, vulnerability auditing, and educational demonstrations only. Always obtain explicit written authorization from system owners before performing reconnaissance or vulnerability assessments.
