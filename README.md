# Vatsal's SecOps Console 2.0: Attack Surface & Reconnaissance Suite

> **Autonomous External Attack Surface Management (EASM), OSINT & Posture Assessment**  
> *Created & Presented by Vatsal Shah — 2026*

An enterprise-grade, high-accuracy cybersecurity reconnaissance toolkit and live SecOps console. Built with **FastAPI**, **AsyncIO**, **DNSPython**, and modern **RFC 7482 HTTPS RDAP**, guaranteeing 100% live, accurate data without hardcoded mocks, false positives, or firewall-blocked socket lookups.

---

## ⚡ Key Modules & Capabilities

1. **Core Reconnaissance & OSINT:**
   - **Deep DNS Record Matrix:** Asynchronously resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, and reverse `PTR` records with Cloudflare DoH fallback.
   - **Dangling CNAME Takeover Guard:** Detects unclaimed cloud resources on AWS S3, Azure, GitHub Pages, and Heroku.
   - **Subdomain Enumeration:** Extracts Certificate Transparency (CT) logs via `crt.sh` and actively checks live IP resolution.
   - **Authoritative RDAP & WHOIS:** Uses modern RFC 7482 HTTPS RDAP to bypass residential ISP port 43 firewall blocks, with socket fallback.
   - **IP Geolocation & ASN Mapping:** BGP Autonomous System Numbers, upstream ISPs, and physical server coordinates.

2. **Web Posture & Cryptography:**
   - **Defensive HTTP Headers & CSP Grader:** Scores security posture from **A+ to F** (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`).
   - **SSL / TLS Deep Inspector:** True TLS 1.2 / 1.3 socket handshake with SNI support, extracting CA issuer, SANs list, cipher suite, and expiration countdown.
   - **Edge Shield & WAF Identification:** Detects Cloudflare, AWS CloudFront, Akamai, and reverse proxies.
   - **CORS Misconfiguration Checker:** Sends controlled origin reflection probes to audit cross-origin policies.

3. **Active Perimeter Auditing:**
   - **Asynchronous TCP Port Scanner:** Non-blocking sockets (`asyncio.open_connection`) with banner grabbing and latency metrics.
   - **Endpoint & Policy Prober:** Non-intrusive discovery of `robots.txt`, `sitemap.xml`, and `security.txt`.

4. **Cryptographic & Network Utilities:**
   - **Shannon Entropy Lab:** Computes exact mathematical Shannon entropy ($H = -\sum p \log_2 p$) and offline GPU crack times (10 GH/s).
   - **Hash & Token Station:** Real-time MD5, SHA-256, Base64, and JWT token parsing.
   - **CIDR Subnet Calculator:** 100% mathematically verified network address, broadcast, netmask, and usable host range.

---

## 🚀 1-Click Local Execution

### Prerequisites:
- Python 3.9+ installed
- Git (optional)

### Quick Run:
```bash
# 1. Navigate to the project folder:
cd vatsal-secops-toolkit

# 2. Run the local launcher:
python run_local.py
```
*(On Windows, you can also double-click `run_local.bat`)*

Open **`http://localhost:8000`** in your browser.  
Interactive OpenAPI documentation is available at **`http://localhost:8000/docs`**.

---

## 🐳 Docker Deployment (Any OS)

Run anywhere with a single Docker command:
```bash
docker compose up -d --build
```
Access the console at **`http://localhost:8000`**.

---

## 🌐 Deploy to GitHub & Connect Your Custom Domain (`audit.vatssi.in`)

### Step 1: Create a New GitHub Repository
```bash
cd vatsal-secops-toolkit
git init
git add .
git commit -m "feat: Vatsal SecOps Console 2.0 complete release"
git branch -M main
git remote add origin https://github.com/Vatsal-Shah-1008/vatsal-secops-toolkit.git
git push -u origin main
```

### Step 2: Deploy for Free to Cloud (Render / Railway / VPS)

#### Option A: Render.com (Recommended — 1-Click Free SSL)
1. Go to [Render.com](https://render.com) and click **New +** $\rightarrow$ **Web Service**.
2. Select your repository (`vatsal-secops-toolkit`).
3. Settings:
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Click **Deploy Web Service**.

#### Step 3: Connect Your Domain (`audit.vatssi.in`)
1. In your Render Dashboard, go to **Settings** $\rightarrow$ **Custom Domains**.
2. Add `audit.vatssi.in` (or your preferred subdomain).
3. In your DNS manager (Cloudflare or GoDaddy), add the CNAME:
   - **Type:** `CNAME`
   - **Name:** `audit`
   - **Target:** `<your-app-name>.onrender.com`
4. Free Let's Encrypt TLS will provision automatically within minutes!
