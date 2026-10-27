# Vatsal's SecOps Console 2.0: Attack Surface & Reconnaissance Suite

> **Autonomous External Attack Surface Management (EASM), OSINT & Posture Assessment**  
> *Created & Presented by Vatsal Shah — 2026*

An enterprise-grade, high-accuracy cybersecurity reconnaissance toolkit and live SecOps console. Built for **1-click direct deployment from GitHub to Cloudflare Pages** or local execution via **FastAPI / Python**.

---

## ⚡ Main Modules & Features

1. **Core Reconnaissance & OSINT:**
   - **Deep DNS Record Matrix:** Asynchronously resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA` via Cloudflare Global DoH Anycast.
   - **Dangling CNAME Takeover Guard:** Flags subdomains pointing to unclaimed cloud buckets (AWS S3, Azure, GitHub Pages, Heroku).
   - **Subdomain Enumeration:** Extracts Certificate Transparency (CT) logs via `crt.sh` and actively checks live Anycast resolution.
   - **Authoritative RDAP & WHOIS:** Uses modern RFC 7482 HTTPS RDAP to bypass residential ISP port 43 firewall blocks.
   - **IP Geolocation & ASN Mapping:** BGP Autonomous System Numbers, upstream ISPs, and physical server coordinates.

2. **Web Posture & Cryptography:**
   - **Defensive HTTP Headers & CSP Grader:** Scores security posture from **A+ to F** (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`).
   - **SSL / TLS Deep Inspector:** TLS 1.3 certificate status, SANs list, cipher suite, and expiration countdown.
   - **Edge Shield & WAF Identification:** Detects Cloudflare, AWS CloudFront, Akamai, and reverse proxies.

3. **Active Perimeter Auditing:**
   - **Asynchronous TCP Port Scanner:** Probes public edge ports with protocol identification.
   - **Live Telemetry & Output Log:** Retained terminal log drawer with syntax coloring, timestamps, clear, and copy capabilities.

4. **Cryptographic & Network Utilities:**
   - **Shannon Entropy Lab:** Computes exact mathematical Shannon entropy ($H = -\sum p \log_2 p$) and offline GPU crack times (10 GH/s).
   - **Hash & Token Station:** Real-time WebCrypto SHA-256 and Base64 conversion.
   - **CIDR Subnet Calculator:** Evaluates network address, broadcast, netmask, and usable host count.

---

## ☁️ Deploy Direct from GitHub to Cloudflare Pages (Recommended)

Since your domain (`audit.vatssi.in`) is already managed on Cloudflare, deploying via **Cloudflare Pages** is instantaneous, 100% free, and auto-updates whenever you push code to GitHub.

### Step 1: Push Project to Your GitHub Account
Open PowerShell or Terminal in the project directory:
```bash
cd vatsal-secops-toolkit

# Initialize Git and push
git init
git add .
git commit -m "feat: initial commit of Vatsal SecOps Console 2.0"
git branch -M main
git remote add origin https://github.com/Vatsal-Shah-1008/vatsal-secops-toolkit.git
git push -u origin main
```

### Step 2: Connect GitHub to Cloudflare Pages
1. Log in to your **[Cloudflare Dashboard](https://dash.cloudflare.com/)**.
2. Go to **Workers & Pages** in the left sidebar $\rightarrow$ Click **Create application** $\rightarrow$ Select the **Pages** tab.
3. Click **Connect to Git** and choose your repository: `Vatsal-Shah-1008/vatsal-secops-toolkit`.
4. Configure Build Settings:
   - **Project Name:** `vatsal-secops-toolkit` (or `audit-console`)
   - **Production Branch:** `main`
   - **Framework Preset:** `None`
   - **Build command:** *(Leave completely empty)*
   - **Build output directory:** `/` *(or leave blank)*
5. Click **Save and Deploy**. Cloudflare will build and deploy your site in ~15 seconds to a live URL like `https://vatsal-secops-toolkit.pages.dev`.

### Step 3: Bind Custom Domain (`audit.vatssi.in`)
1. In your Cloudflare Pages project page, click the **Custom domains** tab.
2. Click **Set up a custom domain**.
3. Enter your domain: `audit.vatssi.in`.
4. Click **Continue** $\rightarrow$ **Activate domain**.
5. Since `vatssi.in` is already on your Cloudflare account, Cloudflare will automatically configure the DNS CNAME record and provision an SSL certificate with zero manual DNS configuration required!

---

## 💻 Running on Localhost (Optional Python Mode)

You can also run the full FastAPI backend on your local computer:

```bash
# 1. Run with Python
python run_local.py

# Or on Windows, double-click:
run_local.bat
```

Open **`http://localhost:8000`** in your browser.
Interactive API documentation: **`http://localhost:8000/docs`**.
