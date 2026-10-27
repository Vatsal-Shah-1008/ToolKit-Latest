import httpx
from typing import Dict, Any, List

class HeadersEngine:
    @classmethod
    async def analyze(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        url = f"https://{clean_domain}"

        results: Dict[str, Any] = {
            "domain": clean_domain,
            "url_probed": url,
            "status_code": 0,
            "posture_score": 0,
            "posture_grade": "F",
            "detected_waf": "None Detected",
            "server_software": "Hidden / Not Disclosed",
            "headers_present": {},
            "headers_missing": [],
            "detailed_findings": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying HTTP headers and defensive posture for: {url}")

        raw_headers = {}
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                res = await client.get(url, headers={"User-Agent": "SecOps-Auditor/2.5 (Mozilla/5.0)"})
                results["status_code"] = res.status_code
                raw_headers = {k.lower(): v for k, v in res.headers.items()}
                results["logs"].append(f"[+] HTTP Handshake succeeded. Status code: {res.status_code}")
        except Exception as e:
            # Try HTTP fallback if HTTPS fails
            try:
                url_http = f"http://{clean_domain}"
                async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                    res = await client.get(url_http, headers={"User-Agent": "SecOps-Auditor/2.5"})
                    results["status_code"] = res.status_code
                    raw_headers = {k.lower(): v for k, v in res.headers.items()}
                    results["logs"].append(f"[!] Target HTTPS failed; probed HTTP fallback. Status: {res.status_code}")
            except Exception as e2:
                results["logs"].append(f"[-] HTTP request failed: {str(e2)}")
                return results

        # WAF Detection Signatures
        waf_signatures = {
            "cf-ray": "Cloudflare Edge & WAF",
            "x-amz-cf-id": "AWS CloudFront WAF",
            "x-akamai-transformed": "Akamai Intelligent Edge",
            "x-sucuri-id": "Sucuri CloudProxy",
            "x-azure-ref": "Microsoft Azure Front Door",
            "x-fastly-request-id": "Fastly CDN / WAF",
            "server": None
        }

        for header_key, waf_name in waf_signatures.items():
            if header_key in raw_headers:
                if waf_name:
                    results["detected_waf"] = waf_name
                    results["logs"].append(f"[+] Identified Edge Shield: {waf_name}")
                    break
                elif header_key == "server":
                    srv = raw_headers["server"].lower()
                    if "cloudflare" in srv:
                        results["detected_waf"] = "Cloudflare Edge Protection"
                    elif "akamai" in srv:
                        results["detected_waf"] = "Akamai CDN / WAF"

        if "server" in raw_headers:
            results["server_software"] = raw_headers["server"]
            results["logs"].append(f"[+] Server Header Disclosed: {results['server_software']}")

        # Header Security Matrix & Scoring
        # Total possible score: 100
        score = 0

        # 1. HSTS (25 pts)
        if "strict-transport-security" in raw_headers:
            hsts_val = raw_headers["strict-transport-security"]
            pts = 20
            if "preload" in hsts_val:
                pts = 25
            score += pts
            results["headers_present"]["Strict-Transport-Security"] = hsts_val
            results["detailed_findings"].append({
                "header": "Strict-Transport-Security (HSTS)",
                "status": "PASS",
                "value": hsts_val,
                "importance": "Enforces TLS encryption and prevents SSL-stripping MITM attacks."
            })
            results["logs"].append(f"[+] PASS: HSTS present ({hsts_val})")
        else:
            results["headers_missing"].append("Strict-Transport-Security")
            results["detailed_findings"].append({
                "header": "Strict-Transport-Security (HSTS)",
                "status": "FAIL",
                "value": "Missing",
                "importance": "Vulnerable to downgrade attacks over insecure HTTP."
            })

        # 2. Content-Security-Policy (25 pts)
        if "content-security-policy" in raw_headers:
            csp_val = raw_headers["content-security-policy"]
            score += 25
            results["headers_present"]["Content-Security-Policy"] = csp_val[:120] + "..." if len(csp_val) > 120 else csp_val
            results["detailed_findings"].append({
                "header": "Content-Security-Policy (CSP)",
                "status": "PASS",
                "value": csp_val[:80] + "...",
                "importance": "Restricts script execution contexts and mitigates XSS attacks."
            })
            results["logs"].append(f"[+] PASS: Content-Security-Policy enabled.")
        else:
            results["headers_missing"].append("Content-Security-Policy")
            results["detailed_findings"].append({
                "header": "Content-Security-Policy (CSP)",
                "status": "FAIL",
                "value": "Missing",
                "importance": "Significantly increases vulnerability to Cross-Site Scripting (XSS)."
            })

        # 3. X-Frame-Options (20 pts)
        if "x-frame-options" in raw_headers:
            xfo_val = raw_headers["x-frame-options"].upper()
            score += 20
            results["headers_present"]["X-Frame-Options"] = xfo_val
            results["detailed_findings"].append({
                "header": "X-Frame-Options",
                "status": "PASS",
                "value": xfo_val,
                "importance": "Defends against clickjacking by preventing framing inside iframes."
            })
            results["logs"].append(f"[+] PASS: X-Frame-Options configured ({xfo_val})")
        else:
            results["headers_missing"].append("X-Frame-Options")
            results["detailed_findings"].append({
                "header": "X-Frame-Options",
                "status": "FAIL",
                "value": "Missing",
                "importance": "Vulnerable to UI redressing and clickjacking attacks."
            })

        # 4. X-Content-Type-Options (15 pts)
        if "x-content-type-options" in raw_headers:
            xcto_val = raw_headers["x-content-type-options"]
            score += 15
            results["headers_present"]["X-Content-Type-Options"] = xcto_val
            results["detailed_findings"].append({
                "header": "X-Content-Type-Options",
                "status": "PASS",
                "value": xcto_val,
                "importance": "Prevents MIME-type confusion and drive-by download attacks."
            })
            results["logs"].append(f"[+] PASS: X-Content-Type-Options nosniff confirmed.")
        else:
            results["headers_missing"].append("X-Content-Type-Options")
            results["detailed_findings"].append({
                "header": "X-Content-Type-Options",
                "status": "FAIL",
                "value": "Missing",
                "importance": "Browsers may perform unsafe MIME sniffing on untrusted files."
            })

        # 5. Referrer-Policy (10 pts)
        if "referrer-policy" in raw_headers:
            rp_val = raw_headers["referrer-policy"]
            score += 10
            results["headers_present"]["Referrer-Policy"] = rp_val
            results["detailed_findings"].append({
                "header": "Referrer-Policy",
                "status": "PASS",
                "value": rp_val,
                "importance": "Prevents sensitive URL parameter leakage in Referer headers."
            })
        else:
            results["headers_missing"].append("Referrer-Policy")

        # 6. Permissions-Policy (5 pts)
        if "permissions-policy" in raw_headers:
            score += 5
            results["headers_present"]["Permissions-Policy"] = raw_headers["permissions-policy"]

        # Deductions: Verbose server version disclosure (-5 pts)
        if "x-powered-by" in raw_headers:
            score = max(0, score - 5)
            results["detailed_findings"].append({
                "header": "X-Powered-By",
                "status": "WARN",
                "value": raw_headers["x-powered-by"],
                "importance": "Information leak: reveals underlying runtime / framework version."
            })

        results["posture_score"] = score
        if score >= 90:
            results["posture_grade"] = "A+"
        elif score >= 80:
            results["posture_grade"] = "A"
        elif score >= 65:
            results["posture_grade"] = "B"
        elif score >= 50:
            results["posture_grade"] = "C"
        elif score >= 35:
            results["posture_grade"] = "D"
        else:
            results["posture_grade"] = "F"

        results["logs"].append(f"[SUMMARY] Posture Score: {score}/100 | Grade: {results['posture_grade']}")
        return results
