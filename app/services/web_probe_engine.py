import httpx
from typing import Dict, Any, List

class WebProbeEngine:
    @classmethod
    async def check_endpoints(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        base_url = f"https://{clean_domain}"

        endpoints = [
            "/robots.txt",
            "/sitemap.xml",
            "/security.txt",
            "/.well-known/security.txt"
        ]

        results: Dict[str, Any] = {
            "domain": clean_domain,
            "endpoints": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Probing public disclosure and policy endpoints for: {base_url}")

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False) as client:
            for ep in endpoints:
                target_url = f"{base_url}{ep}"
                try:
                    res = await client.get(target_url, headers={"User-Agent": "SecOps-Auditor/2.5"})
                    is_found = res.status_code == 200 and len(res.text.strip()) > 0 and "<html" not in res.text.lower()[:100]
                    results["endpoints"].append({
                        "path": ep,
                        "status_code": res.status_code,
                        "found": is_found,
                        "preview": res.text[:250] if is_found else "Endpoint not present (404/Redirect)"
                    })
                    if is_found:
                        results["logs"].append(f"[+] FOUND: {ep} (HTTP 200 - {len(res.text)} bytes)")
                except Exception:
                    results["endpoints"].append({
                        "path": ep,
                        "status_code": 0,
                        "found": False,
                        "preview": "Connection failed"
                    })

        return results

    @classmethod
    async def check_cors(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        target_url = f"https://{clean_domain}"
        test_origin = "https://evil-attacker-test.com"

        results: Dict[str, Any] = {
            "domain": clean_domain,
            "is_vulnerable": False,
            "severity": "LOW",
            "allow_origin": "None",
            "allow_credentials": "False",
            "summary": "CORS policy is properly restricted or disabled.",
            "logs": []
        }

        results["logs"].append(f"[INIT] Testing CORS origin reflection on {target_url} with origin: {test_origin}")

        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                res = await client.options(
                    target_url,
                    headers={
                        "Origin": test_origin,
                        "Access-Control-Request-Method": "GET"
                    }
                )
                if res.status_code not in [200, 204]:
                    res = await client.get(target_url, headers={"Origin": test_origin})

                headers = {k.lower(): v for k, v in res.headers.items()}
                allow_origin = headers.get("access-control-allow-origin", "None")
                allow_creds = headers.get("access-control-allow-credentials", "false").lower()

                results["allow_origin"] = allow_origin
                results["allow_credentials"] = allow_creds

                if allow_origin == test_origin and allow_creds == "true":
                    results["is_vulnerable"] = True
                    results["severity"] = "CRITICAL"
                    results["summary"] = "CRITICAL: Server reflects arbitrary Origin header AND allows credentials! Authenticated data can be exfiltrated."
                    results["logs"].append(f"[!] CRITICAL CORS MISCONFIGURATION: Origin reflection + Credentials allowed!")
                elif allow_origin == "*":
                    results["is_vulnerable"] = False
                    results["severity"] = "LOW / INFO"
                    results["summary"] = "Public Wildcard (*): API is intentionally public without credential sharing."
                    results["logs"].append(f"[+] Public Wildcard detected. Credentials cannot be passed.")
                elif allow_origin == test_origin:
                    results["is_vulnerable"] = True
                    results["severity"] = "MEDIUM"
                    results["summary"] = "WARNING: Server reflects arbitrary Origin header without credentials flag."
                    results["logs"].append(f"[!] Warning: Arbitrary Origin reflected.")
                else:
                    results["logs"].append(f"[+] Secure: CORS origin reflection denied.")

        except Exception as e:
            results["logs"].append(f"[-] CORS probe error: {str(e)[:80]}")

        return results
