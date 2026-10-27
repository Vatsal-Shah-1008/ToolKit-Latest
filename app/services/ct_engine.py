import asyncio
import socket
import httpx
from typing import Dict, Any, List, Set

class CTEngine:
    @staticmethod
    async def _verify_subdomain(subdomain: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        try:
            # Non-blocking DNS resolution
            addr_info = await loop.getaddrinfo(subdomain, None, family=socket.AF_INET)
            ip = addr_info[0][4][0] if addr_info else "Unknown"
            return {
                "subdomain": subdomain,
                "ip": ip,
                "is_live": True,
                "status": "Live Active (Resolving)"
            }
        except Exception:
            return {
                "subdomain": subdomain,
                "ip": "Unresolved",
                "is_live": False,
                "status": "Historical Cert Only"
            }

    @classmethod
    async def enumerate(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        results: Dict[str, Any] = {
            "root_domain": clean_domain,
            "total_discovered": 0,
            "live_count": 0,
            "subdomains": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying Certificate Transparency (CT) logs for: {clean_domain}")

        discovered_names: Set[str] = set()

        # Step 1: Query crt.sh API with timeout
        url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers={"User-Agent": "SecOps-Auditor/2.5"})
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for line in name_value.split("\n"):
                            clean_line = line.strip().lower().replace("*.", "")
                            if clean_line.endswith(clean_domain) and len(clean_line) > len(clean_domain):
                                discovered_names.add(clean_line)
                    results["logs"].append(f"[+] crt.sh logs returned {len(discovered_names)} unique certificate identities.")
        except Exception as e:
            results["logs"].append(f"[!] crt.sh log search notice: {str(e)[:80]}")

        # Step 2: Add common high-probability standard perimeter subdomains
        standard_prefixes = ["www", "api", "mail", "dev", "app", "vpn", "admin", "portal", "stage", "docs", "test", "auth", "audit", "cyber"]
        for p in standard_prefixes:
            discovered_names.add(f"{p}.{clean_domain}")

        # Step 3: Concurrently verify reachability
        sem = asyncio.Semaphore(30)
        async def verify_worker(sub: str):
            async with sem:
                return await cls._verify_subdomain(sub)

        tasks = [verify_worker(sub) for sub in sorted(list(discovered_names))]
        verified_items = await asyncio.gather(*tasks)

        # Prioritize live subdomains at the top
        live_subs = [item for item in verified_items if item["is_live"]]
        unresolved = [item for item in verified_items if not item["is_live"] and item["subdomain"] in [f"{p}.{clean_domain}" for p in ["www", "api", "mail"]]]

        combined = live_subs + unresolved[:10]
        results["subdomains"] = combined
        results["total_discovered"] = len(discovered_names)
        results["live_count"] = len(live_subs)

        results["logs"].append(f"[SUCCESS] Discovered {len(live_subs)} active resolving perimeter hosts.")
        return results
