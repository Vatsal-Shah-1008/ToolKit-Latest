import socket
import httpx
from typing import Dict, Any

class GeoEngine:
    @classmethod
    async def lookup(cls, host_or_ip: str) -> Dict[str, Any]:
        clean_target = host_or_ip.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        target_ip = clean_target
        # If domain, resolve to IP
        try:
            target_ip = socket.gethostbyname(clean_target)
        except Exception:
            pass

        results: Dict[str, Any] = {
            "query": clean_target,
            "ip": target_ip,
            "success": False,
            "country": "Unknown",
            "country_code": "UN",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "N/A",
            "isp": "N/A",
            "org": "N/A",
            "timezone": "UTC",
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying BGP ASN and Geolocation routing for IP: {target_ip}")

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(f"https://ipwho.is/{target_ip}")
                if res.status_code == 200:
                    data = res.json()
                    if data.get("success", False):
                        results["success"] = True
                        results["country"] = data.get("country", "Unknown")
                        results["country_code"] = data.get("country_code", "UN")
                        results["region"] = data.get("region", "Unknown")
                        results["city"] = data.get("city", "Unknown")
                        results["latitude"] = data.get("latitude", 0.0)
                        results["longitude"] = data.get("longitude", 0.0)
                        
                        conn = data.get("connection", {})
                        asn_num = conn.get("asn", "")
                        asn_org = conn.get("org", conn.get("isp", "Unknown"))
                        results["asn"] = f"AS{asn_num} ({asn_org})" if asn_num else "Unknown ASN"
                        results["isp"] = conn.get("isp", "Unknown ISP")
                        results["org"] = conn.get("org", results["isp"])
                        
                        tz = data.get("timezone", {})
                        results["timezone"] = tz.get("id", "UTC")

                        results["logs"].append(f"[+] Located: {results['city']}, {results['region']}, {results['country']} ({results['country_code']})")
                        results["logs"].append(f"[+] Autonomous System: {results['asn']}")
                        results["logs"].append(f"[+] Upstream Provider: {results['isp']}")
                        return results
        except Exception as e:
            results["logs"].append(f"[-] Geolocation query failed: {str(e)[:80]}")

        # Local fallback if external API is unreachable
        results["logs"].append(f"[!] External GeoIP API timed out; returned standard socket route.")
        return results
