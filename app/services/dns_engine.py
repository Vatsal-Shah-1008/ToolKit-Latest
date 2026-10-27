import socket
import dns.resolver
import dns.reversename
import httpx
from typing import Dict, Any, List

CLOUD_TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": "AWS S3 Bucket",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku Application",
    "azurewebsites.net": "Azure Cloud App",
    "zendesk.com": "Zendesk Help Desk",
    "ghost.io": "Ghost Blog",
    "pantheonsite.io": "Pantheon Web Host",
    "wordpress.com": "WordPress Site",
    "unbouncepages.com": "Unbounce Landing Page",
    "readme.io": "ReadMe Docs",
    "shopify.com": "Shopify Store",
    "cargo.site": "Cargo Collective"
}

class DNSEngine:
    @staticmethod
    def _query_doh_fallback(domain: str, record_type: str) -> List[str]:
        """Fallback to Cloudflare DNS-over-HTTPS (DoH) if local resolver fails or is blocked."""
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
            with httpx.Client(timeout=3.5) as client:
                res = client.get(url, headers={"Accept": "application/dns-json"})
                if res.status_code == 200:
                    data = res.json()
                    answers = data.get("Answer", [])
                    return [str(a.get("data", "")).strip('"') for a in answers if "data" in a]
        except Exception:
            pass
        return []

    @classmethod
    def resolve_domain(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        results: Dict[str, Any] = {
            "domain": clean_domain,
            "records": {},
            "reverse_ptr": [],
            "dangling_cnames": [],
            "email_security": {
                "has_spf": False,
                "spf_record": None,
                "spf_strength": "Missing",
                "has_dmarc": False,
                "dmarc_record": None,
                "dmarc_policy": "Missing"
            },
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying DNS infrastructure for target: {clean_domain}")

        # Configure resilient resolver with public fallbacks
        resolver = dns.resolver.Resolver(configure=True)
        resolver.nameservers = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1']
        resolver.timeout = 2.5
        resolver.lifetime = 3.5

        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

        for r_type in record_types:
            found_records = []
            try:
                answers = resolver.resolve(clean_domain, r_type)
                found_records = [str(r.to_text()).strip('"') for r in answers]
            except Exception:
                # Try DoH fallback
                found_records = cls._query_doh_fallback(clean_domain, r_type)

            if found_records:
                results["records"][r_type] = found_records
                results["logs"].append(f"[+] Discovered {len(found_records)} {r_type} record(s): {', '.join(found_records[:3])}{'...' if len(found_records) > 3 else ''}")

                # Reverse PTR for A records
                if r_type == "A":
                    for ip in found_records:
                        try:
                            rev_name = dns.reversename.from_address(ip)
                            ptr_ans = resolver.resolve(rev_name, "PTR")
                            for p in ptr_ans:
                                hostname = str(p).rstrip('.')
                                results["reverse_ptr"].append({"ip": ip, "hostname": hostname})
                                results["logs"].append(f"    └─ Reverse PTR: {ip} -> {hostname}")
                        except Exception:
                            pass

                # CNAME Takeover check
                elif r_type == "CNAME":
                    for cname in found_records:
                        clean_cname = cname.rstrip(".")
                        for sig, provider in CLOUD_TAKEOVER_SIGNATURES.items():
                            if sig in clean_cname.lower():
                                item = {
                                    "cname": clean_cname,
                                    "provider": provider,
                                    "status": "POTENTIAL_TAKEOVER_EXPOSURE",
                                    "severity": "HIGH",
                                    "detail": f"Subdomain points to cloud provider {provider}. If the resource is unclaimed, it can be hijacked."
                                }
                                results["dangling_cnames"].append(item)
                                results["logs"].append(f"[!] POTENTIAL DANGLING CNAME: {clean_cname} ({provider})")

                # Parse SPF from TXT
                elif r_type == "TXT":
                    for txt in found_records:
                        if txt.startswith("v=spf1"):
                            results["email_security"]["has_spf"] = True
                            results["email_security"]["spf_record"] = txt
                            if "-all" in txt:
                                results["email_security"]["spf_strength"] = "Hardfail (-all) [Optimal]"
                            elif "~all" in txt:
                                results["email_security"]["spf_strength"] = "Softfail (~all) [Permissive]"
                            elif "+all" in txt:
                                results["email_security"]["spf_strength"] = "Open Relay (+all) [Vulnerable]"
                            else:
                                results["email_security"]["spf_strength"] = "Neutral / Incomplete"
                            results["logs"].append(f"[+] SPF Authentication: {results['email_security']['spf_strength']}")

        # Query DMARC explicitly (_dmarc.domain)
        try:
            dmarc_host = f"_dmarc.{clean_domain}"
            dmarc_ans = resolver.resolve(dmarc_host, "TXT")
            for r in dmarc_ans:
                txt = str(r.to_text()).strip('"')
                if txt.startswith("v=DMARC1"):
                    results["email_security"]["has_dmarc"] = True
                    results["email_security"]["dmarc_record"] = txt
                    if "p=reject" in txt:
                        results["email_security"]["dmarc_policy"] = "Reject (p=reject) [Strong]"
                    elif "p=quarantine" in txt:
                        results["email_security"]["dmarc_policy"] = "Quarantine (p=quarantine) [Moderate]"
                    else:
                        results["email_security"]["dmarc_policy"] = "None (p=none) [Monitoring Only]"
                    results["logs"].append(f"[+] DMARC Policy: {results['email_security']['dmarc_policy']}")
        except Exception:
            # Fallback to DoH for DMARC
            dmarc_txt = cls._query_doh_fallback(f"_dmarc.{clean_domain}", "TXT")
            for txt in dmarc_txt:
                if txt.startswith("v=DMARC1"):
                    results["email_security"]["has_dmarc"] = True
                    results["email_security"]["dmarc_record"] = txt
                    results["email_security"]["dmarc_policy"] = "Active Policy Found via DoH"
                    results["logs"].append(f"[+] DMARC Policy detected via DoH")

        results["logs"].append(f"[SUCCESS] DNS resolution completed with {len(results['records'])} active record types.")
        return results
