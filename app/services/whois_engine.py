import socket
import re
import httpx
from typing import Dict, Any, List

class WhoisEngine:
    @staticmethod
    def _query_socket_whois(domain: str, server: str = "whois.iana.org", port: int = 43) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((server, port))
            s.send((domain + "\r\n").encode("utf-8"))
            buffer = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buffer += chunk
            s.close()
            return buffer.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _query_rdap_https(domain: str) -> Dict[str, Any]:
        """Modern RFC 7482 RDAP query over HTTPS (bypasses port 43 firewall blocks)."""
        try:
            url = f"https://rdap.org/domain/{domain}"
            with httpx.Client(timeout=4.5, follow_redirects=True) as client:
                res = client.get(url, headers={"Accept": "application/rdap+json, application/json"})
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return {}

    @classmethod
    def lookup(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        results: Dict[str, Any] = {
            "domain": clean_domain,
            "registrar": "Unknown / Private",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "updated_date": "N/A",
            "status": [],
            "name_servers": [],
            "whois_source": "RDAP (RFC 7482 HTTPS)",
            "raw_output": "",
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying registration records for: {clean_domain}")

        # Step 1: Attempt modern HTTPS RDAP first
        rdap_data = cls._query_rdap_https(clean_domain)
        if rdap_data:
            # Parse Entities for Registrar
            entities = rdap_data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles or "sponsor" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if len(prop) > 3 and prop[0] == "fn":
                                results["registrar"] = prop[3]
                                break

            # Parse Events (Registration, Expiration, Last Changed)
            events = rdap_data.get("events", [])
            for ev in events:
                action = ev.get("eventAction", "")
                date_str = ev.get("eventDate", "")
                if "registration" in action:
                    results["creation_date"] = date_str[:10]
                elif "expiration" in action:
                    results["expiration_date"] = date_str[:10]
                elif "last changed" in action or "last update" in action:
                    results["updated_date"] = date_str[:10]

            # Parse Nameservers
            ns_list = rdap_data.get("nameservers", [])
            for ns in ns_list:
                ldh = ns.get("ldhName", "")
                if ldh:
                    results["name_servers"].append(ldh.lower())

            # Parse Status
            results["status"] = rdap_data.get("status", [])
            results["raw_output"] = f"RDAP Handle: {rdap_data.get('handle', 'N/A')}\nDomain: {rdap_data.get('ldhName', clean_domain)}\nStatus: {', '.join(results['status'])}\nRegistrar: {results['registrar']}"
            results["logs"].append(f"[+] Successfully extracted RDAP record via HTTPS.")
            results["logs"].append(f"[+] Registrar: {results['registrar']}")
            results["logs"].append(f"[+] Created: {results['creation_date']} | Expiry: {results['expiration_date']}")
            return results

        # Step 2: Fallback to TCP Port 43 Socket WHOIS
        results["whois_source"] = "Socket WHOIS (Port 43)"
        results["logs"].append(f"[!] RDAP query unavailable; attempting socket query via IANA port 43...")

        iana_res = cls._query_socket_whois(clean_domain, "whois.iana.org")
        refer_match = re.search(r"refer:\s+([^\s]+)", iana_res, re.IGNORECASE)
        tld_server = refer_match.group(1) if refer_match else "whois.internic.net"

        whois_data = cls._query_socket_whois(clean_domain, tld_server)
        if not whois_data:
            whois_data = cls._query_socket_whois(clean_domain, "whois.nic." + clean_domain.split(".")[-1])

        if whois_data:
            results["raw_output"] = whois_data[:2000]
            # Parse registrar
            reg_match = re.search(r"(?:Registrar|registrar name|Sponsoring Registrar):\s*(.+)", whois_data, re.IGNORECASE)
            if reg_match:
                results["registrar"] = reg_match.group(1).strip()

            # Parse creation
            cr_match = re.search(r"(?:Creation Date|Created|registered on|Registration Time):\s*(.+)", whois_data, re.IGNORECASE)
            if cr_match:
                results["creation_date"] = cr_match.group(1).strip()[:10]

            # Parse expiry
            ex_match = re.search(r"(?:Registry Expiry Date|Expir\w+ Date|Expiration Time):\s*(.+)", whois_data, re.IGNORECASE)
            if ex_match:
                results["expiration_date"] = ex_match.group(1).strip()[:10]

            # Parse nameservers
            ns_matches = re.findall(r"(?:Name Server|nserver):\s*([^\s]+)", whois_data, re.IGNORECASE)
            results["name_servers"] = list(set([ns.lower().rstrip('.') for ns in ns_matches]))

            results["logs"].append(f"[+] Extracted records via port 43 WHOIS server ({tld_server}).")
            results["logs"].append(f"[+] Registrar: {results['registrar']}")
        else:
            results["logs"].append(f"[!] Note: Target domain WHOIS is protected, rate-limited, or TLD is internal.")

        return results
