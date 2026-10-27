import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List

class SSLEngine:
    @staticmethod
    def inspect(domain: str, port: int = 443) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        results: Dict[str, Any] = {
            "domain": clean_domain,
            "port": port,
            "has_ssl": False,
            "status": "INSECURE / NO SSL",
            "subject_cn": "N/A",
            "issuer_cn": "N/A",
            "issuer_org": "N/A",
            "valid_from": "N/A",
            "valid_until": "N/A",
            "days_remaining": 0,
            "is_expired": False,
            "is_wildcard": False,
            "tls_version": "N/A",
            "cipher_suite": "N/A",
            "sans": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Establishing TLS handshake to {clean_domain}:{port} (SNI enabled)...")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((clean_domain, port), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    results["has_ssl"] = True
                    results["tls_version"] = ssock.version() or "TLSv1.2"
                    cipher_info = ssock.cipher()
                    results["cipher_suite"] = cipher_info[0] if cipher_info else "Unknown"

                    # If binary form was parsed or peer cert dict returned
                    # Re-handshake with cert validation if possible to parse fields
                    results["status"] = "ACTIVE & ENCRYPTED"
                    results["logs"].append(f"[+] TLS Handshake Succeeded: Protocol {results['tls_version']} | Cipher: {results['cipher_suite']}")

        except Exception as e:
            results["logs"].append(f"[-] TLS Connection Failed: {str(e)}")
            return results

        # Now get formatted certificate fields
        try:
            val_ctx = ssl.create_default_context()
            with socket.create_connection((clean_domain, port), timeout=4.0) as sock:
                with val_ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Subject
                        subject = dict(x[0] for x in cert.get("subject", []))
                        results["subject_cn"] = subject.get("commonName", clean_domain)
                        if results["subject_cn"].startswith("*."):
                            results["is_wildcard"] = True

                        # Issuer
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        results["issuer_cn"] = issuer.get("commonName", "Unknown CA")
                        results["issuer_org"] = issuer.get("organizationName", results["issuer_cn"])

                        # Dates
                        not_before = cert.get("notBefore", "")
                        not_after = cert.get("notAfter", "")
                        results["valid_from"] = not_before
                        results["valid_until"] = not_after

                        # Expiration calculation
                        # Format: 'May 15 12:00:00 2026 GMT'
                        try:
                            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            delta = expiry_dt - now
                            results["days_remaining"] = delta.days
                            if delta.days < 0:
                                results["is_expired"] = True
                                results["status"] = "EXPIRED"
                            elif delta.days < 30:
                                results["status"] = "EXPIRING SOON (<30 Days)"
                            else:
                                results["status"] = f"VALID ({delta.days} Days Left)"
                        except Exception:
                            pass

                        # SANs
                        sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]
                        results["sans"] = sans[:20]

                        results["logs"].append(f"[+] Certificate Subject: {results['subject_cn']}")
                        results["logs"].append(f"[+] Issued By: {results['issuer_org']} ({results['issuer_cn']})")
                        results["logs"].append(f"[+] Expiration: {results['valid_until']} ({results['days_remaining']} days remaining)")
                        results["logs"].append(f"[+] Subject Alternative Names: {len(sans)} host(s) covered")

        except ssl.SSLCertVerificationError as ve:
            results["status"] = "SELF-SIGNED / UNTRUSTED CA"
            results["logs"].append(f"[!] Warning: Untrusted / Self-signed certificate: {str(ve)}")
        except Exception:
            pass

        return results
