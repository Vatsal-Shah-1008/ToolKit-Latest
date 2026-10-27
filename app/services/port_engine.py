import asyncio
import socket
import time
from typing import Dict, Any, List

SERVICE_MAP = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted CLI)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail Retrieval)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Encrypted Web)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP Submission",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL Database",
    1521: "Oracle DB",
    2082: "cPanel Insecure",
    2083: "cPanel SSL",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis Cache Store",
    8000: "HTTP Dev Server",
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
    8888: "Jupyter / HTTP Alt",
    9000: "SonarQube / FastCGI",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database"
}

QUICK_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 1433, 3306, 3389, 5432, 6379, 8080, 8443]

class PortEngine:
    @staticmethod
    async def _check_single_port(host: str, port: int, timeout: float = 1.2) -> Dict[str, Any]:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

            banner = ""
            try:
                # Controlled banner read with fast 0.4s timeout
                banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.4)
                banner = banner_bytes.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:80]
            except Exception:
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service_name = SERVICE_MAP.get(port, "Unknown Service")
            is_critical = port in [21, 23, 3306, 5432, 6379, 9200, 27017, 3389]

            return {
                "port": port,
                "status": "OPEN",
                "service": service_name,
                "banner": banner if banner else "No banner emitted",
                "latency_ms": elapsed_ms,
                "risk": "HIGH" if is_critical else "LOW"
            }
        except asyncio.TimeoutError:
            return {"port": port, "status": "FILTERED", "service": SERVICE_MAP.get(port, "Unknown"), "risk": "INFO"}
        except (ConnectionRefusedError, OSError):
            return {"port": port, "status": "CLOSED", "service": SERVICE_MAP.get(port, "Unknown"), "risk": "INFO"}
        except Exception:
            return {"port": port, "status": "CLOSED", "service": SERVICE_MAP.get(port, "Unknown"), "risk": "INFO"}

    @classmethod
    async def scan(cls, target: str, ports: List[int] = None, profile: str = "quick") -> Dict[str, Any]:
        clean_host = target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        
        # Resolve target IP first
        resolved_ip = clean_host
        try:
            resolved_ip = socket.gethostbyname(clean_host)
        except Exception:
            pass

        target_ports = ports or QUICK_PORTS
        if profile == "databases":
            target_ports = [3306, 5432, 6379, 9200, 27017, 1433, 1521, 8080, 8443]

        results: Dict[str, Any] = {
            "target": clean_host,
            "resolved_ip": resolved_ip,
            "profile": profile,
            "total_scanned": len(target_ports),
            "open_ports": [],
            "closed_count": 0,
            "filtered_count": 0,
            "logs": []
        }

        results["logs"].append(f"[INIT] Scanning {len(target_ports)} ports on {clean_host} ({resolved_ip})...")

        # Concurrency limit to guarantee cross-platform socket safety
        sem = asyncio.Semaphore(40)

        async def worker(p: int):
            async with sem:
                return await cls._check_single_port(resolved_ip, p)

        tasks = [worker(p) for p in target_ports]
        scan_out = await asyncio.gather(*tasks)

        for res in scan_out:
            if res["status"] == "OPEN":
                results["open_ports"].append(res)
                results["logs"].append(f"[+] OPEN PORT: {res['port']} ({res['service']}) - {res['latency_ms']}ms | Risk: {res['risk']}")
            elif res["status"] == "FILTERED":
                results["filtered_count"] += 1
            else:
                results["closed_count"] += 1

        results["open_ports"].sort(key=lambda x: x["port"])
        results["logs"].append(f"[SUCCESS] Audit finished: {len(results['open_ports'])} open ports found.")
        return results
