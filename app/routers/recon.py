import asyncio
from fastapi import APIRouter, Query, HTTPException, Body
from typing import Dict, Any, List, Optional
from app.services.dns_engine import DNSEngine
from app.services.whois_engine import WhoisEngine
from app.services.ssl_engine import SSLEngine
from app.services.headers_engine import HeadersEngine
from app.services.port_engine import PortEngine
from app.services.ct_engine import CTEngine
from app.services.geo_engine import GeoEngine
from app.services.web_probe_engine import WebProbeEngine
from app.services.crypto_engine import CryptoEngine

router = APIRouter(prefix="/api/recon", tags=["Reconnaissance & SecOps"])

@router.get("/dns")
def get_dns(domain: str = Query(..., description="Target domain name")):
    return DNSEngine.resolve_domain(domain)

@router.get("/whois")
def get_whois(domain: str = Query(..., description="Target domain name")):
    return WhoisEngine.lookup(domain)

@router.get("/ssl")
def get_ssl(domain: str = Query(..., description="Target domain name"), port: int = 443):
    return SSLEngine.inspect(domain, port)

@router.get("/headers")
async def get_headers(domain: str = Query(..., description="Target domain name")):
    return await HeadersEngine.analyze(domain)

@router.get("/ports")
async def get_ports(
    target: str = Query(..., description="Target domain or IP"),
    profile: str = Query("quick", description="Port profile: quick, databases, or all")
):
    return await PortEngine.scan(target, profile=profile)

@router.get("/subdomains")
async def get_subdomains(domain: str = Query(..., description="Target root domain")):
    return await CTEngine.enumerate(domain)

@router.get("/geo")
async def get_geo(target: str = Query(..., description="Target domain or IP")):
    return await GeoEngine.lookup(target)

@router.get("/endpoints")
async def get_endpoints(domain: str = Query(..., description="Target domain")):
    return await WebProbeEngine.check_endpoints(domain)

@router.get("/cors")
async def get_cors(domain: str = Query(..., description="Target domain")):
    return await WebProbeEngine.check_cors(domain)

@router.post("/password")
def analyze_password(payload: Dict[str, str] = Body(...)):
    pwd = payload.get("password", "")
    return CryptoEngine.calculate_entropy(pwd)

@router.post("/hashes")
def compute_hashes(payload: Dict[str, str] = Body(...)):
    text = payload.get("text", "")
    return CryptoEngine.generate_hashes(text)

@router.post("/jwt")
def decode_jwt(payload: Dict[str, str] = Body(...)):
    token = payload.get("token", "")
    return CryptoEngine.decode_jwt(token)

@router.get("/subnet")
def calculate_subnet(cidr: str = Query("192.168.1.0/24")):
    return CryptoEngine.calculate_subnet(cidr)

@router.get("/full-audit")
async def run_full_audit(domain: str = Query(..., description="Target root domain")):
    clean = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Concurrently dispatch non-blocking audit routines
    dns_task = asyncio.to_thread(DNSEngine.resolve_domain, clean)
    whois_task = asyncio.to_thread(WhoisEngine.lookup, clean)
    ssl_task = asyncio.to_thread(SSLEngine.inspect, clean)
    headers_task = HeadersEngine.analyze(clean)
    ports_task = PortEngine.scan(clean, profile="quick")
    geo_task = GeoEngine.lookup(clean)

    dns_res, whois_res, ssl_res, headers_res, ports_res, geo_res = await asyncio.gather(
        dns_task, whois_task, ssl_task, headers_task, ports_task, geo_task,
        return_exceptions=True
    )

    return {
        "target": clean,
        "dns": dns_res if not isinstance(dns_res, Exception) else {"error": str(dns_res)},
        "whois": whois_res if not isinstance(whois_res, Exception) else {"error": str(whois_res)},
        "ssl": ssl_res if not isinstance(ssl_res, Exception) else {"error": str(ssl_res)},
        "headers": headers_res if not isinstance(headers_res, Exception) else {"error": str(headers_res)},
        "ports": ports_res if not isinstance(ports_res, Exception) else {"error": str(ports_res)},
        "geo": geo_res if not isinstance(geo_res, Exception) else {"error": str(geo_res)}
    }
