#!/usr/bin/env python3
"""
Vatsal's SecOps Reconnaissance & Attack Surface Console 2.0
One-click Local Development Runner
"""

import sys
import subprocess
import webbrowser
import time

def check_and_install():
    print("=" * 70)
    print("  VATSAL'S SECOPS CONSOLE 2.0 — LOCAL STARTUP SEQUENCE")
    print("=" * 70)
    print("[1/3] Checking Python runtime environment...")
    if sys.version_info < (3, 9):
        print(f"[!] Error: Python 3.9+ is required. Found: {sys.version}")
        sys.exit(1)

    print(f"[+] Python runtime verified: {sys.version.split()[0]}")

    print("[2/3] Checking core dependencies (FastAPI, Uvicorn, DNS, HTTPX)...")
    try:
        import fastapi
        import uvicorn
        import dns.resolver
        import httpx
        import cryptography
        print("[+] All dependencies present and verified.")
    except ImportError as e:
        print(f"[!] Missing dependency detected ({e.name}). Installing from requirements.txt...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[+] Dependencies successfully installed.")

    print("[3/3] Launching FastAPI ASGI Server on http://localhost:8000 ...")
    print("=" * 70)
    print("  CONSOLE ONLINE: http://localhost:8000")
    print("  OPENAPI DOCS:   http://localhost:8000/docs")
    print("  PRESS CTRL+C TO STOP SERVER")
    print("=" * 70)

    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    check_and_install()
