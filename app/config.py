import os
from typing import List

class Settings:
    APP_NAME: str = "Vatsal's SecOps Reconnaissance & Attack Surface Toolkit"
    APP_SHORT_NAME: str = "SecOps Console 2.0"
    VERSION: str = "2.5.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    ALLOWED_ORIGINS: List[str] = ["*"]
    SOCKET_TIMEOUT: float = 3.5
    PORT_SCAN_TIMEOUT: float = 1.2
    MAX_PORT_WORKERS: int = 50
    DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (SecOps-Auditor/2.5)"

settings = Settings()
