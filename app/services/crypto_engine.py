import math
import hashlib
import base64
import json
import urllib.parse
import ipaddress
from collections import Counter
from typing import Dict, Any, List

class CryptoEngine:
    @staticmethod
    def calculate_entropy(password: str) -> Dict[str, Any]:
        """Computes mathematical Shannon Entropy and brute-force cracking complexity."""
        if not password:
            return {
                "length": 0,
                "shannon_entropy": 0.0,
                "pool_size": 0,
                "entropy_bits": 0.0,
                "rating": "EMPTY",
                "crack_time_estimate": "Instant",
                "logs": ["[!] Empty password provided."]
            }

        length = len(password)
        # 1. Shannon Entropy
        counts = Counter(password)
        shannon = -sum((count / length) * math.log2(count / length) for count in counts.values())

        # 2. Key space calculation (NIST Pool Size)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 33

        pool_size = max(pool_size, 1)
        total_combinations = pool_size ** length
        entropy_bits = length * math.log2(pool_size)

        # Crack time estimation at 10 Billion hashes / sec (Standard Modern RTX 4090 cluster)
        hashes_per_sec = 10_000_000_000
        seconds = total_combinations / (2 * hashes_per_sec)  # Average 50% search space

        if seconds < 1:
            crack_time = "Instant (< 1 second)"
            rating = "VERY WEAK"
        elif seconds < 60:
            crack_time = f"{round(seconds)} seconds"
            rating = "WEAK"
        elif seconds < 3600:
            crack_time = f"{round(seconds / 60)} minutes"
            rating = "MODERATE"
        elif seconds < 86400:
            crack_time = f"{round(seconds / 3600, 1)} hours"
            rating = "FAIR"
        elif seconds < 31536000:
            crack_time = f"{round(seconds / 86400)} days"
            rating = "STRONG"
        elif seconds < 3153600000:
            crack_time = f"{round(seconds / 31536000, 1)} years"
            rating = "VERY STRONG"
        else:
            crack_time = "Centuries (> 100 years)"
            rating = "CRYPTOGRAPHICALLY STRONG"

        return {
            "length": length,
            "shannon_entropy": round(shannon, 3),
            "pool_size": pool_size,
            "entropy_bits": round(entropy_bits, 1),
            "rating": rating,
            "crack_time_estimate": crack_time,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "logs": [
                f"[+] Length: {length} chars | Character Pool: {pool_size}",
                f"[+] Shannon Entropy: {round(shannon, 3)} bits/symbol",
                f"[+] Key Space Entropy: {round(entropy_bits, 1)} bits",
                f"[+] Offline GPU (10 GH/s) Crack Time: {crack_time}",
                f"[+] Verdict: {rating}"
            ]
        }

    @staticmethod
    def generate_hashes(text: str) -> Dict[str, Any]:
        data = text.encode("utf-8")
        return {
            "input": text,
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "base64_encoded": base64.b64encode(data).decode("utf-8"),
            "url_encoded": urllib.parse.quote(text),
            "hex_encoded": data.hex()
        }

    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT token structure (must have 3 dot-separated parts)"}

        def _b64_decode(segment: str):
            rem = len(segment) % 4
            if rem > 0:
                segment += "=" * (4 - rem)
            return json.loads(base64.urlsafe_b64decode(segment).decode("utf-8"))

        try:
            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            return {
                "valid_format": True,
                "header": header,
                "payload": payload,
                "algorithm": header.get("alg", "Unknown"),
                "token_type": header.get("typ", "JWT"),
                "signature": parts[2][:16] + "..."
            }
        except Exception as e:
            return {"error": f"Failed to parse JWT segments: {str(e)}"}

    @staticmethod
    def calculate_subnet(cidr: str) -> Dict[str, Any]:
        """Calculates 100% mathematically accurate IPv4/IPv6 subnet parameters."""
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            num_addresses = net.num_addresses
            usable_hosts = max(0, num_addresses - 2) if net.version == 4 and net.prefixlen < 31 else num_addresses

            first_usable = "N/A"
            last_usable = "N/A"
            if net.version == 4:
                if net.prefixlen < 31:
                    first_usable = str(net.network_address + 1)
                    last_usable = str(net.broadcast_address - 1)
                else:
                    first_usable = str(net.network_address)
                    last_usable = str(net.broadcast_address)

            return {
                "cidr": str(net),
                "ip_version": net.version,
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address) if net.version == 4 else "N/A (IPv6 Multicast)",
                "netmask": str(net.netmask),
                "hostmask": str(net.hostmask),
                "prefix_length": net.prefixlen,
                "total_addresses": num_addresses,
                "usable_hosts": usable_hosts,
                "first_usable_ip": first_usable,
                "last_usable_ip": last_usable,
                "is_private": net.is_private,
                "is_global": net.is_global
            }
        except Exception as e:
            return {"error": f"Invalid CIDR notation '{cidr}': {str(e)}"}
