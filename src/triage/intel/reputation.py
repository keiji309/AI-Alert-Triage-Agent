from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from .. import settings
from ..ingest.synthesizer import (
    IP_AMB_PROXY, IP_C2, IP_EXFIL_DST, IP_MINER_POOL, IP_SSH_BRUTE,
    IP_STAGING, IP_TOR,
)

# Bundled local reputation table for the demo IP space. In production this
# is one of several configured feeds (see INTEL_FEEDS) behind the same API.
_DEMO_INTEL: Dict[str, Dict[str, Any]] = {
    IP_SSH_BRUTE: {
        "ip": IP_SSH_BRUTE, "score": 94, "malicious": True, "categorization": "ssh-bruteforcer",
        "reports": 231, "last_seen": "2026-08-27", "ttl_hours": 24,
    },
    IP_C2: {
        "ip": IP_C2, "score": 99, "malicious": True, "categorization": "c2-command-and-control",
        "reports": 512, "last_seen": "2026-08-28", "ttl_hours": 24,
    },
    IP_STAGING: {
        "ip": IP_STAGING, "score": 88, "malicious": True, "categorization": "malware-staging",
        "reports": 143, "last_seen": "2026-08-28", "ttl_hours": 24,
    },
    IP_EXFIL_DST: {
        "ip": IP_EXFIL_DST, "score": 91, "malicious": True, "categorization": "data-extraction",
        "reports": 89, "last_seen": "2026-08-26", "ttl_hours": 24,
    },
    IP_MINER_POOL: {
        "ip": IP_MINER_POOL, "score": 82, "malicious": True, "categorization": "mining-pool",
        "reports": 61, "last_seen": "2026-08-25", "ttl_hours": 24,
    },
    IP_TOR: {
        "ip": IP_TOR, "score": 73, "malicious": False, "categorization": "anon-tor-exit",
        "reports": 180, "last_seen": "2026-08-28", "ttl_hours": 24,
    },
    IP_AMB_PROXY: {
        "ip": IP_AMB_PROXY, "score": 48, "malicious": False, "categorization": "anonymous-proxy",
        "reports": 22, "last_seen": "2026-08-20", "ttl_hours": 24,
    },
}

INTEL_FEEDS = ["local-demo"]

_ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


class ThreatIntel:
    """Threat-intel lookup layer. Bundled local feed by default; AbuseIPDB can
    be enabled by setting ABUSEIPDB_API_KEY. Results are cached per IP."""

    def __init__(self, api_key: str = ""):
        self._cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._abuseipdb_key = (api_key or settings.ABUSEIPDB_API_KEY).strip()

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if ip in self._cache:
            return self._cache[ip]
        result = self._lookup_local(ip)
        if result is None:
            result = self._lookup_abuseipdb(ip)
        if result is None:
            result = self._lookup_empty(ip)
        self._cache[ip] = result
        return result

    def lookup_many(self, ips) -> Dict[str, Optional[Dict[str, Any]]]:
        return {ip: self.lookup(ip) for ip in ips}

    def _lookup_local(self, ip: str) -> Optional[Dict[str, Any]]:
        entry = _DEMO_INTEL.get(ip)
        if not entry:
            return None
        return {**entry, "_feed": "local-demo"}

    def _lookup_empty(self, ip: str) -> Dict[str, Any]:
        return {"ip": ip, "score": 0, "malicious": False, "categorization": "unknown",
                "reports": 0, "last_seen": None, "ttl_hours": None, "_feed": "no-feed"}

    def _lookup_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self._abuseipdb_key or ip.startswith(("10.", "172.", "192.168.")):
            return None
        try:
            resp = httpx.get(
                _ABUSEIPDB_API,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
                timeout=8,
            )
            resp.raise_for_status()
            d = resp.json()["data"]
            return {
                "ip": ip,
                "score": d.get("abuseConfidenceScore", 0),
                "malicious": (d.get("abuseConfidenceScore", 0) or 0) >= 50,
                "categorization": d.get("isTor", False) and "anon-tor-exit" or "reported",
                "reports": None,
                "last_seen": d.get("lastReportedAt"),
                "ttl_hours": None,
                "_feed": "abuseipdb",
            }
        except Exception:
            return None