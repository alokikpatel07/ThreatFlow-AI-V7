from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IOC_PATH = ROOT / "threat_intel" / "iocs.json"

# Cached IOC database — loaded once, refreshed only on demand.
_IOC_CACHE: dict[str, Any] | None = None


def load_iocs(*, force_reload: bool = False) -> dict[str, Any]:
    """Load local IOC feed. Results are cached for the process lifetime."""
    global _IOC_CACHE
    if _IOC_CACHE is not None and not force_reload:
        return _IOC_CACHE
    try:
        _IOC_CACHE = json.loads(IOC_PATH.read_text(encoding="utf-8"))
    except Exception:
        _IOC_CACHE = {"ips": {}, "domains": {}, "tls_fingerprints": {}}
    return _IOC_CACHE


def enrich(flow: dict) -> list[dict]:
    """Match flow fields against the cached local IOC feed."""
    db = load_iocs()
    matches: list[dict] = []
    src = flow.get("src_ip", "")
    dst = flow.get("dst_ip", "")
    dns = flow.get("dns_name") or flow.get("dns_query") or ""
    tls = flow.get("tls_fingerprint") or ""

    if src in db.get("ips", {}):
        matches.append({"type": "source_ip", "value": src, "context": db["ips"][src]})
    if dst in db.get("ips", {}):
        matches.append({"type": "destination_ip", "value": dst, "context": db["ips"][dst]})
    if dns in db.get("domains", {}):
        matches.append({"type": "domain", "value": dns, "context": db["domains"][dns]})
    if tls in db.get("tls_fingerprints", {}):
        matches.append(
            {"type": "tls_fingerprint", "value": tls, "context": db["tls_fingerprints"][tls]}
        )
    return matches
