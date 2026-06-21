"""VirusTotal read-only tools: IP, file-hash, domain reputation."""
import logging
import re
from typing import Any

import httpx

from ..config import get_settings
from .netutil import is_public_ip
from .registry import Tool, ToolContext, register

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _vt_get(path: str) -> tuple[int, dict]:
    s = get_settings()
    try:
        resp = httpx.get(f"{VT_BASE}/{path}", headers={"x-apikey": s.virustotal_api_key},
                         timeout=s.vt_timeout)
    except httpx.HTTPError as exc:
        logger.error("VirusTotal request failed for %s: %s", path, exc)
        return 0, {"error": "request_failed", "detail": str(exc)}
    if resp.status_code == 200:
        return 200, resp.json()
    return resp.status_code, {}


def _stats(attrs: dict) -> dict:
    s = attrs.get("last_analysis_stats", {}) or {}
    return {
        "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
        "harmless": s.get("harmless", 0), "undetected": s.get("undetected", 0),
        "reputation": attrs.get("reputation"),
    }


# --- IP ---------------------------------------------------------------------
def _ip_lookup(args: dict, ctx: ToolContext) -> dict:
    ip = (args.get("ip") or "").strip()
    if not is_public_ip(ip):
        return {"ip": ip, "skipped": True, "reason": "private/local/reserved IP"}
    code, body = _vt_get(f"ip_addresses/{ip}")
    if code == 404:
        return {"ip": ip, "found": False}
    if code != 200:
        return {"ip": ip, "error": f"vt_status_{code}", **body}
    a = body.get("data", {}).get("attributes", {})
    return {"ip": ip, "found": True, **_stats(a),
            "country": a.get("country"), "as_owner": a.get("as_owner"), "tags": a.get("tags", [])}


# --- File hash --------------------------------------------------------------
def _hash_lookup(args: dict, ctx: ToolContext) -> dict:
    h = (args.get("hash") or "").strip()
    if not _HASH_RE.match(h):
        return {"hash": h, "error": "invalid hash (expect md5/sha1/sha256 hex)"}
    code, body = _vt_get(f"files/{h}")
    if code == 404:
        return {"hash": h, "found": False}
    if code != 200:
        return {"hash": h, "error": f"vt_status_{code}", **body}
    a = body.get("data", {}).get("attributes", {})
    return {"hash": h, "found": True, **_stats(a),
            "type_description": a.get("type_description"),
            "meaningful_name": a.get("meaningful_name"),
            "names": (a.get("names") or [])[:5]}


# --- Domain -----------------------------------------------------------------
def _domain_lookup(args: dict, ctx: ToolContext) -> dict:
    d = (args.get("domain") or "").strip().lower()
    if not _DOMAIN_RE.match(d):
        return {"domain": d, "error": "invalid domain"}
    code, body = _vt_get(f"domains/{d}")
    if code == 404:
        return {"domain": d, "found": False}
    if code != 200:
        return {"domain": d, "error": f"vt_status_{code}", **body}
    a = body.get("data", {}).get("attributes", {})
    return {"domain": d, "found": True, **_stats(a),
            "categories": list((a.get("categories") or {}).values())[:5]}


register(Tool(
    name="virustotal_ip_lookup",
    description="Reputation of a public IPv4 on VirusTotal. Use for external source/dest IPs "
                "in network/auth alerts. Private/local IPs are skipped automatically.",
    parameters={"ip": {"type": "string", "description": "Public IPv4 to look up"}},
    required=["ip"], handler=_ip_lookup,
))
register(Tool(
    name="lookup_file_hash",
    description="Reputation of a file hash (md5/sha1/sha256) on VirusTotal. Use for malware / "
                "file-integrity / process alerts that carry a hash.",
    parameters={"hash": {"type": "string", "description": "md5/sha1/sha256 hex"}},
    required=["hash"], handler=_hash_lookup,
))
register(Tool(
    name="lookup_domain",
    description="Reputation/categories of a domain on VirusTotal. Use for DNS/proxy/C2 alerts "
                "that reference a domain.",
    parameters={"domain": {"type": "string", "description": "domain name, e.g. evil.example.com"}},
    required=["domain"], handler=_domain_lookup,
))
