"""Tool functions available to the agent.

Phase 1 has exactly one external tool: a VirusTotal IP lookup. Per RAM v1 design,
we never call VirusTotal for private / local / reserved IPs.
"""
import ipaddress
import logging
import re
from typing import Any

import httpx

from .config import get_settings
from .schemas import WazuhAlert

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def is_public_ip(value: str) -> bool:
    """True only for routable public IPs (skip private/loopback/link-local/reserved)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def extract_public_ips(alert: WazuhAlert) -> list[str]:
    """Pull candidate IPs from the common Wazuh fields plus the raw log, dedup,
    keep only public ones, preserving first-seen order."""
    candidates: list[str] = []
    data = alert.data or {}
    for key in ("srcip", "src_ip", "dstip", "dst_ip", "dest_ip", "remote_ip"):
        v = data.get(key)
        if isinstance(v, str):
            candidates.append(v)
    if alert.full_log:
        candidates.extend(_IP_RE.findall(alert.full_log))

    seen: set[str] = set()
    public: list[str] = []
    for ip in candidates:
        if ip in seen:
            continue
        seen.add(ip)
        if is_public_ip(ip):
            public.append(ip)
    return public


def virustotal_ip_lookup(ip: str) -> dict[str, Any]:
    """Look up an IP's reputation on VirusTotal v3.

    Returns a compact, structured summary. Private/local IPs are skipped before
    any network call. All failures are returned as structured errors (never raised)
    so the agent loop can reason about them rather than crashing.
    """
    if not is_public_ip(ip):
        logger.info("Skipping VirusTotal lookup for non-public IP %s", ip)
        return {"ip": ip, "skipped": True, "reason": "private/local/reserved IP"}

    settings = get_settings()
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        resp = httpx.get(
            f"{VT_BASE_URL}/ip_addresses/{ip}",
            headers=headers,
            timeout=settings.vt_timeout,
        )
    except httpx.HTTPError as exc:
        logger.error("VirusTotal request failed for %s: %s", ip, exc)
        return {"ip": ip, "error": "request_failed", "detail": str(exc)}

    if resp.status_code == 404:
        return {"ip": ip, "found": False, "reason": "not found in VirusTotal"}
    if resp.status_code == 429:
        logger.warning("VirusTotal rate limit hit for %s", ip)
        return {"ip": ip, "error": "rate_limited"}
    if resp.status_code != 200:
        logger.error("VirusTotal returned %s for %s", resp.status_code, ip)
        return {"ip": ip, "error": "unexpected_status", "status": resp.status_code}

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    summary = {
        "ip": ip,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "tags": attrs.get("tags", []),
    }
    logger.info(
        "VirusTotal %s: malicious=%s suspicious=%s reputation=%s",
        ip, summary["malicious"], summary["suspicious"], summary["reputation"],
    )
    return summary
