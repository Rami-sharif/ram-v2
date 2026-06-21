"""IP helpers shared across tools (private-IP skip is a locked RAM v1 rule)."""
import ipaddress
import re

from ..schemas import WazuhAlert

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def extract_public_ips(alert: WazuhAlert) -> list[str]:
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
