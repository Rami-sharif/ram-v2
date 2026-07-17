"""IP helpers shared across tools (private-IP skip is a locked RAM v1 rule).

For newcomers: IP addresses come in two broad kinds. "Public" IPs are reachable on
the open internet and belong to outside parties, so they're worth checking against a
reputation service. "Private" (and loopback/link-local/reserved) IPs are internal
addresses like 192.168.x.x or 10.x.x.x, or 127.0.0.1 ("localhost") — they only mean
something inside a local network, so looking them up externally is pointless. That's
why the whole system skips private IPs: it saves wasted lookups and avoids noise."""
# Standard library module for parsing/classifying IPv4/IPv6 addresses.
import ipaddress
# Standard library regex module, used to scrape IPv4-looking substrings out of free text.
import re

# WazuhAlert is the shared alert schema; used here only for type-hinting extract_public_ips.
from ..schemas import WazuhAlert

# Regex matching a bare dotted-quad IPv4 address anywhere in a string (used on full_log text).
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_public_ip(value: str) -> bool:
    """True only if `value` is a valid, internet-routable IP. Anything invalid or
    internal returns False so callers can safely skip it."""
    try:
        # Parse the string into an ipaddress object; raises ValueError if not a valid IP.
        ip = ipaddress.ip_address(value)
    except ValueError:
        # Not even a valid IP address, so treat it as "not public" (nothing to look up).
        return False
    # Public means none of these locked-down/non-routable categories apply.
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def extract_public_ips(alert: WazuhAlert) -> list[str]:
    """Find every public IP mentioned in a Wazuh alert (Wazuh is the security monitor
    that generates these alerts). It looks both in the alert's structured fields and
    in the raw log line, then returns a de-duplicated list of only the public ones —
    exactly the IPs worth sending to a reputation service."""
    # Accumulator for every IP-looking string found before public/private filtering.
    candidates: list[str] = []
    # alert.data may be None; default to {} so .get() calls below are always safe.
    data = alert.data or {}
    # Check each common Wazuh field name that might carry a source/destination IP.
    for key in ("srcip", "src_ip", "dstip", "dst_ip", "dest_ip", "remote_ip"):
        v = data.get(key)
        # Only keep string values (guards against unexpected types in the alert payload).
        if isinstance(v, str):
            candidates.append(v)
    # Also scan the raw log line for any IPv4-looking substrings the structured fields missed.
    if alert.full_log:
        candidates.extend(_IP_RE.findall(alert.full_log))
    # Track which IPs we've already processed so duplicates in candidates aren't re-tested.
    seen: set[str] = set()
    # Final de-duplicated list of confirmed-public IPs, in first-seen order.
    public: list[str] = []
    for ip in candidates:
        if ip in seen:
            # Already handled this exact string; skip to avoid duplicate output/lookups.
            continue
        seen.add(ip)
        # Only keep IPs that pass the public-IP check (drops private/loopback/etc.).
        if is_public_ip(ip):
            public.append(ip)
    return public
