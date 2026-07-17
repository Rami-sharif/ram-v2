"""VirusTotal read-only tools: IP, file-hash, domain reputation.

For newcomers: VirusTotal is an online service that aggregates dozens of antivirus
engines and threat feeds. You send it an indicator (an IP address, a file hash, or a
domain) and it tells you how many engines flagged it as malicious — i.e. its
"reputation". A "hash" is a short fixed-length fingerprint of a file (e.g. sha256);
identical files always produce the same hash, so a hash uniquely identifies a file
without needing the file itself.

We talk to VirusTotal over its REST API: a REST API is just a set of web URLs you
send HTTP requests to (like a browser fetching a page), and it answers with JSON
(a text format of nested key/value data). These three tools are READ-ONLY — they
only fetch reputation info, they never change anything — so they are safe for the
automated agent to call."""
# Standard library logging for reporting VT request failures without crashing tool dispatch.
import logging
# Standard library regex, used to validate hash and domain shapes before calling out to VT.
import re
# Any is used for the loosely-typed "raw response body" return values.
from typing import Any

# HTTP client used to call the VirusTotal REST API.
import httpx

# Settings accessor: pulls the VT API key and per-call timeout from app config.
from ..config import get_settings
# Shared private/public IP classifier so we never waste a VT lookup on internal IPs.
from .netutil import is_public_ip
# Tool/ToolContext dataclasses and register() to add these handlers to TOOL_REGISTRY.
from .registry import Tool, ToolContext, register

# Module logger for this file.
logger = logging.getLogger(__name__)

# Base URL for VirusTotal's v3 REST API; individual lookups append a resource path.
VT_BASE = "https://www.virustotal.com/api/v3"
# Matches a bare MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) hash, case-insensitive.
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
# Matches a plausible domain name (labels separated by dots, ending in an alphabetic TLD).
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _vt_get(path: str) -> tuple[int, dict]:
    """One shared helper for every VirusTotal call: GET the given path and return
    (http_status_code, parsed_json_body). Centralizing it means all three lookups
    handle errors and authentication the same way."""
    # Load current settings (API key, timeout) fresh on each call. An API key is a
    # secret token that proves to VirusTotal who we are; the timeout is the max
    # seconds to wait before giving up so a slow network can't hang the agent.
    s = get_settings()
    try:
        # Issue the HTTP GET request against VT. A GET only reads data. We send the
        # API key in the "x-apikey" request header, which is how VT authenticates us.
        resp = httpx.get(f"{VT_BASE}/{path}", headers={"x-apikey": s.virustotal_api_key},
                         timeout=s.vt_timeout)
    except httpx.HTTPError as exc:
        # Network-level failure (timeout, DNS, connection refused, etc.); don't raise —
        # return a structured error instead so one bad lookup can't crash the agent.
        logger.error("VirusTotal request failed for %s: %s", path, exc)
        return 0, {"error": "request_failed", "detail": str(exc)}
    if resp.status_code == 200:
        # Success: hand back the status and parsed JSON body.
        return 200, resp.json()
    # Any non-200 (404 not found, 401/403 auth, etc.): return the status with an empty body.
    return resp.status_code, {}


def _stats(attrs: dict) -> dict:
    """Pull the common "how many engines flagged this" numbers out of any VT response,
    since IPs, files, and domains all report detections the same way."""
    # VT's detection-engine tallies: how many of its scanning engines voted each way.
    # Default to {} if the attribute is missing entirely so the .get() calls stay safe.
    s = attrs.get("last_analysis_stats", {}) or {}
    return {
        # Extract each detection bucket, defaulting to 0 counts when absent.
        # malicious/suspicious = engines that consider it dangerous; harmless/undetected
        # = engines that consider it clean or had no opinion.
        "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
        "harmless": s.get("harmless", 0), "undetected": s.get("undetected", 0),
        # VT's own reputation score for the resource (can be negative).
        "reputation": attrs.get("reputation"),
    }


# --- IP ---------------------------------------------------------------------
def _ip_lookup(args: dict, ctx: ToolContext) -> dict:
    # Pull the IP argument, defaulting to "" and trimming whitespace.
    ip = (args.get("ip") or "").strip()
    if not is_public_ip(ip):
        # Locked RAM v1 rule: never spend a VT call on a private/local/reserved IP.
        return {"ip": ip, "skipped": True, "reason": "private/local/reserved IP"}
    # Query VT's IP address endpoint for this address.
    code, body = _vt_get(f"ip_addresses/{ip}")
    if code == 404:
        # VT has no record of this IP at all.
        return {"ip": ip, "found": False}
    if code != 200:
        # Any other non-success status: surface it plus whatever body VT returned.
        return {"ip": ip, "error": f"vt_status_{code}", **body}
    # Drill into the nested VT response shape to get the resource's attributes.
    a = body.get("data", {}).get("attributes", {})
    # Merge detection stats with IP-specific metadata (country, AS owner, tags).
    return {"ip": ip, "found": True, **_stats(a),
            "country": a.get("country"), "as_owner": a.get("as_owner"), "tags": a.get("tags", [])}


# --- File hash --------------------------------------------------------------
def _hash_lookup(args: dict, ctx: ToolContext) -> dict:
    # Pull the hash argument, defaulting to "" and trimming whitespace.
    h = (args.get("hash") or "").strip()
    if not _HASH_RE.match(h):
        # Reject anything that isn't a well-formed md5/sha1/sha256 hex string up front.
        return {"hash": h, "error": "invalid hash (expect md5/sha1/sha256 hex)"}
    # Query VT's file endpoint using the hash as the resource id.
    code, body = _vt_get(f"files/{h}")
    if code == 404:
        # VT has never seen this hash.
        return {"hash": h, "found": False}
    if code != 200:
        # Any other failure status: surface it with whatever body came back.
        return {"hash": h, "error": f"vt_status_{code}", **body}
    # Drill into the VT response to get file attributes.
    a = body.get("data", {}).get("attributes", {})
    # Merge detection stats with file-type metadata and a capped list of known filenames.
    return {"hash": h, "found": True, **_stats(a),
            "type_description": a.get("type_description"),
            "meaningful_name": a.get("meaningful_name"),
            "names": (a.get("names") or [])[:5]}


# --- Domain -----------------------------------------------------------------
def _domain_lookup(args: dict, ctx: ToolContext) -> dict:
    # Pull the domain argument, defaulting to "", trimming, and lower-casing for consistency.
    d = (args.get("domain") or "").strip().lower()
    if not _DOMAIN_RE.match(d):
        # Reject malformed domain strings before calling out to VT.
        return {"domain": d, "error": "invalid domain"}
    # Query VT's domain endpoint.
    code, body = _vt_get(f"domains/{d}")
    if code == 404:
        # VT has no record of this domain.
        return {"domain": d, "found": False}
    if code != 200:
        # Any other failure status: surface it with whatever body came back.
        return {"domain": d, "error": f"vt_status_{code}", **body}
    # Drill into the VT response to get domain attributes.
    a = body.get("data", {}).get("attributes", {})
    # Merge detection stats with a capped list of category labels (values only, not the keying engine).
    return {"domain": d, "found": True, **_stats(a),
            "categories": list((a.get("categories") or {}).values())[:5]}


# --- Register the three tools -------------------------------------------------
# register() adds a Tool to the shared TOOL_REGISTRY that the automated agent reads.
# Each Tool bundles: a name the model uses to call it, a description that tells the
# model WHEN to use it, a JSON-schema `parameters` block describing the arguments,
# which args are `required`, and the `handler` function to run when it's called.

# Register the IP-reputation tool so the agent loop can call it as "virustotal_ip_lookup".
register(Tool(
    name="virustotal_ip_lookup",
    description="Reputation of a public IPv4 on VirusTotal. Use for external source/dest IPs "
                "in network/auth alerts. Private/local IPs are skipped automatically.",
    parameters={"ip": {"type": "string", "description": "Public IPv4 to look up"}},
    required=["ip"], handler=_ip_lookup,
))
# Register the hash-reputation tool as "lookup_file_hash".
register(Tool(
    name="lookup_file_hash",
    description="Reputation of a file hash (md5/sha1/sha256) on VirusTotal. Use for malware / "
                "file-integrity / process alerts that carry a hash.",
    parameters={"hash": {"type": "string", "description": "md5/sha1/sha256 hex"}},
    required=["hash"], handler=_hash_lookup,
))
# Register the domain-reputation tool as "lookup_domain".
register(Tool(
    name="lookup_domain",
    description="Reputation/categories of a domain on VirusTotal. Use for DNS/proxy/C2 alerts "
                "that reference a domain.",
    parameters={"domain": {"type": "string", "description": "domain name, e.g. evil.example.com"}},
    required=["domain"], handler=_domain_lookup,
))
