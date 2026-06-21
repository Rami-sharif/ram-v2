"""Read-only Wazuh Indexer (OpenSearch) investigation tools.

All queries use the least-privilege ram_agent_ro user against wazuh-alerts-*.
Failures (indexer down, no data) return {'error'|'count':...} so the agent can
continue. Results are size-capped (rows + per-log truncation).
"""
import datetime as dt
import logging
from typing import Any, Optional

import httpx

from ..config import get_settings
from ..memory import parse_alert_timestamp
from .registry import Tool, ToolContext, register

logger = logging.getLogger(__name__)
ALERTS_INDEX = "wazuh-alerts-*"


def _client() -> httpx.Client:
    s = get_settings()
    verify: Any = s.wazuh_indexer_ca_cert if s.wazuh_indexer_ca_cert else False
    return httpx.Client(
        base_url=s.wazuh_indexer_url,
        auth=(s.wazuh_indexer_ro_user, s.wazuh_indexer_ro_password),
        verify=verify, timeout=s.wazuh_indexer_timeout,
    )


def _search(body: dict) -> dict:
    """POST a search; returns {'hits':[...]} or {'error':...}. Never raises."""
    try:
        with _client() as c:
            resp = c.post(f"/{ALERTS_INDEX}/_search", json=body)
    except httpx.HTTPError as exc:
        logger.error("Indexer query failed: %s", exc)
        return {"error": f"indexer unreachable: {exc}"}
    if resp.status_code != 200:
        logger.warning("Indexer returned %s: %s", resp.status_code, resp.text[:200])
        return {"error": f"indexer status {resp.status_code}"}
    return {"raw": resp.json()}


def _shape(resp: dict) -> dict:
    """Turn a raw search response into compact, capped alert records."""
    if "error" in resp:
        return resp
    s = get_settings()
    hits = resp["raw"].get("hits", {}).get("hits", [])
    total = resp["raw"].get("hits", {}).get("total", {})
    out = []
    for h in hits[: s.tool_max_hits]:
        src = h.get("_source", {})
        rule = src.get("rule", {}) or {}
        data = src.get("data", {}) or {}
        full_log = (src.get("full_log") or "")[: s.tool_full_log_max_chars]
        out.append({
            "timestamp": src.get("timestamp"),
            "agent": (src.get("agent", {}) or {}).get("name"),
            "rule_id": rule.get("id"), "level": rule.get("level"),
            "description": rule.get("description"),
            "srcip": data.get("srcip"), "srcuser": data.get("srcuser"),
            "dstuser": data.get("dstuser"),
            "full_log": full_log,
        })
    return {"total": total.get("value") if isinstance(total, dict) else total,
            "returned": len(out), "alerts": out}


def _center_time(ctx: ToolContext) -> dt.datetime:
    ts = parse_alert_timestamp(ctx.alert.timestamp)
    return ts or dt.datetime.now(dt.timezone.utc)


def _related_logs(args: dict, ctx: ToolContext) -> dict:
    s = get_settings()
    host = args.get("host") or ctx.alert.agent.name
    minutes = int(args.get("minutes") or s.tool_related_window_minutes)
    center = _center_time(ctx)
    lo = (center - dt.timedelta(minutes=minutes)).isoformat()
    hi = (center + dt.timedelta(minutes=minutes)).isoformat()
    body = {
        "size": s.tool_max_hits,
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"term": {"agent.name": host}},
            {"range": {"timestamp": {"gte": lo, "lte": hi}}},
        ]}},
    }
    return {"host": host, "window_minutes": minutes, **_shape(_search(body))}


def _host_history(args: dict, ctx: ToolContext) -> dict:
    s = get_settings()
    host = args.get("host") or ctx.alert.agent.name
    body = {"size": s.tool_max_hits, "sort": [{"timestamp": "desc"}],
            "query": {"term": {"agent.name": host}}}
    return {"host": host, **_shape(_search(body))}


def _user_activity(args: dict, ctx: ToolContext) -> dict:
    s = get_settings()
    user = args.get("username") or ""
    if not user:
        return {"error": "username required"}
    body = {
        "size": s.tool_max_hits, "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"should": [
            {"term": {"data.srcuser": user}},
            {"term": {"data.dstuser": user}},
        ], "minimum_should_match": 1}},
    }
    res = {"username": user, **_shape(_search(body))}
    # Surface cross-host activity (lateral-movement signal).
    if "alerts" in res:
        res["hosts_seen"] = sorted({a["agent"] for a in res["alerts"] if a.get("agent")})
    return res


def _full_log_context(args: dict, ctx: ToolContext) -> dict:
    s = get_settings()
    host = args.get("host") or ctx.alert.agent.name
    minutes = int(args.get("minutes") or 5)
    center = _center_time(ctx)
    lo = (center - dt.timedelta(minutes=minutes)).isoformat()
    hi = (center + dt.timedelta(minutes=minutes)).isoformat()
    body = {
        "size": s.tool_max_hits, "sort": [{"timestamp": "asc"}],
        "_source": ["timestamp", "full_log", "rule.description"],
        "query": {"bool": {"filter": [
            {"term": {"agent.name": host}},
            {"range": {"timestamp": {"gte": lo, "lte": hi}}},
        ]}},
    }
    shaped = _shape(_search(body))
    if "alerts" in shaped:
        shaped["log_lines"] = [a["full_log"] for a in shaped.pop("alerts") if a.get("full_log")]
    return {"host": host, "window_minutes": minutes, **shaped}


register(Tool(
    name="get_related_logs",
    description="Other Wazuh alerts on the SAME host within +/- a time window around the "
                "trigger. Use to see what else happened on the host at the same time.",
    parameters={"host": {"type": "string", "description": "agent/host name (defaults to the alert's host)"},
                "minutes": {"type": "integer", "description": "window half-width in minutes"}},
    handler=_related_logs,
))
register(Tool(
    name="get_host_alert_history",
    description="Recent alert history for a host - is it already noisy/implicated? "
                "Use to judge whether this host has prior suspicious activity.",
    parameters={"host": {"type": "string", "description": "agent/host name (defaults to the alert's host)"}},
    handler=_host_history,
))
register(Tool(
    name="get_user_activity",
    description="Recent alerts referencing a user account (src/dst user) across hosts. "
                "Use for auth/login alerts to spot lateral movement or repeated failures.",
    parameters={"username": {"type": "string", "description": "account name from the alert"}},
    required=["username"], handler=_user_activity,
))
register(Tool(
    name="get_full_log_context",
    description="Raw full_log lines around the triggering event on the host (not just the "
                "matched line). Use to read surrounding activity for malware/process/file alerts.",
    parameters={"host": {"type": "string", "description": "agent/host name (defaults to alert host)"},
                "minutes": {"type": "integer", "description": "window half-width in minutes"}},
    handler=_full_log_context,
))
