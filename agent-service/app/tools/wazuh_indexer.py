"""Read-only Wazuh Indexer (OpenSearch) investigation tools.

All queries use the least-privilege ram_agent_ro user against wazuh-alerts-*.
Failures (indexer down, no data) return {'error'|'count':...} so the agent can
continue. Results are size-capped (rows + per-log truncation).
"""
import datetime as dt
import json
import logging
import re
from typing import Any, Optional

import httpx

from ..config import get_settings
from ..memory import parse_alert_timestamp
from .registry import Tool, ToolContext, register, register_interactive

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


# --------------------------------------------------------------------------- #
# Generalized query tool (interactive console chat only).
#
# One tool that replaces many narrow ones. Every parameter is validated against
# allowlists BEFORE any query is built — unknown fields/operators are rejected
# with {"error": ...} and never passed through to OpenSearch. It is registered
# into INTERACTIVE_REGISTRY (not the automated read-only TOOL_REGISTRY).
# --------------------------------------------------------------------------- #

# field -> value kind. Only these fields may be queried or grouped on.
_QUERY_FIELDS: dict[str, str] = {
    "rule.id": "string",
    "rule.level": "numeric",
    "agent.name": "string",
    "data.srcip": "string",
    "data.dstuser": "string",
    "data.srcuser": "string",
}
_OPERATORS = ("equals", "contains", "range")
_TIME_BUCKET_RE = re.compile(r"^\d+[smhd]$")
_RELATIVE_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class _QueryError(ValueError):
    """Raised on invalid query parameters; surfaced as {'error': ...}."""


def _parse_time_range(time_range: Any) -> Optional[dict]:
    """Return a timestamp range clause, or None if no time_range given.

    Accepts a relative string ('24h', '30m', '7d') or a dict {start, end} of ISO
    timestamps (at least one of start/end). Raises _QueryError on bad input."""
    if time_range in (None, "", {}):
        return None
    now = dt.datetime.now(dt.timezone.utc)
    if isinstance(time_range, str):
        s = time_range.strip()
        m = _RELATIVE_RE.match(s)
        if m:
            secs = int(m.group(1)) * _UNIT_SECONDS[m.group(2)]
            lo = (now - dt.timedelta(seconds=secs)).isoformat()
            return {"range": {"timestamp": {"gte": lo, "lte": now.isoformat()}}}
        if s.startswith("{"):  # the model may pass a JSON-encoded {start,end}
            try:
                time_range = json.loads(s)
            except json.JSONDecodeError:
                raise _QueryError(f"time_range {time_range!r} must be relative ('24h') or {{start,end}}")
        else:
            raise _QueryError(f"time_range {time_range!r} must be relative like '24h', '30m', '7d'")
    if isinstance(time_range, dict):
        bounds = {}
        if time_range.get("start"):
            bounds["gte"] = time_range["start"]
        if time_range.get("end"):
            bounds["lte"] = time_range["end"]
        if not bounds:
            raise _QueryError("time_range object needs 'start' and/or 'end' (ISO timestamps)")
        return {"range": {"timestamp": bounds}}
    raise _QueryError("time_range must be a relative string or {start,end} object")


def _field_clause(field: str, operator: str, value: Any) -> dict:
    """Validate + build one query clause. Raises _QueryError on any mismatch."""
    if field not in _QUERY_FIELDS:
        raise _QueryError(f"field {field!r} not allowed (allowed: {sorted(_QUERY_FIELDS)})")
    if operator not in _OPERATORS:
        raise _QueryError(f"operator {operator!r} not allowed (allowed: {list(_OPERATORS)})")
    kind = _QUERY_FIELDS[field]

    if operator == "equals":
        if value is None or value == "":
            raise _QueryError("equals requires a value")
        if kind == "numeric":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise _QueryError(f"{field} is numeric; equals value {value!r} is not an integer")
        return {"term": {field: value}}

    if operator == "contains":
        if kind != "string":
            raise _QueryError(f"contains is only valid on string fields, not {field!r}")
        if not isinstance(value, str) or not value:
            raise _QueryError("contains requires a non-empty string value")
        return {"wildcard": {field: f"*{value}*"}}

    # range
    if kind != "numeric":
        raise _QueryError(f"range is only valid on numeric fields, not {field!r}")
    if isinstance(value, str):  # the model passes args as strings; accept JSON-encoded bounds
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise _QueryError("range value must be an object like {\"gte\":3,\"lte\":10}")
    if not isinstance(value, dict):
        raise _QueryError("range requires a value object with 'gte' and/or 'lte'")
    bounds = {}
    for k in ("gte", "lte", "gt", "lt"):
        if k in value and value[k] is not None:
            try:
                bounds[k] = int(value[k])
            except (TypeError, ValueError):
                raise _QueryError(f"range bound {k}={value[k]!r} is not an integer")
    if not bounds:
        raise _QueryError("range requires at least one of gte/lte/gt/lt")
    return {"range": {field: bounds}}


def _aggregate(body_filter: list, group_by: Optional[str], time_bucket: Optional[str]) -> dict:
    """Build + run an aggregation (terms and/or date_histogram). No raw alerts."""
    s = get_settings()
    cap = s.tool_max_agg_buckets
    if not group_by and not time_bucket:
        return {"error": "aggregate mode requires group_by and/or time_bucket"}
    if group_by and group_by not in _QUERY_FIELDS:
        return {"error": f"group_by {group_by!r} not allowed (allowed: {sorted(_QUERY_FIELDS)})"}
    if time_bucket and not _TIME_BUCKET_RE.match(time_bucket):
        return {"error": f"time_bucket {time_bucket!r} must look like '1h', '30m', '1d'"}

    if time_bucket:
        agg: dict = {"date_histogram": {"field": "timestamp", "fixed_interval": time_bucket,
                                        "min_doc_count": 1}}
        if group_by:
            agg["aggs"] = {"grp": {"terms": {"field": group_by, "size": cap}}}
    else:
        agg = {"terms": {"field": group_by, "size": cap}}

    body = {"size": 0, "aggs": {"agg": agg}}
    if body_filter:
        body["query"] = {"bool": {"filter": body_filter}}
    resp = _search(body)
    if "error" in resp:
        return resp
    raw_buckets = resp["raw"].get("aggregations", {}).get("agg", {}).get("buckets", [])
    out = []
    for b in raw_buckets[:cap]:
        entry = {"key": b.get("key_as_string") or b.get("key"), "doc_count": b.get("doc_count")}
        if "grp" in b:
            entry["groups"] = [{"key": g.get("key"), "doc_count": g.get("doc_count")}
                               for g in b["grp"].get("buckets", [])[:cap]]
        out.append(entry)
    return {"mode": "aggregate", "group_by": group_by, "time_bucket": time_bucket,
            "returned_buckets": len(out), "total_buckets": len(raw_buckets),
            "truncated": len(raw_buckets) > cap, "buckets": out}


def _query_wazuh_logs(args: dict, ctx: ToolContext) -> dict:
    s = get_settings()
    mode = (args.get("mode") or "search").lower()
    if mode not in ("search", "aggregate"):
        return {"error": f"mode {mode!r} must be 'search' or 'aggregate'"}
    try:
        clauses: list = []
        # A field condition is optional (an aggregate over all alerts in a time
        # range is valid), but if a field is named it must fully validate.
        if args.get("field"):
            clauses.append(_field_clause(args.get("field"), args.get("operator") or "equals",
                                         args.get("value")))
        time_clause = _parse_time_range(args.get("time_range"))
        if time_clause:
            clauses.append(time_clause)
    except _QueryError as exc:
        return {"error": str(exc)}

    if mode == "aggregate":
        return _aggregate(clauses, args.get("group_by") or None, args.get("time_bucket") or None)

    # search mode: same shape/capping as the narrow tools (reuses _shape/tool_max_hits)
    body: dict = {"size": s.tool_max_hits, "sort": [{"timestamp": "desc"}]}
    if clauses:
        body["query"] = {"bool": {"filter": clauses}}
    return {"mode": "search", "field": args.get("field"), "operator": args.get("operator"),
            **_shape(_search(body))}


register_interactive(Tool(
    name="query_wazuh_logs",
    description=(
        "Flexible read-only query over Wazuh alerts (indexer). Use instead of the narrow "
        "tools when you need a custom filter or counts. mode='search' returns matching "
        "alerts; mode='aggregate' returns COUNTS grouped by a field and/or time bucket "
        "(not raw alerts). Only these fields are queryable: rule.id, rule.level, agent.name, "
        "data.srcip, data.dstuser, data.srcuser."
    ),
    parameters={
        "field": {"type": "string",
                  "description": "field to filter on: rule.id | rule.level | agent.name | "
                                 "data.srcip | data.dstuser | data.srcuser (optional for aggregate)"},
        "operator": {"type": "string", "enum": list(_OPERATORS),
                     "description": "equals (any field), contains (string fields), range (numeric fields)"},
        "value": {"type": "string",
                  "description": "match value; for range pass an object like {\"gte\":3,\"lte\":10}"},
        "time_range": {"type": "string",
                       "description": "relative like '24h'/'7d', or an object {start,end} of ISO timestamps"},
        "mode": {"type": "string", "enum": ["search", "aggregate"], "description": "default 'search'"},
        "group_by": {"type": "string", "description": "aggregate mode: field to group counts by"},
        "time_bucket": {"type": "string", "description": "aggregate mode: bucket size e.g. '1h', '1d'"},
    },
    handler=_query_wazuh_logs,
))
