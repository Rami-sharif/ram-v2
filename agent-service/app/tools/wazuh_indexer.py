"""Read-only Wazuh Indexer (OpenSearch) investigation tools.

Background for newcomers:
- Wazuh is an open-source security monitoring platform. When something notable
  happens on a machine ("host"/"agent") it raises an *alert*. Those alerts are
  stored in the "Wazuh Indexer", which is really OpenSearch (an Elasticsearch
  fork) — a search engine you talk to over an HTTP REST API using JSON queries.
- The JSON query language is called the "Query DSL" (Domain-Specific Language).
  Instead of SQL, you POST a JSON body describing filters, sorting, and
  aggregations. The helpers below build those JSON bodies for you.
- "least-privilege" is a security principle: give code only the access it needs.
  Here every query runs as the read-only ram_agent_ro user, so a bug (or a
  compromised model) can *read* alerts but never modify or delete anything.

All queries use the least-privilege ram_agent_ro user against wazuh-alerts-*.
Failures (indexer down, no data) return {'error'|'count':...} so the agent can
continue instead of crashing. Results are size-capped (a limit on the number of
rows returned, plus per-log truncation) so one noisy host can't overflow the
prompt we send to the model.
"""
# Standard library datetime module, used for time-window queries (aliased dt to avoid clashing).
import datetime as dt
# Used to decode/encode JSON-encoded query parameters the model may pass as strings.
import json
# Standard library logging for indexer-failure diagnostics.
import logging
# Standard library regex, used to validate time-bucket/relative-time syntax.
import re
# Typing helpers for loosely-typed values and optional fields.
from typing import Any, Optional

# HTTP client used to talk to the Wazuh Indexer's OpenSearch-compatible REST API.
import httpx

# Settings accessor: indexer URL/credentials/timeouts and result-size caps.
from ..config import get_settings
# Shared timestamp parser so alert.timestamp (various formats) becomes a real datetime.
from ..memory import parse_alert_timestamp
# Tool/ToolContext dataclasses and both register functions (automated + interactive tools live here).
from .registry import Tool, ToolContext, register, register_interactive

# Module logger for this file.
logger = logging.getLogger(__name__)
# Index pattern covering all Wazuh alert indices. An "index" in OpenSearch is like
# a database table; Wazuh creates a new one per day (wazuh-alerts-2026-07-15, etc.),
# so the trailing "*" wildcard tells OpenSearch to search across all of them at once.
ALERTS_INDEX = "wazuh-alerts-*"


def _client() -> httpx.Client:
    # Load current settings for indexer connection details.
    s = get_settings()
    # TLS ("https") verification: if a CA certificate file is configured, use it to
    # confirm we're really talking to the indexer; otherwise pass False to skip the
    # check (only acceptable for local/self-signed dev setups).
    verify: Any = s.wazuh_indexer_ca_cert if s.wazuh_indexer_ca_cert else False
    # Build an httpx client pre-configured with base URL, basic auth (the read-only
    # username/password), TLS verify, and a request timeout. httpx is a modern HTTP
    # library; this client object carries these settings for every request we make.
    return httpx.Client(
        base_url=s.wazuh_indexer_url,
        auth=(s.wazuh_indexer_ro_user, s.wazuh_indexer_ro_password),
        verify=verify, timeout=s.wazuh_indexer_timeout,
    )


def _search(body: dict) -> dict:
    """Send one search request to OpenSearch and return a plain dict.

    `body` is the JSON Query DSL describing what to look for. On success this
    returns {'raw': <full response>}; on any failure it returns {'error': ...}.
    It NEVER raises, so callers can keep going even if the indexer is down."""
    try:
        # `with ... as c:` is a context manager. It guarantees the client (and its
        # network connection) is properly closed when the block ends, even if an
        # error is thrown — like automatically calling c.close() in a finally block.
        with _client() as c:
            # Issue the search request. The "_search" endpoint is OpenSearch's REST
            # API for querying; we POST the JSON query body to it.
            resp = c.post(f"/{ALERTS_INDEX}/_search", json=body)
    except httpx.HTTPError as exc:
        # Network-level failure (indexer down, timeout, etc.): report but don't raise.
        logger.error("Indexer query failed: %s", exc)
        return {"error": f"indexer unreachable: {exc}"}
    if resp.status_code != 200:
        # Non-200 response from OpenSearch (bad query, auth issue, etc.).
        logger.warning("Indexer returned %s: %s", resp.status_code, resp.text[:200])
        return {"error": f"indexer status {resp.status_code}"}
    # Success: wrap the raw JSON response for downstream shaping.
    return {"raw": resp.json()}


def _shape(resp: dict) -> dict:
    """Turn a raw OpenSearch response into compact, capped alert records.

    The raw response is deeply nested and verbose. This pulls out just the fields
    the model cares about, and limits how many records (and how much text per log)
    come back — keeping the data small enough to fit in the model's prompt."""
    if "error" in resp:
        # Pass errors through unchanged; nothing to shape.
        return resp
    # Load settings fresh to get the current max-hits and log-truncation limits.
    s = get_settings()
    # OpenSearch nests results as response["hits"]["hits"] — an outer "hits" object
    # containing a "hits" list of matching documents. .get(..., {}) safely returns
    # an empty dict/list if a level is missing, avoiding KeyError crashes.
    hits = resp["raw"].get("hits", {}).get("hits", [])
    # Total match count metadata (may be a dict with "value" or a bare number, depending on version).
    total = resp["raw"].get("hits", {}).get("total", {})
    # Collector for the shaped/compact alert records.
    out = []
    # Slicing with [: s.tool_max_hits] keeps at most that many rows — a simple cap so
    # a host with thousands of alerts can't produce a giant result.
    for h in hits[: s.tool_max_hits]:
        # Each matching document wraps its real fields inside "_source"; that's where
        # the actual alert data lives.
        src = h.get("_source", {})
        # Nested rule metadata. In Wazuh a "rule" is the detection that fired: it has
        # an id, a "level" (severity — higher means more serious), and a description.
        # The `or {}` guards against the field being present but set to None.
        rule = src.get("rule", {}) or {}
        # Nested structured data fields Wazuh parsed out of the log, such as srcip
        # (source IP address) and src/dst user (the accounts involved).
        data = src.get("data", {}) or {}
        # Truncate the raw log line to a max number of characters so a single huge
        # log entry can't eat up the whole result-size budget.
        full_log = (src.get("full_log") or "")[: s.tool_full_log_max_chars]
        out.append({
            "timestamp": src.get("timestamp"),
            # Host/agent name the alert originated from.
            "agent": (src.get("agent", {}) or {}).get("name"),
            "rule_id": rule.get("id"), "level": rule.get("level"),
            "description": rule.get("description"),
            "srcip": data.get("srcip"), "srcuser": data.get("srcuser"),
            "dstuser": data.get("dstuser"),
            "full_log": full_log,
        })
    # Return the total match count, how many were actually returned (post-cap), and the records.
    # `total` may be a dict {"value": N} or a bare number depending on the OpenSearch
    # version, so isinstance() picks the right one out.
    return {"total": total.get("value") if isinstance(total, dict) else total,
            "returned": len(out), "alerts": out}


def _center_time(ctx: ToolContext) -> dt.datetime:
    # Many tools search a time WINDOW centered on the alert that triggered this run.
    # First try to parse that triggering alert's own timestamp to use as the center.
    ts = parse_alert_timestamp(ctx.alert.timestamp)
    # If the timestamp couldn't be parsed, fall back to "now" in UTC. (`a or b`
    # returns b when a is None/empty — a common Python default-value idiom.)
    return ts or dt.datetime.now(dt.timezone.utc)


def _related_logs(args: dict, ctx: ToolContext) -> dict:
    # Load settings for the default related-window size and hit cap.
    s = get_settings()
    # Use the model-supplied host, defaulting to the triggering alert's own host.
    host = args.get("host") or ctx.alert.agent.name
    # Half-width of the time window in minutes, defaulting to the configured default.
    minutes = int(args.get("minutes") or s.tool_related_window_minutes)
    # Anchor the window on the triggering alert's timestamp (or now, if unparsable).
    center = _center_time(ctx)
    # Lower bound of the window: center minus the half-width. .isoformat() renders the
    # datetime as an ISO 8601 string (e.g. "2026-07-15T12:00:00+00:00") for the query.
    lo = (center - dt.timedelta(minutes=minutes)).isoformat()
    # Upper bound of the window: center plus the half-width.
    hi = (center + dt.timedelta(minutes=minutes)).isoformat()
    # Build the OpenSearch query body (the JSON DSL). Reading it inside-out:
    #  - "term" = exact match; here agent.name must equal this host.
    #  - "range" with gte/lte = timestamp between lo and hi (greater-than-or-equal /
    #    less-than-or-equal).
    #  - "bool"/"filter" combines conditions with AND (all must match). "filter" is
    #    used instead of "must" because we only care about yes/no matching, not
    #    relevance scoring — which is faster.
    #  - "sort" desc = newest first; "size" caps how many rows come back.
    body = {
        "size": s.tool_max_hits,
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"term": {"agent.name": host}},
            {"range": {"timestamp": {"gte": lo, "lte": hi}}},
        ]}},
    }
    # Run the search and merge the shaped results into a dict that also echoes back the
    # host/window. The ** operator "spreads" the shaped dict's keys into this new dict.
    return {"host": host, "window_minutes": minutes, **_shape(_search(body))}


def _host_history(args: dict, ctx: ToolContext) -> dict:
    # Load settings for the hit cap.
    s = get_settings()
    # Use the model-supplied host, defaulting to the triggering alert's own host.
    host = args.get("host") or ctx.alert.agent.name
    # Build a simple query: all alerts for this host, newest first, no time bound.
    body = {"size": s.tool_max_hits, "sort": [{"timestamp": "desc"}],
            "query": {"term": {"agent.name": host}}}
    # Run the search and merge the shaped results with the host metadata.
    return {"host": host, **_shape(_search(body))}


def _user_activity(args: dict, ctx: ToolContext) -> dict:
    # Load settings for the hit cap.
    s = get_settings()
    # The account name to search for; empty string if not supplied.
    user = args.get("username") or ""
    if not user:
        # A username is mandatory for this tool.
        return {"error": "username required"}
    # Build a query matching this user as either the source OR destination user.
    # In the bool query, "should" clauses are OR conditions; minimum_should_match=1
    # means at least one of them must match (so srcuser==user OR dstuser==user).
    body = {
        "size": s.tool_max_hits, "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"should": [
            {"term": {"data.srcuser": user}},
            {"term": {"data.dstuser": user}},
        ], "minimum_should_match": 1}},
    }
    # Run the search and merge the shaped results with the username metadata.
    res = {"username": user, **_shape(_search(body))}
    # "Lateral movement" is when an attacker who compromised one account uses it to
    # hop between machines. Seeing the same user across many hosts is a warning sign,
    # so we surface the distinct set of hosts they appeared on.
    if "alerts" in res:
        # {a["agent"] for ...} is a set comprehension: it auto-removes duplicates.
        # sorted(...) turns it back into an ordered list for stable output.
        res["hosts_seen"] = sorted({a["agent"] for a in res["alerts"] if a.get("agent")})
    return res


def _full_log_context(args: dict, ctx: ToolContext) -> dict:
    # Load settings for the hit cap.
    s = get_settings()
    # Use the model-supplied host, defaulting to the triggering alert's own host.
    host = args.get("host") or ctx.alert.agent.name
    # Half-width of the time window in minutes, defaulting to 5 if not supplied.
    minutes = int(args.get("minutes") or 5)
    # Anchor the window on the triggering alert's timestamp (or now, if unparsable).
    center = _center_time(ctx)
    # Lower bound of the window.
    lo = (center - dt.timedelta(minutes=minutes)).isoformat()
    # Upper bound of the window.
    hi = (center + dt.timedelta(minutes=minutes)).isoformat()
    # Build the query: host + time-range filter, this time sorted "asc" (ascending =
    # oldest first) so the logs read in the order events actually happened. The
    # "_source" list is field-filtering: it tells OpenSearch to return only these
    # fields instead of the whole document, keeping the response small.
    body = {
        "size": s.tool_max_hits, "sort": [{"timestamp": "asc"}],
        "_source": ["timestamp", "full_log", "rule.description"],
        "query": {"bool": {"filter": [
            {"term": {"agent.name": host}},
            {"range": {"timestamp": {"gte": lo, "lte": hi}}},
        ]}},
    }
    # Shape the raw response the same way as other tools (for consistent capping/truncation).
    shaped = _shape(_search(body))
    if "alerts" in shaped:
        # This tool only wants the raw log text. list.pop("alerts") both removes the
        # "alerts" key and returns its value; the comprehension then keeps just each
        # record's full_log line, dropping the other fields.
        shaped["log_lines"] = [a["full_log"] for a in shaped.pop("alerts") if a.get("full_log")]
    return {"host": host, "window_minutes": minutes, **shaped}


# Each register(Tool(...)) call below adds one tool to the shared registry (see
# registry.py). The agent loop reads that registry to tell the model which tools
# exist and what they do — the "description" text is literally what the model reads
# to decide when to call each tool. These four go into the AUTOMATED read-only
# toolset that the unattended agent is allowed to use.

# Register "get_related_logs" — other alerts on the same host within a time window.
register(Tool(
    name="get_related_logs",
    description="Other Wazuh alerts on the SAME host within +/- a time window around the "
                "trigger. Use to see what else happened on the host at the same time.",
    parameters={"host": {"type": "string", "description": "agent/host name (defaults to the alert's host)"},
                "minutes": {"type": "integer", "description": "window half-width in minutes"}},
    handler=_related_logs,
))
# Register "get_host_alert_history" — full recent alert history for a host, no time bound.
register(Tool(
    name="get_host_alert_history",
    description="Recent alert history for a host - is it already noisy/implicated? "
                "Use to judge whether this host has prior suspicious activity.",
    parameters={"host": {"type": "string", "description": "agent/host name (defaults to the alert's host)"}},
    handler=_host_history,
))
# Register "get_user_activity" — cross-host alerts referencing a given user account.
register(Tool(
    name="get_user_activity",
    description="Recent alerts referencing a user account (src/dst user) across hosts. "
                "Use for auth/login alerts to spot lateral movement or repeated failures.",
    parameters={"username": {"type": "string", "description": "account name from the alert"}},
    required=["username"], handler=_user_activity,
))
# Register "get_full_log_context" — raw log lines surrounding the triggering event.
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
# One flexible tool that replaces many narrow ones. The security idea here is the
# "allowlist" (a.k.a. whitelist): rather than trying to block bad input, we define
# the small set of things that ARE permitted and reject everything else. Every
# parameter is validated against these allowlists BEFORE any query is built — an
# unknown field or operator is rejected with {"error": ...} and never reaches
# OpenSearch. This stops the model from crafting arbitrary/dangerous queries.
#
# It is registered into INTERACTIVE_REGISTRY (the human-driven console chat), NOT
# the automated read-only TOOL_REGISTRY, so the unattended agent never gets it.
# --------------------------------------------------------------------------- #

# The allowlist of queryable fields, mapping each field name to its "kind"
# (string or numeric). Only these fields may be filtered or grouped on; the kind
# controls which operators are legal (e.g. "contains" only makes sense on strings).
_QUERY_FIELDS: dict[str, str] = {
    "rule.id": "string",
    "rule.level": "numeric",
    "agent.name": "string",
    "data.srcip": "string",
    "data.dstuser": "string",
    "data.srcuser": "string",
}
# The only comparison operators this tool supports (another allowlist).
_OPERATORS = ("equals", "contains", "range")
# A compiled regular expression ("regex" — a pattern for matching text). This one
# validates a time_bucket string like "1h", "30m", "1d": ^\d+ = one or more digits
# at the start, [smhd] = exactly one unit letter (second/minute/hour/day), $ = end.
# Pre-compiling with re.compile makes repeated matching faster.
_TIME_BUCKET_RE = re.compile(r"^\d+[smhd]$")
# Same idea, but the parentheses create capture "groups" so we can pull the number
# and the unit out separately from a relative time like "24h" -> ("24", "h").
_RELATIVE_RE = re.compile(r"^(\d+)([smhd])$")
# Lookup table converting each unit letter to a number of seconds, used to turn a
# relative window like "24h" into an actual duration.
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


# A custom exception type. Subclassing ValueError lets the validation helpers below
# `raise _QueryError(...)` on bad input, and one try/except in the handler catches
# them all and turns them into a clean {'error': ...} response.
class _QueryError(ValueError):
    """Raised on invalid query parameters; surfaced to the caller as {'error': ...}."""


def _parse_time_range(time_range: Any) -> Optional[dict]:
    """Return a timestamp range clause, or None if no time_range given.

    Accepts a relative string ('24h', '30m', '7d') or a dict {start, end} of ISO
    timestamps (at least one of start/end). Raises _QueryError on bad input."""
    if time_range in (None, "", {}):
        # No time range requested; caller treats this as "no time filter".
        return None
    # Current time, used as the reference point for relative windows.
    now = dt.datetime.now(dt.timezone.utc)
    if isinstance(time_range, str):
        # Strip incidental whitespace from the model-supplied string.
        s = time_range.strip()
        # Try to match the relative-time shorthand form first (e.g. "24h"). .match
        # returns a match object (truthy) if the pattern fits, or None if it doesn't.
        m = _RELATIVE_RE.match(s)
        if m:
            # group(1) is the number, group(2) is the unit letter; multiply to get a
            # duration in seconds (e.g. 24 * 3600 = 86400 seconds for "24h").
            secs = int(m.group(1)) * _UNIT_SECONDS[m.group(2)]
            # Window = [now - duration, now]. timedelta represents a length of time.
            lo = (now - dt.timedelta(seconds=secs)).isoformat()
            return {"range": {"timestamp": {"gte": lo, "lte": now.isoformat()}}}
        if s.startswith("{"):  # the model may pass a JSON-encoded {start,end}
            try:
                # Attempt to decode the JSON object form.
                time_range = json.loads(s)
            except json.JSONDecodeError:
                # Not valid JSON either: neither accepted shape matched.
                raise _QueryError(f"time_range {time_range!r} must be relative ('24h') or {{start,end}}")
        else:
            # Doesn't match relative shorthand and isn't JSON: reject.
            raise _QueryError(f"time_range {time_range!r} must be relative like '24h', '30m', '7d'")
    if isinstance(time_range, dict):
        # Build the range bounds only from whichever of start/end were actually provided.
        bounds = {}
        if time_range.get("start"):
            bounds["gte"] = time_range["start"]
        if time_range.get("end"):
            bounds["lte"] = time_range["end"]
        if not bounds:
            # Neither start nor end supplied: nothing to filter on, so reject.
            raise _QueryError("time_range object needs 'start' and/or 'end' (ISO timestamps)")
        return {"range": {"timestamp": bounds}}
    # time_range was neither a recognized string form nor a dict.
    raise _QueryError("time_range must be a relative string or {start,end} object")


def _field_clause(field: str, operator: str, value: Any) -> dict:
    """Validate one field/operator/value triple and build its OpenSearch clause.

    A "clause" is one condition in the query (e.g. rule.level >= 10). This checks
    the field and operator against the allowlists and that the value has the right
    type, then returns the matching bit of Query DSL. Raises _QueryError on any
    mismatch so nothing invalid ever reaches OpenSearch."""
    if field not in _QUERY_FIELDS:
        # Refuse to query any field outside the fixed allowlist.
        raise _QueryError(f"field {field!r} not allowed (allowed: {sorted(_QUERY_FIELDS)})")
    if operator not in _OPERATORS:
        # Refuse any operator outside the fixed allowlist.
        raise _QueryError(f"operator {operator!r} not allowed (allowed: {list(_OPERATORS)})")
    # Look up whether this field is treated as a string or numeric for operator validation.
    kind = _QUERY_FIELDS[field]

    if operator == "equals":
        if value is None or value == "":
            # equals needs an actual value to compare against.
            raise _QueryError("equals requires a value")
        if kind == "numeric":
            try:
                # Coerce to int for numeric fields since OpenSearch term queries expect the right type.
                value = int(value)
            except (TypeError, ValueError):
                raise _QueryError(f"{field} is numeric; equals value {value!r} is not an integer")
        # Build an exact-match term query on this field.
        return {"term": {field: value}}

    if operator == "contains":
        if kind != "string":
            # "contains" only makes sense on string fields, not numeric ones.
            raise _QueryError(f"contains is only valid on string fields, not {field!r}")
        if not isinstance(value, str) or not value:
            # Need a non-empty string to build a wildcard pattern from.
            raise _QueryError("contains requires a non-empty string value")
        # A "wildcard" query matches text with "*" standing for "any characters".
        # Wrapping the value as "*value*" turns it into a substring search — matching
        # any field that contains the value anywhere inside it.
        return {"wildcard": {field: f"*{value}*"}}

    # range: match values inside numeric bounds (e.g. severity level between 3 and 10).
    if kind != "numeric":
        # "range" only makes sense on numeric fields.
        raise _QueryError(f"range is only valid on numeric fields, not {field!r}")
    if isinstance(value, str):  # the model passes args as strings; accept JSON-encoded bounds
        try:
            # The model may hand us a JSON-encoded object like '{"gte":3}'; decode it.
            value = json.loads(value)
        except json.JSONDecodeError:
            raise _QueryError("range value must be an object like {\"gte\":3,\"lte\":10}")
    if not isinstance(value, dict):
        # After the string-decode attempt, it must be a dict of bounds.
        raise _QueryError("range requires a value object with 'gte' and/or 'lte'")
    # Collected, validated numeric bounds to pass through to OpenSearch. The keys are
    # standard comparison shorthands: gte = >=, lte = <=, gt = >, lt = <.
    bounds = {}
    for k in ("gte", "lte", "gt", "lt"):
        if k in value and value[k] is not None:
            try:
                # Coerce each supplied bound to int.
                bounds[k] = int(value[k])
            except (TypeError, ValueError):
                raise _QueryError(f"range bound {k}={value[k]!r} is not an integer")
    if not bounds:
        # At least one bound must have been supplied and valid.
        raise _QueryError("range requires at least one of gte/lte/gt/lt")
    # Build the OpenSearch range query clause from the validated bounds.
    return {"range": {field: bounds}}


def _aggregate(body_filter: list, group_by: Optional[str], time_bucket: Optional[str]) -> dict:
    """Build + run an aggregation and return COUNTS, not raw alerts.

    An "aggregation" is OpenSearch's version of SQL's GROUP BY: instead of listing
    matching documents, it groups them into "buckets" and counts each bucket. This
    supports two kinds:
      - terms:          group by a field's values (e.g. count alerts per host).
      - date_histogram: group by time slices (e.g. count alerts per hour).
    They can also nest (counts per host, per hour). Great for spotting spikes."""
    # Load settings for the aggregation bucket cap (max number of buckets to return).
    s = get_settings()
    cap = s.tool_max_agg_buckets
    if not group_by and not time_bucket:
        # An aggregate query needs at least one grouping dimension.
        return {"error": "aggregate mode requires group_by and/or time_bucket"}
    if group_by and group_by not in _QUERY_FIELDS:
        # Only allowlisted fields may be grouped on.
        return {"error": f"group_by {group_by!r} not allowed (allowed: {sorted(_QUERY_FIELDS)})"}
    if time_bucket and not _TIME_BUCKET_RE.match(time_bucket):
        # Reject malformed bucket-size strings before building the aggregation.
        return {"error": f"time_bucket {time_bucket!r} must look like '1h', '30m', '1d'"}

    if time_bucket:
        # date_histogram slices the timeline into fixed intervals (fixed_interval),
        # counting the alerts in each. min_doc_count:1 drops empty slices from the
        # output so we don't get a long run of zero-count buckets.
        agg: dict = {"date_histogram": {"field": "timestamp", "fixed_interval": time_bucket,
                                        "min_doc_count": 1}}
        if group_by:
            # Nesting a "terms" sub-aggregation inside each time bucket gives a 2D
            # breakdown (e.g. for each hour, the per-host counts).
            agg["aggs"] = {"grp": {"terms": {"field": group_by, "size": cap}}}
    else:
        # No time bucketing requested: just a flat "terms" aggregation — the count of
        # alerts for each distinct value of group_by (size caps how many values).
        agg = {"terms": {"field": group_by, "size": cap}}

    # size:0 tells OpenSearch "return NO raw documents, only the aggregation results" —
    # we just want the counts, which keeps the response tiny.
    body = {"size": 0, "aggs": {"agg": agg}}
    if body_filter:
        # Apply any field/time filter clauses built by the caller.
        body["query"] = {"bool": {"filter": body_filter}}
    # Execute the aggregation query.
    resp = _search(body)
    if "error" in resp:
        # Pass errors through unchanged.
        return resp
    # Aggregation results live under "aggregations" -> our name "agg" -> "buckets",
    # each bucket being one group with a key and a doc_count (how many docs matched).
    raw_buckets = resp["raw"].get("aggregations", {}).get("agg", {}).get("buckets", [])
    # Collector for the shaped bucket output.
    out = []
    for b in raw_buckets[:cap]:
        # Date-histogram buckets carry both a raw numeric key and a "key_as_string"
        # (a human-readable timestamp); prefer the readable one when present.
        entry = {"key": b.get("key_as_string") or b.get("key"), "doc_count": b.get("doc_count")}
        if "grp" in b:
            # If this bucket has our nested "grp" sub-aggregation, flatten its inner
            # buckets into a simple list of {key, count} pairs.
            entry["groups"] = [{"key": g.get("key"), "doc_count": g.get("doc_count")}
                               for g in b["grp"].get("buckets", [])[:cap]]
        out.append(entry)
    # Report both the (possibly capped) returned buckets and the true total bucket count.
    return {"mode": "aggregate", "group_by": group_by, "time_bucket": time_bucket,
            "returned_buckets": len(out), "total_buckets": len(raw_buckets),
            "truncated": len(raw_buckets) > cap, "buckets": out}


# This is the handler for the generalized query tool: the function actually run when
# the model calls query_wazuh_logs. It ties the validators above together, then runs
# either a search or an aggregate. `args` = the model's arguments; `ctx` = shared context.
def _query_wazuh_logs(args: dict, ctx: ToolContext) -> dict:
    # Load settings for the hit cap used in search mode.
    s = get_settings()
    # Mode selects between raw-alert search and count-only aggregation; defaults to search.
    mode = (args.get("mode") or "search").lower()
    if mode not in ("search", "aggregate"):
        # Reject any mode outside the two supported values.
        return {"error": f"mode {mode!r} must be 'search' or 'aggregate'"}
    try:
        # Collected, validated OpenSearch bool-filter clauses.
        clauses: list = []
        # A field condition is optional (an aggregate over all alerts in a time
        # range is valid), but if a field is named it must fully validate.
        if args.get("field"):
            # Validate and build the field/operator/value clause.
            clauses.append(_field_clause(args.get("field"), args.get("operator") or "equals",
                                         args.get("value")))
        # Validate and build the optional time_range clause.
        time_clause = _parse_time_range(args.get("time_range"))
        if time_clause:
            clauses.append(time_clause)
    except _QueryError as exc:
        # Any validation failure anywhere above is surfaced as a structured error, not an exception.
        return {"error": str(exc)}

    if mode == "aggregate":
        # Delegate to the aggregation builder/executor with the validated clauses.
        return _aggregate(clauses, args.get("group_by") or None, args.get("time_bucket") or None)

    # search mode: same shape/capping as the narrow tools (reuses _shape/tool_max_hits)
    body: dict = {"size": s.tool_max_hits, "sort": [{"timestamp": "desc"}]}
    if clauses:
        # Only attach a query if there's actually something to filter on.
        body["query"] = {"bool": {"filter": clauses}}
    # Execute the search and merge the shaped results with the echoed field/operator for context.
    return {"mode": "search", "field": args.get("field"), "operator": args.get("operator"),
            **_shape(_search(body))}


# register_interactive (vs register) puts this tool ONLY into INTERACTIVE_REGISTRY —
# the flexible, validated query tool is available exclusively to the human-driven
# console chat, and is deliberately withheld from the unattended automated agent.
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
        # Which allowlisted field to filter/group on (optional for pure time-bucketed aggregates).
        "field": {"type": "string",
                  "description": "field to filter on: rule.id | rule.level | agent.name | "
                                 "data.srcip | data.dstuser | data.srcuser (optional for aggregate)"},
        # Which comparison operator to apply to `field`/`value`.
        "operator": {"type": "string", "enum": list(_OPERATORS),
                     "description": "equals (any field), contains (string fields), range (numeric fields)"},
        # The value to compare against (string, or JSON-encoded object for range bounds).
        "value": {"type": "string",
                  "description": "match value; for range pass an object like {\"gte\":3,\"lte\":10}"},
        # Relative or absolute time window to restrict the query to.
        "time_range": {"type": "string",
                       "description": "relative like '24h'/'7d', or an object {start,end} of ISO timestamps"},
        # search returns raw matching alerts; aggregate returns grouped counts.
        "mode": {"type": "string", "enum": ["search", "aggregate"], "description": "default 'search'"},
        # Aggregate-mode only: which field to group counts by.
        "group_by": {"type": "string", "description": "aggregate mode: field to group counts by"},
        # Aggregate-mode only: time bucket size for a date histogram (e.g. "1h", "1d").
        "time_bucket": {"type": "string", "description": "aggregate mode: bucket size e.g. '1h', '1d'"},
    },
    handler=_query_wazuh_logs,
))
