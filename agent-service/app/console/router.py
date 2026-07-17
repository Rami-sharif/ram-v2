"""Console router. Step B adds two read-only views over the write-once
investigation records: the triage queue and the investigation detail page.
Analyst actions (overrides/feedback/case control) come in Step C.

All routes are session-authenticated; kept entirely separate from the webhook.

BEGINNER ORIENTATION — how this file fits together:
- This is a FastAPI "router": a collection of URL endpoints (routes). Each
  function decorated with @router.get(...) or @protected.post(...) handles one
  URL. FastAPI reads the decorator to know WHICH url + HTTP method runs it.
- GET routes usually READ data and return an HTML page for the browser to show.
  POST routes usually CHANGE something (delete, update, close a case) and then
  send the browser back to a page.
- "Session-authenticated" means the browser must already be logged in (it carries
  a session cookie). The require_analyst dependency (below) enforces that and
  hands each route the logged-in analyst's info.
- Most pages are built server-side with Jinja HTML templates (files like
  queue.html). The route gathers data, then renders a template into HTML.
- The console uses HTMX, a small library that lets the browser swap in just a
  PIECE of a page (a "partial") without a full reload — used here for the chat.
"""
import json  # used to parse/serialize memory analysis JSON blobs
import logging  # module logger for intent markers and error traces
import re  # used to validate the "back" querystring is safe to re-embed in a redirect
from typing import Optional  # typed optional query/form params for FastAPI

# FastAPI building blocks used throughout this file:
#   APIRouter  - groups related URL routes together
#   Depends    - "dependency injection": ask FastAPI to run a helper (like the
#                login check) and pass its result into the route automatically
#   Form       - reads a value the browser submitted from an HTML <form>
#   Query      - reads a value from the URL's query string (the ?a=1&b=2 part)
#   Request    - the incoming HTTP request object (headers, query params, etc.)
from fastapi import APIRouter, Depends, Form, Query, Request
# Response types this file returns to the browser:
#   HTMLResponse     - a page (or fragment) of HTML
#   RedirectResponse - tells the browser "go to this other URL instead"
from fastapi.responses import HTMLResponse, RedirectResponse

# Domain modules: agent (LLM chat), explain ("why this verdict" summary), memory (learned alert
# store), thehive (case API), triage (dedup/case logic)
from .. import agent, explain, memory, thehive, triage
from ..config import get_settings  # app settings, e.g. TheHive public URL for building links
from . import store  # console-local persistence: investigations, audit log, chat, conversations
from .auth import require_analyst  # dependency that enforces session auth and yields the analyst
from .auth import router as auth_router  # separate router carrying the (unauthenticated) login/logout routes
from .templating import templates  # shared Jinja environment for rendering console pages

logger = logging.getLogger(__name__)  # module-level logger, named after this module's path

# The main router this module hands back to the app. Other routers get "mounted"
# onto it below so all their routes live under one object.
router = APIRouter()  # top-level router exported from this module
# Login/logout must work BEFORE you are logged in, so those routes are public
# (no auth check) and are attached directly to the top-level router.
router.include_router(auth_router)  # mount the auth routes (login/logout) unauthenticated at the top level

# A second router for everything that DOES require login. `prefix="/console"`
# means every route below starts with /console (e.g. /console/queue). `tags` just
# groups these routes together in the auto-generated API docs.
protected = APIRouter(prefix="/console", tags=["console"])  # everything under /console requires require_analyst

# Pagination = splitting a long list into fixed-size "pages" so one screen never
# has to load thousands of rows at once.
PAGE_SIZE = 25  # rows per page across queue/memory listings
SEVERITY_LABELS = ("low", "medium", "high", "critical")  # canonical severity vocabulary for filters/selects
TRIAGE_ACTIONS = ("auto_close", "create_open", "create_flagged", "suppress_duplicate")  # canonical triage outcomes for filters
_SAFE_QS = re.compile(r"[A-Za-z0-9_=&%.\-+]*")  # whitelist pattern for a "back" querystring we redirect into (prevents injection)


def _case_url(case_id: Optional[str]) -> Optional[str]:
    """Link into TheHive (system of record). Console is controller only."""
    if not case_id:
        # No case linked yet: nothing to link to.
        return None
    base = get_settings().console_thehive_public_url.rstrip("/")  # strip trailing slash before joining path
    return f"{base}/cases/{case_id}/details"  # TheHive's case detail URL shape


def _resolve_retrieved(retrieved_ids) -> list[dict]:
    """Resolve each retrieved memory id (a write-once snapshot on the investigation,
    with no FK) to its current memory row. A referenced memory may have been deleted
    since the investigation ran, so a missing id resolves to exists=False and renders
    as 'deleted / not found' — never a 404. We do not link deleted ids."""
    out = []  # accumulator of resolved memory summaries, in the original order
    for mid in retrieved_ids or []:  # tolerate None (no retrieved ids recorded)
        row = memory.get_memory(mid)  # look up the current memory row, if it still exists
        out.append({
            "id": mid,  # the id as recorded on the investigation (stable even if deleted)
            "exists": row is not None,  # drives the "deleted / not found" rendering in the template
            "source_ip": row.get("source_ip") if row else None,  # only available if the row still exists
            "rule_id": row.get("rule_id") if row else None,  # only available if the row still exists
        })
    return out


# Actions hidden from the queue's default "actionable only" view.
_RESOLVED_ACTIONS = ("auto_close",)  # auto-closed alerts don't need analyst attention by default


# @protected.get("/") registers this function as the handler for a GET request to
# /console/ (the prefix "/console" + "/"). response_class=HTMLResponse tells FastAPI
# the return value is an HTML page. `analyst: dict = Depends(require_analyst)` runs
# the login check first: if not logged in it redirects to login; if logged in it
# passes the analyst's record in as `analyst`.
@protected.get("/", response_class=HTMLResponse)
def overview(request: Request, analyst: dict = Depends(require_analyst)):
    """Landing dashboard: global at-a-glance counts, severity mix, and the
    'needs me now' list. Drill-downs link into the queue with a matching filter."""
    summary = store.summary_counts()  # top-line counters (totals by status, etc.)
    distribution = store.severity_distribution()  # counts per severity label, for the bar chart
    dist_total = sum(d["n"] for d in distribution) or 1  # avoid /0 for bar widths
    attention = store.needs_attention(limit=8)  # short list of alerts that most need analyst eyes
    recent, _ = store.list_investigations(limit=8, offset=0)  # most recent investigations regardless of status
    correlated = store.correlated_cases(limit=12)  # memory-correlation feed for the ticker
    for r in (*attention, *recent):  # annotate both lists with a clickable TheHive case link
        r["case_url"] = _case_url(r.get("case_id"))
    # Render the overview.html Jinja template into an HTML page. The dict is the
    # "context": every key becomes a variable the template can display. FastAPI
    # sends the resulting HTML back to the browser.
    return templates.TemplateResponse(request, "overview.html", {
        "analyst": analyst, "nav": "overview", "summary": summary,
        "distribution": distribution, "dist_total": dist_total,
        "attention": attention, "recent": recent, "correlated": correlated,
        # "Flash" messages: after a POST action we redirect and tuck a short
        # success/error note into the URL (?msg=... / ?err=...). We read it here so
        # the page can show a one-time banner. request.query_params reads the URL's
        # ?key=value pairs.
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


# The triage queue: a filterable, paginated list of alerts. Each Query(...) param
# is read from the URL's query string, e.g. /console/queue?severity=high&page=2.
# Query(None) means "optional, default None"; Query(1, ge=1) means "default 1, and
# FastAPI rejects anything less than 1" (ge = greater-than-or-equal).
@protected.get("/queue", response_class=HTMLResponse)
def queue(
    request: Request,
    analyst: dict = Depends(require_analyst),  # session auth; also injects the current analyst
    severity: Optional[str] = Query(None),  # optional severity filter from the querystring
    action: Optional[str] = Query(None),  # optional triage-action filter from the querystring
    q: Optional[str] = Query(None),  # optional free-text search term
    show: Optional[str] = Query(None),  # "all" includes resolved (auto_close)
    page: int = Query(1, ge=1),  # 1-based page number, must be >= 1
):
    severity = severity or None  # normalize empty string to None for the store layer
    action = action or None  # normalize empty string to None for the store layer
    search = (q or "").strip() or None  # trim whitespace and normalize empty to None
    show_all = show == "all"  # explicit opt-in to see resolved (auto_close) rows too
    # Default view hides auto-closed items; an explicit action filter or show=all
    # overrides. exclude_actions is ignored by the store when `action` is set.
    exclude = () if (show_all or action) else _RESOLVED_ACTIONS
    # "offset" = how many rows to skip before this page starts. Page 1 skips 0,
    # page 2 skips PAGE_SIZE, and so on — the standard way to fetch one page.
    offset = (page - 1) * PAGE_SIZE  # translate page number into a row offset
    # Ask the data layer for just this page of rows plus the grand total (used to
    # compute how many pages exist).
    rows, total = store.list_investigations(
        severity_label=severity, triage_action=action, search=search,
        exclude_actions=exclude, limit=PAGE_SIZE, offset=offset,
    )
    for r in rows:  # attach a clickable TheHive link per row for the template
        r["case_url"] = _case_url(r.get("case_id"))
    # Number of pages = total rows divided by page size, rounded UP. The
    # (total + PAGE_SIZE - 1) // PAGE_SIZE trick is integer "ceiling" division.
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)  # ceiling division, at least 1 page
    return templates.TemplateResponse(request, "queue.html", {
        "analyst": analyst, "nav": "queue", "rows": rows, "total": total,
        "page": page, "total_pages": total_pages,
        "severity": severity or "", "action": action or "", "q": search or "",
        "show_all": show_all,
        "severity_labels": SEVERITY_LABELS, "triage_actions": TRIAGE_ACTIONS,
        "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"),
    })


# A "path parameter": the {inv_id} in the URL is captured and passed to the
# function. Because the argument is typed `inv_id: int`, FastAPI converts it to an
# integer for us (and rejects non-numbers). So /console/investigations/42 -> inv_id=42.
@protected.get("/investigations/{inv_id}", response_class=HTMLResponse)
def investigation_detail(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
):
    rec = store.get_investigation(inv_id)  # full record: investigation + its reviews/feedback
    if rec is None:
        # Unknown id: render a dedicated not-found page and set the HTTP status to
        # 404 ("Not Found") — the standard code for "this thing doesn't exist" —
        # rather than letting an error bubble up as a generic 500 (server error).
        return templates.TemplateResponse(
            request, "not_found.html", {"analyst": analyst, "inv_id": inv_id},
            status_code=404,
        )
    rec["case_url"] = _case_url(rec["inv"].get("case_id"))  # clickable TheHive link, if a case is linked
    retrieved = _resolve_retrieved(rec["inv"].get("retrieved_ids"))  # resolve memory ids the agent cited
    # `chat_context` anchors the assistant dock to THIS investigation: the dock's
    # form posts the id, so "is this a real threat?" needs no case number.
    # When the investigation has no case, offer the right recovery: link it to the
    # case its dedup group already has, or (if the group has none) create one.
    inv = rec["inv"]  # convenience alias for the investigation dict
    parent_case = None if inv.get("case_id") else triage.parent_case_for(inv)  # only look up if not already linked
    if parent_case:
        parent_case = {**parent_case, "url": _case_url(parent_case["case_id"])}  # add a link for the recovery UI
    # "Why this verdict" summary: prefers the explanation stored at insert time; for older
    # (write-once) investigations that predate it, recomputes a best-effort one at render time.
    # Never let a summary failure take down the detail page.
    try:
        explanation = explain.build_explanation_from_record(inv)
    except Exception:  # noqa: BLE001 - presentational only
        logger.exception("Explanation render failed for investigation %s", inv_id)
        explanation = None
    return templates.TemplateResponse(request, "investigation.html", {
        "analyst": analyst, "nav": "queue", "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"), "retrieved": retrieved,
        "severity_labels": SEVERITY_LABELS, "close_statuses": thehive.CLOSED_STATUSES,
        "chat_context": _chat_context(inv),
        "parent_case": parent_case, "explanation": explanation,
        "can_retry_case": parent_case is None and triage.can_retry_case(inv),
        **rec,  # spreads in "inv", "reviews", "feedback" (whatever store.get_investigation returns)
    })


def _chat_context(inv: dict) -> dict:
    """What the dock shows (and posts) when the analyst chats from an investigation."""
    return {
        "investigation_id": inv["id"],  # posted back by the dock's form to anchor the chat turn
        "label": f"Investigation #{inv['id']}"
                 + (f" · case #{inv['case_number']}" if inv.get("case_number") else ""),  # human-readable badge
    }


def _parse_ids(raw: list[str], *, cap: int = 200) -> list[int]:
    """Ids arrive from checkbox form fields, so they are untrusted strings. Keep the
    integers, drop duplicates, preserve order, and cap the batch — one click should
    never be able to issue an unbounded delete.

    "Untrusted" is a security mindset: anything the browser sends could be faked or
    malformed, so we validate it here instead of blindly trusting it."""
    out: list[int] = []  # de-duplicated, order-preserving list of parsed ids
    for value in raw:  # each value is a raw string from a checked checkbox
        try:
            n = int(value)  # coerce to int; only valid integers are accepted
        except (TypeError, ValueError):
            continue  # silently drop anything that isn't a valid integer
        if n not in out:  # de-duplicate while preserving first-seen order
            out.append(n)
    return out[:cap]  # hard cap so one submit can't affect an unbounded number of rows


# A POST route: the browser submits an HTML <form> here to CHANGE data (delete).
# Form(...) pulls values out of that submitted form. `ids` is a list because the
# form has many checkboxes all named "ids"; `back` remembers which queue view
# (filters + page) the analyst was on, so we can return them there afterward.
@protected.post("/investigations/bulk-delete")
def bulk_delete_investigations(
    request: Request, analyst: dict = Depends(require_analyst),
    ids: list[str] = Form(default=[]), back: str = Form(""),  # checked ids + the queue URL to return to
):
    """Delete every selected investigation. Each one is audited individually (see
    store.delete_investigations) — selecting 20 rows is 20 audit rows, not one.

    "Audited" means every action is recorded in a tamper-evident log (who did what,
    when, and to which record) so the SOC has an accountability trail."""
    inv_ids = _parse_ids(ids)  # sanitize the untrusted form-submitted id strings
    if not inv_ids:
        return _queue_back(back, err="select+at+least+one+alert")  # nothing was actually selected
    deleted = store.delete_investigations(inv_ids, actor_username=analyst["username"])  # audited per-row delete
    if not deleted:
        return _queue_back(back, err="nothing+deleted+-+those+alerts+are+already+gone")  # ids were already gone
    return _queue_back(back, msg=f"deleted+{len(deleted)}+investigation(s)")  # report actual delete count


def _queue_back(back: str, *, msg: str = None, err: str = None) -> RedirectResponse:
    """Back to the queue view the analyst acted from (filters/page intact)."""
    # SECURITY: `back` came from the browser, so we only reuse it if it matches the
    # safe character whitelist (_SAFE_QS). This blocks someone crafting a malicious
    # redirect target — never build a redirect URL from raw user input unchecked.
    qs = back.lstrip("?") if _SAFE_QS.fullmatch(back.lstrip("?")) else ""  # only keep `back` if it matches the safe charset
    tail = f"msg={msg}" if msg else f"err={err}"  # append exactly one flash param
    sep = "&" if qs else ""  # only add a separator if there's an existing querystring to join
    # A redirect with HTTP status 303 ("See Other") tells the browser to fetch the
    # given URL with a fresh GET. This is the standard "Post/Redirect/Get" pattern:
    # after a POST it stops the browser from re-submitting the form if the user hits
    # refresh (which would double-delete). The ?msg/?err carries the flash banner.
    return RedirectResponse(f"/console/queue?{qs}{sep}{tail}", status_code=303)  # 303 so the browser re-GETs


@protected.post("/investigations/{inv_id}/delete")
def delete_investigation(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    back: str = Form(""),  # the queue URL (with filters/page) to redirect back to
):
    """Drop an alert from the triage queue. Audited FIRST (an audit failure raises
    and nothing is deleted), then the record and its layered human input go.

    "Audit first" ordering matters: if writing the audit log fails it raises an
    exception, so the delete below never runs. That guarantees we never quietly
    change data without a record of who did it."""
    rec = store.get_investigation(inv_id)  # load the record so we can audit its details before deleting
    if rec is None:
        return RedirectResponse("/console/queue?err=investigation+not+found", status_code=303)
    inv = rec["inv"]  # convenience alias
    store.write_audit(
        analyst["username"], "investigation_delete", target_type="investigation",
        target_id=str(inv_id),
        before={"alert_id": inv.get("alert_id"), "agent_name": inv.get("agent_name"),
                "source_ip": inv.get("source_ip"), "rule_id": inv.get("rule_id"),
                "severity_label": inv.get("severity_label"),
                "triage_action": inv.get("triage_action"), "case_number": inv.get("case_number")},
        detail=f"deleted from triage queue ({len(rec['reviews'])} review(s), "
               f"{len(rec['feedback'])} feedback row(s) removed with it)",
    )  # audit row written first; if this raises, delete_investigation below never runs
    store.delete_investigation(inv_id)  # actually remove the investigation and its dependent rows
    return _queue_back(back, msg="investigation+deleted")


# Shared helper: after an action on ONE investigation, redirect back to that
# investigation's detail page, carrying a flash message. (Same 303 Post/Redirect/Get
# idea as _queue_back, but pointing at the detail page instead of the queue.)
def _back(inv_id: int, *, msg: str = None, err: str = None) -> RedirectResponse:
    qs = f"?msg={msg}" if msg else (f"?err={err}" if err else "")  # build a single flash param, or none
    return RedirectResponse(f"/console/investigations/{inv_id}{qs}", status_code=303)  # 303 back to the detail page


# --- dashboard-level analyst chat -------------------------------------------
# The assistant is a GLOBAL slide-in dock (rendered from base.html on every
# page). Its thread is lazy-loaded via this GET so no page pays for the history
# until the analyst opens the dock. One ongoing thread per analyst (username).
_CHAT_EMPTY_HTML = (  # placeholder markup shown when a conversation has no messages yet
    '<p class="muted chat-empty" id="chat-empty">No messages yet. Ask about any '
    'recorded case, check whether an IP or hash appeared elsewhere, or request '
    'an audited action on a case.</p>'
)


def _ensure_conversation(analyst: dict) -> dict:
    """The analyst's most-recent conversation, creating a first one if none exist."""
    return (store.most_recent_conversation(analyst["username"])  # reuse the latest thread if one exists
            or store.create_conversation(analyst["username"]))  # otherwise lazily create the first one


def _resolve_conversation(analyst: dict, conversation_id) -> dict:
    """Resolve which conversation a chat turn targets. An explicit id must belong
    to the analyst (authorization); otherwise fall back to their most-recent
    (the dock posts with no id and targets the most-recent chat)."""
    if conversation_id:
        try:
            convo = store.get_conversation(int(conversation_id), analyst["username"])  # ownership-checked lookup
        except (TypeError, ValueError):
            convo = None  # non-numeric id: treat as "no explicit conversation"
        if convo is not None:
            return convo  # valid, owned conversation id was supplied
    return _ensure_conversation(analyst)  # no valid id: fall back to (or create) the most-recent thread


# Dock thread (lazy-loaded): render the analyst's most-recent conversation, with
# its id on the wrapper so the dock's form posts back to the right chat.
# "Lazy-loaded" = the chat history isn't fetched when the page first loads; HTMX
# calls this endpoint only when the analyst actually opens the dock, saving work.
# Note it returns a PARTIAL template (_chat_log.html — just the chat box), not a
# whole page, because HTMX will splice this fragment into the already-open page.
@protected.get("/assistant", response_class=HTMLResponse)
def assistant_thread(request: Request, analyst: dict = Depends(require_analyst)):
    convo = _ensure_conversation(analyst)  # get-or-create the analyst's latest thread
    chat = store.list_chat(convo["thread_key"])  # full message history for that thread
    return templates.TemplateResponse(request, "_chat_log.html", {
        "messages": chat, "conversation": convo,
    })


# Full-page assistant with multi-conversation management. `c` selects a
# conversation (must be owned); otherwise the most-recent is shown. The dock is
# suppressed here (hide_dock) so #chat-log stays unique and console.js drives it.
@protected.get("/agent", response_class=HTMLResponse)
def agent_page(request: Request, analyst: dict = Depends(require_analyst),
               c: Optional[int] = Query(None)):  # optional conversation id selected from the sidebar
    conversations = store.list_conversations(analyst["username"])  # sidebar list of this analyst's threads
    active = None  # will hold the conversation to render
    if c is not None:
        active = store.get_conversation(c, analyst["username"])  # ownership-checked; None if not found/not owned
    if active is None:
        active = _ensure_conversation(analyst)  # fall back to (or create) the most-recent thread
        if not conversations:  # first-ever conversation just created
            conversations = store.list_conversations(analyst["username"])  # refresh sidebar to include it
    chat = store.list_chat(active["thread_key"])  # message history for the active thread
    return templates.TemplateResponse(request, "agent.html", {
        "analyst": analyst, "nav": "agent", "hide_dock": True, "chat": chat,
        "conversations": conversations, "active": active,
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


# --- conversation management (create / rename / delete) ----------------------
@protected.post("/conversations")
def create_conversation(request: Request, analyst: dict = Depends(require_analyst)):
    convo = store.create_conversation(analyst["username"])  # start a brand-new, empty thread
    # HTMX sets an "HX-Request" header on requests it makes. We check for it to
    # decide HOW to answer: if HTMX asked, return just the chat fragment so it can
    # swap it in place (no page reload). If a plain browser asked (no JavaScript),
    # fall through to a normal redirect / full page load instead.
    if request.headers.get("HX-Request"):  # dock: swap in the fresh empty thread
        return templates.TemplateResponse(request, "_chat_log.html", {
            "messages": [], "conversation": convo,
        })
    return RedirectResponse(f"/console/agent?c={convo['id']}", status_code=303)  # non-JS fallback: full page reload


@protected.post("/conversations/{conversation_id}/rename")
def rename_conversation(
    request: Request, conversation_id: int, analyst: dict = Depends(require_analyst),
    title: str = Form(...),  # new title submitted from the sidebar rename form
):
    title = title.strip()[:120] or "Untitled chat"  # trim, bound length, and fall back if left blank
    store.rename_conversation(conversation_id, analyst["username"], title)  # ownership enforced inside store
    return RedirectResponse(f"/console/agent?c={conversation_id}", status_code=303)  # back to the same thread


@protected.post("/conversations/{conversation_id}/delete")
def delete_conversation(
    request: Request, conversation_id: int, analyst: dict = Depends(require_analyst),
):
    store.delete_conversation(conversation_id, analyst["username"])  # ownership enforced inside store
    return RedirectResponse("/console/agent", status_code=303)  # back to the agent page (picks a new active thread)


# One ongoing thread per analyst (keyed by username), driven from the dock.
# The analyst asks freely; the assistant looks up any case it needs by number and
# may take audited actions on a case it just looked up. Persists the conversation
# (write-once per message); any action the assistant takes is separately audited
# by its underlying tool. HTMX requests get an appended-messages partial; a plain
# POST falls back to a redirect so it works without JS.
@protected.post("/chat")
def post_chat(
    request: Request, analyst: dict = Depends(require_analyst), message: str = Form(...),
    conversation_id: Optional[str] = Form(None),  # which thread this turn belongs to (None = most-recent)
    investigation_id: Optional[str] = Form(None),  # optional anchor when chatting from an investigation page
):
    message = message.strip()  # normalize whitespace before checking/storing/sending to the model
    if not message:
        # HTTP status 204 ("No Content") = "success, but there's nothing to show."
        # HTMX treats an empty 204 as "do nothing", so a blank submit is ignored.
        if request.headers.get("HX-Request"):
            return HTMLResponse("", status_code=204)  # HTMX: no-op response, nothing to append
        return RedirectResponse("/console/queue?err=empty+message", status_code=303)  # non-JS fallback

    # Chatting from an investigation page anchors the turn to that record, so the
    # analyst can say "this alert" without naming a case number. The id comes from
    # the page (not the model), and is only a starting point — the assistant still
    # looks the case up through its audited tools before acting on it.
    focus = None  # the investigation dict to anchor this turn to, if any
    if investigation_id:
        try:
            rec = store.get_investigation(int(investigation_id))  # load the anchor investigation
        except (TypeError, ValueError):
            rec = None  # malformed id: treat as no anchor
        focus = rec["inv"] if rec else None

    # Resolve the target conversation (owner-checked); the dock omits the id and
    # targets the most-recent chat. History is that conversation's ONLY — chats
    # are isolated; the shared SOC alert memory stays available via the tools.
    convo = _resolve_conversation(analyst, conversation_id)  # ownership-checked resolution, with fallback
    thread_key = convo["thread_key"]  # stable key used to store/query this conversation's messages
    prior = store.list_chat(thread_key)  # history BEFORE this turn (this chat only)
    store.add_chat_message(thread_key=thread_key, role="analyst",
                           actor=analyst["username"], message=message)  # persist the analyst's turn first
    try:
        reply, tool_calls, referenced = agent.run_interactive(
            message, analyst["username"],
            history=[{"role": h["role"], "message": h["message"]} for h in prior],  # trim history to role+message
            focus_investigation=focus,
        )  # run the LLM turn; may call audited tools internally
    except Exception as exc:  # noqa: BLE001 - never lose the turn; record the failure
        logger.exception("Dashboard chat failed for analyst %s", thread_key)
        reply, tool_calls, referenced = f"(assistant error: {exc})", [], []  # degrade to a visible error reply
    store.add_chat_message(thread_key=thread_key, role="agent", actor="agent",
                           message=reply, tool_calls=tool_calls, referenced_case_ids=referenced)  # persist the reply
    # First analyst message titles a still-unnamed chat; bump recency either way.
    if convo.get("title") in (None, "New chat"):
        store.rename_conversation(convo["id"], analyst["username"], message[:48])  # auto-title from first message
    store.touch_conversation(convo["id"])  # bump recency so this thread sorts to the top

    # If HTMX made this request, reply with ONLY the two new messages (the
    # analyst's line and the assistant's line) as an HTML fragment. HTMX appends
    # that fragment to the bottom of the existing chat — far cheaper than re-rendering
    # the whole conversation. A plain browser instead gets a redirect (below).
    if request.headers.get("HX-Request"):
        new_messages = [
            {"role": "analyst", "actor": analyst["username"], "message": message,
             "tool_calls": [], "referenced_case_ids": []},
            {"role": "agent", "actor": "agent", "message": reply,
             "tool_calls": tool_calls, "referenced_case_ids": referenced},
        ]  # only the two new messages from this turn — HTMX appends them, doesn't re-render the whole log
        return templates.TemplateResponse(request, "_chat_messages.html",
                                          {"messages": new_messages})
    return RedirectResponse("/console/queue?msg=chat+updated", status_code=303)  # non-JS fallback


# --- analyst actions on the verdict / triage decision -----------------------
@protected.post("/investigations/{inv_id}/verdict")
def post_verdict(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    action: str = Form(...), reason: str = Form(""),  # "confirm" or "override", plus optional free-text reason
    severity_label: str = Form(""), severity_score: str = Form(""),  # override fields, only used when action=override
    attack_type: str = Form(""),  # override field, only used when action=override
):
    if action not in ("confirm", "override"):
        return _back(inv_id, err="invalid+verdict+action")  # reject any action outside the allowed set
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    inv = rec["inv"]
    before = {"severity_label": inv["severity_label"], "severity_score": inv["severity_score"],
              "attack_type": inv["attack_type"]}  # snapshot of the agent's original verdict, for the audit trail
    payload = None  # only populated when overriding; confirm has no payload
    if action == "override":
        payload = {"severity_label": severity_label or None, "attack_type": attack_type or None}
        if severity_score.strip():
            try:
                payload["severity_score"] = int(severity_score)  # only add if provided and numeric
            except ValueError:
                return _back(inv_id, err="severity+score+must+be+a+number")  # reject non-numeric input
    # Action + audit are written in ONE transaction (atomic).
    store.add_verdict_review(
        investigation_id=inv_id, actor_username=analyst["username"], action=action,
        override_payload=payload, reason=reason or None, before=before,
    )
    # Learning loop: fold this verdict into the alert's memory row (best-effort;
    # a memory failure must never fail the recorded verdict).
    try:
        memory.record_human_verdict(inv, action=action, override_payload=payload,
                                    actor=analyst["username"])
    except Exception:  # noqa: BLE001
        logger.exception("Learning-loop memory update failed (verdict recorded) inv=%s", inv_id)  # verdict already saved above
    return _back(inv_id, msg=f"verdict+{action}+recorded")


@protected.post("/investigations/{inv_id}/feedback")
def post_feedback(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    rating: str = Form(...), reason: str = Form(""),  # "correct"/"incorrect" rating of the triage decision, plus reason
):
    if rating not in ("correct", "incorrect"):
        return _back(inv_id, err="invalid+rating")  # reject any rating outside the allowed set
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    before = {"triage_action": rec["inv"]["triage_action"], "triage_branch": rec["inv"]["triage_branch"]}  # audit snapshot
    store.add_triage_feedback(
        investigation_id=inv_id, actor_username=analyst["username"], rating=rating,
        reason=reason or None, before=before,
    )
    return _back(inv_id, msg=f"triage+marked+{rating}")


# --- TheHive case actions (close / severity / comment only) -----------------
# TheHive is the external case-management system (the "system of record"). These
# routes change a case THERE. The safety rule ("action contract") for every one:
#   1) perform the change through the service account,
#   2) VERIFY it actually landed by re-reading the case from TheHive's API,
#   3) and only THEN write our local audit row.
# This way we never record "we closed the case" unless TheHive really did close it.
def _require_case(inv_id: int):
    rec = store.get_investigation(inv_id)  # load the investigation
    if rec is None:
        return None, None  # caller checks case_id falsiness to detect "not found" too
    return rec, rec["inv"].get("case_id")  # (record, linked case id or None)


@protected.post("/investigations/{inv_id}/case/link")
def post_case_link(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
):
    """Link an investigation to the case its dedup group already has. This is the
    correct recovery for a suppressed duplicate (and for any alert of a group whose
    case was created later): the group is ONE incident and must stay one case."""
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    inv = rec["inv"]
    if inv.get("case_id"):
        return _back(inv_id, err="case+already+linked")  # don't clobber an existing link
    parent = triage.parent_case_for(inv)  # find the case belonging to this alert's dedup group, if any
    if not parent:
        return _back(inv_id, err="no+case+exists+for+this+alert+group")
    try:
        store.link_case(
            investigation_id=inv_id, case_id=parent["case_id"],
            case_number=parent.get("case_number"), actor_username=analyst["username"],
            action="investigation_case_link",
            detail=f"linked to existing case #{parent.get('case_number')} "
                   f"(the case this alert's dedup group belongs to)",
            before={"case_id": None, "case_error": inv.get("case_error")},
        )  # atomic link + audit write
    except Exception:  # noqa: BLE001
        logger.exception("Linking investigation %s to case %s failed", inv_id, parent["case_id"])
        return _back(inv_id, err="linking+the+case+failed")
    return _back(inv_id, msg=f"linked+to+case+%23{parent.get('case_number')}")  # %23 is a URL-encoded '#'


@protected.post("/investigations/{inv_id}/case/create")
def post_case_create(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
):
    """Retry the case creation that failed during triage. The agent's output is NOT
    rewritten: on success the new case is recorded as an attributed link row (audited
    in the same transaction), which every console view then resolves as the
    investigation's case. On failure the analyst sees the TheHive error and can retry."""
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    inv = rec["inv"]
    if inv.get("case_id"):
        return _back(inv_id, err="case+already+linked")  # don't create a duplicate case
    if not triage.can_retry_case(inv):
        # No stored alert payload (recorded before this feature) or not a case-creating
        # alert — nothing faithful to replay, so refuse rather than invent a case.
        return _back(inv_id, err="this+investigation+cannot+be+retried")
    logger.info("THEHIVE_INTENT actor=%s action=thehive_create_case investigation=%s "
                "original_error=%r", analyst["username"], inv_id, inv.get("case_error"))  # pre-call intent trace
    try:
        case = triage.create_case_for_investigation(inv)  # replay the original alert payload to create the case
    except thehive.TheHiveError as exc:
        logger.error("Case retry failed for investigation %s: %s", inv_id, exc)
        return _back(inv_id, err="case+creation+failed+again")
    try:
        store.link_case(investigation_id=inv_id, case_id=case["_id"], case_number=case.get("number"),
                        actor_username=analyst["username"],
                        before={"case_id": None, "case_error": inv.get("case_error")})  # record the new link + audit
    except Exception:  # noqa: BLE001 - the case EXISTS now; never lose that fact silently
        logger.exception("Case #%s created in TheHive for investigation %s but linking it "
                         "failed (case_id=%s)", case.get("number"), inv_id, case.get("_id"))
        return _back(inv_id, err="case+created+but+linking+failed+-+see+logs")
    return _back(inv_id, msg=f"case+created+%23{case.get('number')}")


@protected.post("/investigations/{inv_id}/case/close")
def post_case_close(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    summary: str = Form(""), resolution: str = Form(thehive.DEFAULT_CLOSE_STATUS),  # closing note + status
):
    rec, case_id = _require_case(inv_id)  # rec unused here; only case_id matters for this action
    if not case_id:
        return _back(inv_id, err="no+linked+case")  # can't close a case that isn't linked
    if resolution not in thehive.CLOSED_STATUSES:
        return _back(inv_id, err="invalid+close+resolution")  # reject any status outside the allowed set
    # Pre-call intent marker: a durable trace of who tried what, BEFORE the API
    # call, so a (rare) audit-write failure after a verified change still leaves
    # a record. The authoritative audit row is still written verify-then-audit below.
    logger.info("THEHIVE_INTENT actor=%s action=thehive_close case=%s resolution=%r summary=%r",
                analyst["username"], case_id, resolution, summary)
    try:
        thehive.close_case_strict(case_id, summary or "Closed by RAM v2 analyst console.", resolution)  # perform the close
        case = thehive.get_case(case_id)  # re-fetch to verify the mutation actually landed
        if case.get("stage") != "Closed":
            return _back(inv_id, err="close+not+confirmed+in+thehive")  # verification failed: do not audit as success
        store.write_audit(analyst["username"], "thehive_close", target_type="thehive_case",
                          target_id=case_id,
                          after={"status": case.get("status"), "stage": case.get("stage")},
                          detail=f"{resolution}: {summary}" if summary else resolution)  # audit only after verified
    except thehive.TheHiveError as exc:
        logger.error("TheHive close failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+close+failed")
    return _back(inv_id, msg="case+closed")


@protected.post("/investigations/{inv_id}/case/severity")
def post_case_severity(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    severity_label: str = Form(...),  # human label (e.g. "high") submitted from the form
):
    rec, case_id = _require_case(inv_id)  # rec unused here; only case_id matters for this action
    if not case_id:
        return _back(inv_id, err="no+linked+case")  # can't set severity on a case that isn't linked
    target = thehive.severity_to_int(severity_label)  # TheHive's API expects the integer encoding
    logger.info("THEHIVE_INTENT actor=%s action=thehive_set_severity case=%s target=%s(%s)",
                analyst["username"], case_id, target, severity_label)  # pre-call intent trace
    try:
        before = thehive.get_case(case_id).get("severity")  # snapshot prior value for the audit row
        thehive.set_severity(case_id, target)  # perform the mutation
        landed = thehive.get_case(case_id).get("severity")  # re-fetch to verify it actually landed
        if landed != target:
            return _back(inv_id, err="severity+not+confirmed+in+thehive")  # verification failed
        store.write_audit(analyst["username"], "thehive_set_severity", target_type="thehive_case",
                          target_id=case_id, before={"severity": before}, after={"severity": landed},
                          detail=f"set to {severity_label} ({target})")  # audit only after verified
    except thehive.TheHiveError as exc:
        logger.error("TheHive set_severity failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+severity+failed")
    return _back(inv_id, msg="severity+updated")


@protected.post("/investigations/{inv_id}/case/comment")
def post_case_comment(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    message: str = Form(...),  # raw comment text submitted from the form
):
    rec, case_id = _require_case(inv_id)  # rec unused here; only case_id matters for this action
    if not case_id:
        return _back(inv_id, err="no+linked+case")  # can't comment on a case that isn't linked
    message = message.strip()  # normalize whitespace
    if not message:
        return _back(inv_id, err="empty+comment")  # reject a blank comment
    stamped = f"[{analyst['username']}] {message}"  # attribute the comment to the acting analyst in TheHive
    logger.info("THEHIVE_INTENT actor=%s action=thehive_comment case=%s message=%r",
                analyst["username"], case_id, stamped)  # pre-call intent trace
    try:
        thehive.post_comment(case_id, stamped)  # perform the mutation
        landed = any(c.get("message") == stamped for c in thehive.get_case_comments(case_id))  # verify it landed
        if not landed:
            return _back(inv_id, err="comment+not+confirmed+in+thehive")  # verification failed
        store.write_audit(analyst["username"], "thehive_comment", target_type="thehive_case",
                          target_id=case_id, after={"message": stamped})  # audit only after verified
    except thehive.TheHiveError as exc:
        logger.error("TheHive comment failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+comment+failed")
    return _back(inv_id, msg="comment+added")


# --- Memory browser (list / inspect / edit / delete) ------------------------
# "Memory" = the store of past alerts the agent has learned from. Each entry has an
# "embedding": a numeric fingerprint of its text that lets the system find SIMILAR
# past alerts by meaning (semantic search).
# Edits follow LOCKED rules: editing only the analysis notes does NOT recompute the
# embedding (cheap); editing the identity TEXT must "re-embed" (recompute the
# fingerprint) so similarity search stays accurate. Every edit is audited FIRST
# (if the audit write fails it aborts, so no change ever happens un-recorded).
@protected.get("/memory", response_class=HTMLResponse)
def memory_list(
    request: Request, analyst: dict = Depends(require_analyst),
    agent_name: Optional[str] = Query(None), source_ip: Optional[str] = Query(None),  # exact-match filters
    rule_id: Optional[str] = Query(None), q: Optional[str] = Query(None),  # more filters + free-text search
    reviewed: Optional[str] = Query(None), page: int = Query(1, ge=1),  # "1" = human-reviewed only; page number
):
    search = (q or "").strip() or None  # trim and normalize empty to None
    reviewed_only = reviewed == "1"  # checkbox-style query flag
    if search:
        rows = memory.search_memories(search, agent_name=agent_name or None, k=PAGE_SIZE)  # semantic/text search, top-k
        if reviewed_only:
            rows = [r for r in rows if (r.get("analysis") or {}).get("human_reviewed")]  # filter search results in-process
        total, total_pages, page = len(rows), 1, 1  # search mode has no real pagination: one page of results
    else:
        offset = (page - 1) * PAGE_SIZE  # translate page number into a row offset
        rows = memory.list_memories(
            agent_name=agent_name or None, source_ip=source_ip or None,
            rule_id=rule_id or None, reviewed_only=reviewed_only,
            limit=PAGE_SIZE + 1, offset=offset,  # fetch one extra row to detect a next page cheaply
        )
        has_next = len(rows) > PAGE_SIZE  # the extra row (if present) means there's more beyond this page
        rows = rows[:PAGE_SIZE]  # trim back down to the actual page size before rendering
        total_pages = page + 1 if has_next else page  # cheap pagination without a full COUNT(*)
        total = None  # unknown total in listing mode (only computed in search mode)
    return templates.TemplateResponse(request, "memory_list.html", {
        "analyst": analyst, "nav": "memory", "rows": rows, "page": page, "total_pages": total_pages,
        "total": total, "q": search or "", "agent_name": agent_name or "",
        "source_ip": source_ip or "", "rule_id": rule_id or "", "reviewed": reviewed_only,
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


@protected.get("/memory/{mid}", response_class=HTMLResponse)
def memory_detail(request: Request, mid: int, analyst: dict = Depends(require_analyst)):
    row = memory.get_memory(mid)  # load the memory row by id
    if row is None:
        # Unknown id: render the shared not-found page (reused for both investigations and memory).
        return templates.TemplateResponse(
            request, "not_found.html", {"analyst": analyst, "inv_id": f"memory {mid}"},
            status_code=404)
    return templates.TemplateResponse(request, "memory_detail.html", {
        "analyst": analyst, "nav": "memory", "m": row,
        # json.dumps turns the analysis dict into a JSON text string; indent=2 makes
        # it neatly formatted so it reads well inside the editable <textarea>.
        "analysis_json": json.dumps(row.get("analysis") or {}, indent=2),  # pretty-print for the edit textarea
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


def _mem_back(mid: int, *, msg=None, err=None) -> RedirectResponse:
    qs = f"?msg={msg}" if msg else (f"?err={err}" if err else "")  # build a single flash param, or none
    return RedirectResponse(f"/console/memory/{mid}{qs}", status_code=303)  # back to this memory's detail page


@protected.post("/memory/{mid}/analysis")
def memory_edit_analysis(
    request: Request, mid: int, analyst: dict = Depends(require_analyst),
    analysis: str = Form(...),  # raw JSON text submitted from the edit form
):
    before = memory.get_memory(mid)  # load current row so we can audit the prior analysis
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    try:
        parsed = json.loads(analysis)  # analysis must be valid JSON
        if not isinstance(parsed, dict):
            raise ValueError("not an object")  # must specifically be a JSON object, not e.g. a list/number
    except (json.JSONDecodeError, ValueError):
        return _mem_back(mid, err="analysis+must+be+valid+json+object")
    # Audit BEFORE the mutation; if the audit write fails it raises and we never edit.
    store.write_audit(analyst["username"], "memory_update_analysis", target_type="memory",
                      target_id=str(mid), before=before.get("analysis"), after=parsed,
                      detail="analysis-only edit (no re-embed)")
    memory.update_analysis(mid, parsed)  # locked rule: analysis edit does NOT re-embed
    return _mem_back(mid, msg="analysis+updated+no+reembed")


@protected.post("/memory/{mid}/identity")
def memory_edit_identity(
    request: Request, mid: int, analyst: dict = Depends(require_analyst),
    alert_text: str = Form(...),  # new identity text submitted from the edit form
):
    before = memory.get_memory(mid)  # load current row so we can audit the prior identity text
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    alert_text = alert_text.strip()  # normalize whitespace
    if not alert_text:
        return _mem_back(mid, err="identity+text+required")  # identity text cannot be blank
    store.write_audit(analyst["username"], "memory_reembed_identity", target_type="memory",
                      target_id=str(mid), before={"alert_text": before.get("alert_text")},
                      after={"alert_text": alert_text}, detail="identity edit -> re-embed")  # audit before mutating
    memory.reembed_identity(mid, alert_text)  # locked rule: identity change re-embeds
    return _mem_back(mid, msg="identity+updated+reembedded")


@protected.post("/memory/bulk-delete")
def memory_bulk_delete(
    request: Request, analyst: dict = Depends(require_analyst),
    ids: list[str] = Form(default=[]), back: str = Form(""),  # checked ids + the memory list URL to return to
):
    """Delete every selected memory row. Each is audited BEFORE anything is removed —
    if an audit write fails it raises and nothing is deleted, same rule as the single
    delete. Deleting learned memory changes what the agent knows, so the audit row
    keeps the identity text and analysis that were destroyed."""
    mids = _parse_ids(ids)  # sanitize the untrusted form-submitted id strings
    if not mids:
        return _memory_back(back, err="select+at+least+one+memory")  # nothing was actually selected
    rows = [(mid, memory.get_memory(mid)) for mid in mids]  # load each row (may be None if already gone)
    present = [(mid, row) for mid, row in rows if row is not None]  # keep only rows that still exist
    if not present:
        return _memory_back(back, err="nothing+deleted+-+those+memories+are+already+gone")
    for mid, row in present:  # one audit row per memory, written before any deletion happens
        store.write_audit(
            analyst["username"], "memory_delete", target_type="memory", target_id=str(mid),
            before={"alert_text": row.get("alert_text"), "analysis": row.get("analysis")},
            detail=f"bulk delete of {len(present)} memory row(s) from the memory browser",
        )
    deleted = memory.delete_memories([mid for mid, _ in present])  # perform the actual deletion, after all audits
    return _memory_back(back, msg=f"deleted+{len(deleted)}+memory+row(s)")


def _memory_back(back: str, *, msg: str = None, err: str = None) -> RedirectResponse:
    qs = back.lstrip("?") if _SAFE_QS.fullmatch(back.lstrip("?")) else ""  # only keep `back` if it's a safe querystring
    tail = f"msg={msg}" if msg else f"err={err}"  # append exactly one flash param
    sep = "&" if qs else ""  # only add a separator if there's an existing querystring to join
    return RedirectResponse(f"/console/memory?{qs}{sep}{tail}", status_code=303)  # 303 so the browser re-GETs


@protected.post("/memory/{mid}/delete")
def memory_delete(request: Request, mid: int, analyst: dict = Depends(require_analyst)):
    before = memory.get_memory(mid)  # load current row so we can audit what's being destroyed
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    store.write_audit(analyst["username"], "memory_delete", target_type="memory",
                      target_id=str(mid),
                      before={"alert_text": before.get("alert_text"), "analysis": before.get("analysis")},
                      detail="deleted from memory store")  # audit before mutating
    memory.delete_memory(mid)  # actually remove the row
    return RedirectResponse("/console/memory?msg=memory+deleted", status_code=303)  # back to the memory list


# Finally, attach every /console/* route (the `protected` router) onto the
# top-level `router`. `router` is what the main app imports and serves, so this line
# is what actually makes all the login-protected pages above reachable.
router.include_router(protected)  # mount all /console/* routes onto the module's top-level router
