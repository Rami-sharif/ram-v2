"""Console router. Step B adds two read-only views over the write-once
investigation records: the triage queue and the investigation detail page.
Analyst actions (overrides/feedback/case control) come in Step C.

All routes are session-authenticated; kept entirely separate from the webhook.
"""
import json
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import agent, memory, thehive, triage
from ..config import get_settings
from . import store
from .auth import require_analyst
from .auth import router as auth_router
from .templating import templates

logger = logging.getLogger(__name__)

router = APIRouter()
router.include_router(auth_router)

protected = APIRouter(prefix="/console", tags=["console"])

PAGE_SIZE = 25
SEVERITY_LABELS = ("low", "medium", "high", "critical")
TRIAGE_ACTIONS = ("auto_close", "create_open", "create_flagged", "suppress_duplicate")
_SAFE_QS = re.compile(r"[A-Za-z0-9_=&%.\-+]*")


def _case_url(case_id: Optional[str]) -> Optional[str]:
    """Link into TheHive (system of record). Console is controller only."""
    if not case_id:
        return None
    base = get_settings().console_thehive_public_url.rstrip("/")
    return f"{base}/cases/{case_id}/details"


def _resolve_retrieved(retrieved_ids) -> list[dict]:
    """Resolve each retrieved memory id (a write-once snapshot on the investigation,
    with no FK) to its current memory row. A referenced memory may have been deleted
    since the investigation ran, so a missing id resolves to exists=False and renders
    as 'deleted / not found' — never a 404. We do not link deleted ids."""
    out = []
    for mid in retrieved_ids or []:
        row = memory.get_memory(mid)
        out.append({
            "id": mid,
            "exists": row is not None,
            "source_ip": row.get("source_ip") if row else None,
            "rule_id": row.get("rule_id") if row else None,
        })
    return out


# Actions hidden from the queue's default "actionable only" view.
_RESOLVED_ACTIONS = ("auto_close",)


@protected.get("/", response_class=HTMLResponse)
def overview(request: Request, analyst: dict = Depends(require_analyst)):
    """Landing dashboard: global at-a-glance counts, severity mix, and the
    'needs me now' list. Drill-downs link into the queue with a matching filter."""
    summary = store.summary_counts()
    distribution = store.severity_distribution()
    dist_total = sum(d["n"] for d in distribution) or 1  # avoid /0 for bar widths
    attention = store.needs_attention(limit=8)
    recent, _ = store.list_investigations(limit=8, offset=0)
    accuracy = store.agent_accuracy()
    for r in (*attention, *recent):
        r["case_url"] = _case_url(r.get("case_id"))
    return templates.TemplateResponse(request, "overview.html", {
        "analyst": analyst, "nav": "overview", "summary": summary,
        "distribution": distribution, "dist_total": dist_total,
        "attention": attention, "recent": recent, "accuracy": accuracy,
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


@protected.get("/queue", response_class=HTMLResponse)
def queue(
    request: Request,
    analyst: dict = Depends(require_analyst),
    severity: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    show: Optional[str] = Query(None),  # "all" includes resolved (auto_close)
    page: int = Query(1, ge=1),
):
    severity = severity or None
    action = action or None
    search = (q or "").strip() or None
    show_all = show == "all"
    # Default view hides auto-closed items; an explicit action filter or show=all
    # overrides. exclude_actions is ignored by the store when `action` is set.
    exclude = () if (show_all or action) else _RESOLVED_ACTIONS
    offset = (page - 1) * PAGE_SIZE
    rows, total = store.list_investigations(
        severity_label=severity, triage_action=action, search=search,
        exclude_actions=exclude, limit=PAGE_SIZE, offset=offset,
    )
    for r in rows:
        r["case_url"] = _case_url(r.get("case_id"))
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return templates.TemplateResponse(request, "queue.html", {
        "analyst": analyst, "nav": "queue", "rows": rows, "total": total,
        "page": page, "total_pages": total_pages,
        "severity": severity or "", "action": action or "", "q": search or "",
        "show_all": show_all,
        "severity_labels": SEVERITY_LABELS, "triage_actions": TRIAGE_ACTIONS,
        "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"),
    })


@protected.get("/investigations/{inv_id}", response_class=HTMLResponse)
def investigation_detail(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
):
    rec = store.get_investigation(inv_id)
    if rec is None:
        return templates.TemplateResponse(
            request, "not_found.html", {"analyst": analyst, "inv_id": inv_id},
            status_code=404,
        )
    rec["case_url"] = _case_url(rec["inv"].get("case_id"))
    retrieved = _resolve_retrieved(rec["inv"].get("retrieved_ids"))
    # `chat_context` anchors the assistant dock to THIS investigation: the dock's
    # form posts the id, so "is this a real threat?" needs no case number.
    # When the investigation has no case, offer the right recovery: link it to the
    # case its dedup group already has, or (if the group has none) create one.
    inv = rec["inv"]
    parent_case = None if inv.get("case_id") else triage.parent_case_for(inv)
    if parent_case:
        parent_case = {**parent_case, "url": _case_url(parent_case["case_id"])}
    return templates.TemplateResponse(request, "investigation.html", {
        "analyst": analyst, "nav": "queue", "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"), "retrieved": retrieved,
        "severity_labels": SEVERITY_LABELS, "close_statuses": thehive.CLOSED_STATUSES,
        "chat_context": _chat_context(inv),
        "parent_case": parent_case,
        "can_retry_case": parent_case is None and triage.can_retry_case(inv),
        **rec,
    })


def _chat_context(inv: dict) -> dict:
    """What the dock shows (and posts) when the analyst chats from an investigation."""
    return {
        "investigation_id": inv["id"],
        "label": f"Investigation #{inv['id']}"
                 + (f" · case #{inv['case_number']}" if inv.get("case_number") else ""),
    }


def _parse_ids(raw: list[str], *, cap: int = 200) -> list[int]:
    """Ids arrive from checkbox form fields, so they are untrusted strings. Keep the
    integers, drop duplicates, preserve order, and cap the batch — one click should
    never be able to issue an unbounded delete."""
    out: list[int] = []
    for value in raw:
        try:
            n = int(value)
        except (TypeError, ValueError):
            continue
        if n not in out:
            out.append(n)
    return out[:cap]


@protected.post("/investigations/bulk-delete")
def bulk_delete_investigations(
    request: Request, analyst: dict = Depends(require_analyst),
    ids: list[str] = Form(default=[]), back: str = Form(""),
):
    """Delete every selected investigation. Each one is audited individually (see
    store.delete_investigations) — selecting 20 rows is 20 audit rows, not one."""
    inv_ids = _parse_ids(ids)
    if not inv_ids:
        return _queue_back(back, err="select+at+least+one+alert")
    deleted = store.delete_investigations(inv_ids, actor_username=analyst["username"])
    if not deleted:
        return _queue_back(back, err="nothing+deleted+-+those+alerts+are+already+gone")
    return _queue_back(back, msg=f"deleted+{len(deleted)}+investigation(s)")


def _queue_back(back: str, *, msg: str = None, err: str = None) -> RedirectResponse:
    """Back to the queue view the analyst acted from (filters/page intact)."""
    qs = back.lstrip("?") if _SAFE_QS.fullmatch(back.lstrip("?")) else ""
    tail = f"msg={msg}" if msg else f"err={err}"
    sep = "&" if qs else ""
    return RedirectResponse(f"/console/queue?{qs}{sep}{tail}", status_code=303)


@protected.post("/investigations/{inv_id}/delete")
def delete_investigation(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    back: str = Form(""),
):
    """Drop an alert from the triage queue. Audited FIRST (an audit failure raises
    and nothing is deleted), then the record and its layered human input go."""
    rec = store.get_investigation(inv_id)
    if rec is None:
        return RedirectResponse("/console/queue?err=investigation+not+found", status_code=303)
    inv = rec["inv"]
    store.write_audit(
        analyst["username"], "investigation_delete", target_type="investigation",
        target_id=str(inv_id),
        before={"alert_id": inv.get("alert_id"), "agent_name": inv.get("agent_name"),
                "source_ip": inv.get("source_ip"), "rule_id": inv.get("rule_id"),
                "severity_label": inv.get("severity_label"),
                "triage_action": inv.get("triage_action"), "case_number": inv.get("case_number")},
        detail=f"deleted from triage queue ({len(rec['reviews'])} review(s), "
               f"{len(rec['feedback'])} feedback row(s) removed with it)",
    )
    store.delete_investigation(inv_id)
    return _queue_back(back, msg="investigation+deleted")


def _back(inv_id: int, *, msg: str = None, err: str = None) -> RedirectResponse:
    qs = f"?msg={msg}" if msg else (f"?err={err}" if err else "")
    return RedirectResponse(f"/console/investigations/{inv_id}{qs}", status_code=303)


# --- dashboard-level analyst chat -------------------------------------------
# The assistant is a GLOBAL slide-in dock (rendered from base.html on every
# page). Its thread is lazy-loaded via this GET so no page pays for the history
# until the analyst opens the dock. One ongoing thread per analyst (username).
_CHAT_EMPTY_HTML = (
    '<p class="muted chat-empty" id="chat-empty">No messages yet. Ask about any '
    'recorded case, check whether an IP or hash appeared elsewhere, or request '
    'an audited action on a case.</p>'
)


def _ensure_conversation(analyst: dict) -> dict:
    """The analyst's most-recent conversation, creating a first one if none exist."""
    return (store.most_recent_conversation(analyst["username"])
            or store.create_conversation(analyst["username"]))


def _resolve_conversation(analyst: dict, conversation_id) -> dict:
    """Resolve which conversation a chat turn targets. An explicit id must belong
    to the analyst (authorization); otherwise fall back to their most-recent
    (the dock posts with no id and targets the most-recent chat)."""
    if conversation_id:
        try:
            convo = store.get_conversation(int(conversation_id), analyst["username"])
        except (TypeError, ValueError):
            convo = None
        if convo is not None:
            return convo
    return _ensure_conversation(analyst)


# Dock thread (lazy-loaded): render the analyst's most-recent conversation, with
# its id on the wrapper so the dock's form posts back to the right chat.
@protected.get("/assistant", response_class=HTMLResponse)
def assistant_thread(request: Request, analyst: dict = Depends(require_analyst)):
    convo = _ensure_conversation(analyst)
    chat = store.list_chat(convo["thread_key"])
    return templates.TemplateResponse(request, "_chat_log.html", {
        "messages": chat, "conversation": convo,
    })


# Full-page assistant with multi-conversation management. `c` selects a
# conversation (must be owned); otherwise the most-recent is shown. The dock is
# suppressed here (hide_dock) so #chat-log stays unique and console.js drives it.
@protected.get("/agent", response_class=HTMLResponse)
def agent_page(request: Request, analyst: dict = Depends(require_analyst),
               c: Optional[int] = Query(None)):
    conversations = store.list_conversations(analyst["username"])
    active = None
    if c is not None:
        active = store.get_conversation(c, analyst["username"])
    if active is None:
        active = _ensure_conversation(analyst)
        if not conversations:  # first-ever conversation just created
            conversations = store.list_conversations(analyst["username"])
    chat = store.list_chat(active["thread_key"])
    return templates.TemplateResponse(request, "agent.html", {
        "analyst": analyst, "nav": "agent", "hide_dock": True, "chat": chat,
        "conversations": conversations, "active": active,
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


# --- conversation management (create / rename / delete) ----------------------
@protected.post("/conversations")
def create_conversation(request: Request, analyst: dict = Depends(require_analyst)):
    convo = store.create_conversation(analyst["username"])
    if request.headers.get("HX-Request"):  # dock: swap in the fresh empty thread
        return templates.TemplateResponse(request, "_chat_log.html", {
            "messages": [], "conversation": convo,
        })
    return RedirectResponse(f"/console/agent?c={convo['id']}", status_code=303)


@protected.post("/conversations/{conversation_id}/rename")
def rename_conversation(
    request: Request, conversation_id: int, analyst: dict = Depends(require_analyst),
    title: str = Form(...),
):
    title = title.strip()[:120] or "Untitled chat"
    store.rename_conversation(conversation_id, analyst["username"], title)
    return RedirectResponse(f"/console/agent?c={conversation_id}", status_code=303)


@protected.post("/conversations/{conversation_id}/delete")
def delete_conversation(
    request: Request, conversation_id: int, analyst: dict = Depends(require_analyst),
):
    store.delete_conversation(conversation_id, analyst["username"])
    return RedirectResponse("/console/agent", status_code=303)


# One ongoing thread per analyst (keyed by username), driven from the dock.
# The analyst asks freely; the assistant looks up any case it needs by number and
# may take audited actions on a case it just looked up. Persists the conversation
# (write-once per message); any action the assistant takes is separately audited
# by its underlying tool. HTMX requests get an appended-messages partial; a plain
# POST falls back to a redirect so it works without JS.
@protected.post("/chat")
def post_chat(
    request: Request, analyst: dict = Depends(require_analyst), message: str = Form(...),
    conversation_id: Optional[str] = Form(None),
    investigation_id: Optional[str] = Form(None),
):
    message = message.strip()
    if not message:
        if request.headers.get("HX-Request"):
            return HTMLResponse("", status_code=204)
        return RedirectResponse("/console/queue?err=empty+message", status_code=303)

    # Chatting from an investigation page anchors the turn to that record, so the
    # analyst can say "this alert" without naming a case number. The id comes from
    # the page (not the model), and is only a starting point — the assistant still
    # looks the case up through its audited tools before acting on it.
    focus = None
    if investigation_id:
        try:
            rec = store.get_investigation(int(investigation_id))
        except (TypeError, ValueError):
            rec = None
        focus = rec["inv"] if rec else None

    # Resolve the target conversation (owner-checked); the dock omits the id and
    # targets the most-recent chat. History is that conversation's ONLY — chats
    # are isolated; the shared SOC alert memory stays available via the tools.
    convo = _resolve_conversation(analyst, conversation_id)
    thread_key = convo["thread_key"]
    prior = store.list_chat(thread_key)  # history BEFORE this turn (this chat only)
    store.add_chat_message(thread_key=thread_key, role="analyst",
                           actor=analyst["username"], message=message)
    try:
        reply, tool_calls, referenced = agent.run_interactive(
            message, analyst["username"],
            history=[{"role": h["role"], "message": h["message"]} for h in prior],
            focus_investigation=focus,
        )
    except Exception as exc:  # noqa: BLE001 - never lose the turn; record the failure
        logger.exception("Dashboard chat failed for analyst %s", thread_key)
        reply, tool_calls, referenced = f"(assistant error: {exc})", [], []
    store.add_chat_message(thread_key=thread_key, role="agent", actor="agent",
                           message=reply, tool_calls=tool_calls, referenced_case_ids=referenced)
    # First analyst message titles a still-unnamed chat; bump recency either way.
    if convo.get("title") in (None, "New chat"):
        store.rename_conversation(convo["id"], analyst["username"], message[:48])
    store.touch_conversation(convo["id"])

    if request.headers.get("HX-Request"):
        new_messages = [
            {"role": "analyst", "actor": analyst["username"], "message": message,
             "tool_calls": [], "referenced_case_ids": []},
            {"role": "agent", "actor": "agent", "message": reply,
             "tool_calls": tool_calls, "referenced_case_ids": referenced},
        ]
        return templates.TemplateResponse(request, "_chat_messages.html",
                                          {"messages": new_messages})
    return RedirectResponse("/console/queue?msg=chat+updated", status_code=303)


# --- analyst actions on the verdict / triage decision -----------------------
@protected.post("/investigations/{inv_id}/verdict")
def post_verdict(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    action: str = Form(...), reason: str = Form(""),
    severity_label: str = Form(""), severity_score: str = Form(""),
    attack_type: str = Form(""),
):
    if action not in ("confirm", "override"):
        return _back(inv_id, err="invalid+verdict+action")
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    inv = rec["inv"]
    before = {"severity_label": inv["severity_label"], "severity_score": inv["severity_score"],
              "attack_type": inv["attack_type"]}
    payload = None
    if action == "override":
        payload = {"severity_label": severity_label or None, "attack_type": attack_type or None}
        if severity_score.strip():
            try:
                payload["severity_score"] = int(severity_score)
            except ValueError:
                return _back(inv_id, err="severity+score+must+be+a+number")
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
        logger.exception("Learning-loop memory update failed (verdict recorded) inv=%s", inv_id)
    return _back(inv_id, msg=f"verdict+{action}+recorded")


@protected.post("/investigations/{inv_id}/feedback")
def post_feedback(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    rating: str = Form(...), reason: str = Form(""),
):
    if rating not in ("correct", "incorrect"):
        return _back(inv_id, err="invalid+rating")
    rec = store.get_investigation(inv_id)
    if rec is None:
        return _back(inv_id, err="investigation+not+found")
    before = {"triage_action": rec["inv"]["triage_action"], "triage_branch": rec["inv"]["triage_branch"]}
    store.add_triage_feedback(
        investigation_id=inv_id, actor_username=analyst["username"], rating=rating,
        reason=reason or None, before=before,
    )
    return _back(inv_id, msg=f"triage+marked+{rating}")


# --- TheHive case actions (close / severity / comment only) -----------------
# Ordering per the action contract: perform the mutation through the service
# account, VERIFY it landed via the API, and only THEN write the local audit row.
def _require_case(inv_id: int):
    rec = store.get_investigation(inv_id)
    if rec is None:
        return None, None
    return rec, rec["inv"].get("case_id")


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
        return _back(inv_id, err="case+already+linked")
    parent = triage.parent_case_for(inv)
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
        )
    except Exception:  # noqa: BLE001
        logger.exception("Linking investigation %s to case %s failed", inv_id, parent["case_id"])
        return _back(inv_id, err="linking+the+case+failed")
    return _back(inv_id, msg=f"linked+to+case+%23{parent.get('case_number')}")


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
        return _back(inv_id, err="case+already+linked")
    if not triage.can_retry_case(inv):
        # No stored alert payload (recorded before this feature) or not a case-creating
        # alert — nothing faithful to replay, so refuse rather than invent a case.
        return _back(inv_id, err="this+investigation+cannot+be+retried")
    logger.info("THEHIVE_INTENT actor=%s action=thehive_create_case investigation=%s "
                "original_error=%r", analyst["username"], inv_id, inv.get("case_error"))
    try:
        case = triage.create_case_for_investigation(inv)
    except thehive.TheHiveError as exc:
        logger.error("Case retry failed for investigation %s: %s", inv_id, exc)
        return _back(inv_id, err="case+creation+failed+again")
    try:
        store.link_case(investigation_id=inv_id, case_id=case["_id"], case_number=case.get("number"),
                        actor_username=analyst["username"],
                        before={"case_id": None, "case_error": inv.get("case_error")})
    except Exception:  # noqa: BLE001 - the case EXISTS now; never lose that fact silently
        logger.exception("Case #%s created in TheHive for investigation %s but linking it "
                         "failed (case_id=%s)", case.get("number"), inv_id, case.get("_id"))
        return _back(inv_id, err="case+created+but+linking+failed+-+see+logs")
    return _back(inv_id, msg=f"case+created+%23{case.get('number')}")


@protected.post("/investigations/{inv_id}/case/close")
def post_case_close(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    summary: str = Form(""), resolution: str = Form(thehive.DEFAULT_CLOSE_STATUS),
):
    rec, case_id = _require_case(inv_id)
    if not case_id:
        return _back(inv_id, err="no+linked+case")
    if resolution not in thehive.CLOSED_STATUSES:
        return _back(inv_id, err="invalid+close+resolution")
    # Pre-call intent marker: a durable trace of who tried what, BEFORE the API
    # call, so a (rare) audit-write failure after a verified change still leaves
    # a record. The authoritative audit row is still written verify-then-audit below.
    logger.info("THEHIVE_INTENT actor=%s action=thehive_close case=%s resolution=%r summary=%r",
                analyst["username"], case_id, resolution, summary)
    try:
        thehive.close_case_strict(case_id, summary or "Closed by RAM v2 analyst console.", resolution)
        case = thehive.get_case(case_id)
        if case.get("stage") != "Closed":
            return _back(inv_id, err="close+not+confirmed+in+thehive")
        store.write_audit(analyst["username"], "thehive_close", target_type="thehive_case",
                          target_id=case_id,
                          after={"status": case.get("status"), "stage": case.get("stage")},
                          detail=f"{resolution}: {summary}" if summary else resolution)
    except thehive.TheHiveError as exc:
        logger.error("TheHive close failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+close+failed")
    return _back(inv_id, msg="case+closed")


@protected.post("/investigations/{inv_id}/case/severity")
def post_case_severity(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    severity_label: str = Form(...),
):
    rec, case_id = _require_case(inv_id)
    if not case_id:
        return _back(inv_id, err="no+linked+case")
    target = thehive.severity_to_int(severity_label)
    logger.info("THEHIVE_INTENT actor=%s action=thehive_set_severity case=%s target=%s(%s)",
                analyst["username"], case_id, target, severity_label)
    try:
        before = thehive.get_case(case_id).get("severity")
        thehive.set_severity(case_id, target)
        landed = thehive.get_case(case_id).get("severity")
        if landed != target:
            return _back(inv_id, err="severity+not+confirmed+in+thehive")
        store.write_audit(analyst["username"], "thehive_set_severity", target_type="thehive_case",
                          target_id=case_id, before={"severity": before}, after={"severity": landed},
                          detail=f"set to {severity_label} ({target})")
    except thehive.TheHiveError as exc:
        logger.error("TheHive set_severity failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+severity+failed")
    return _back(inv_id, msg="severity+updated")


@protected.post("/investigations/{inv_id}/case/comment")
def post_case_comment(
    request: Request, inv_id: int, analyst: dict = Depends(require_analyst),
    message: str = Form(...),
):
    rec, case_id = _require_case(inv_id)
    if not case_id:
        return _back(inv_id, err="no+linked+case")
    message = message.strip()
    if not message:
        return _back(inv_id, err="empty+comment")
    stamped = f"[{analyst['username']}] {message}"
    logger.info("THEHIVE_INTENT actor=%s action=thehive_comment case=%s message=%r",
                analyst["username"], case_id, stamped)
    try:
        thehive.post_comment(case_id, stamped)
        landed = any(c.get("message") == stamped for c in thehive.get_case_comments(case_id))
        if not landed:
            return _back(inv_id, err="comment+not+confirmed+in+thehive")
        store.write_audit(analyst["username"], "thehive_comment", target_type="thehive_case",
                          target_id=case_id, after={"message": stamped})
    except thehive.TheHiveError as exc:
        logger.error("TheHive comment failed for case %s: %s", case_id, exc)
        return _back(inv_id, err="thehive+comment+failed")
    return _back(inv_id, msg="comment+added")


# --- Memory browser (list / inspect / edit / delete) ------------------------
# Edits go through the LOCKED memory pipeline: an analysis-only edit never
# re-embeds; an identity edit re-embeds via the same embed() path. Each edit is
# audited FIRST (audit failure aborts the edit -> no unaudited mutation).
@protected.get("/memory", response_class=HTMLResponse)
def memory_list(
    request: Request, analyst: dict = Depends(require_analyst),
    agent_name: Optional[str] = Query(None), source_ip: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None), q: Optional[str] = Query(None),
    reviewed: Optional[str] = Query(None), page: int = Query(1, ge=1),
):
    search = (q or "").strip() or None
    reviewed_only = reviewed == "1"
    if search:
        rows = memory.search_memories(search, agent_name=agent_name or None, k=PAGE_SIZE)
        if reviewed_only:
            rows = [r for r in rows if (r.get("analysis") or {}).get("human_reviewed")]
        total, total_pages, page = len(rows), 1, 1
    else:
        offset = (page - 1) * PAGE_SIZE
        rows = memory.list_memories(
            agent_name=agent_name or None, source_ip=source_ip or None,
            rule_id=rule_id or None, reviewed_only=reviewed_only,
            limit=PAGE_SIZE + 1, offset=offset,
        )
        has_next = len(rows) > PAGE_SIZE
        rows = rows[:PAGE_SIZE]
        total_pages = page + 1 if has_next else page
        total = None
    return templates.TemplateResponse(request, "memory_list.html", {
        "analyst": analyst, "nav": "memory", "rows": rows, "page": page, "total_pages": total_pages,
        "total": total, "q": search or "", "agent_name": agent_name or "",
        "source_ip": source_ip or "", "rule_id": rule_id or "", "reviewed": reviewed_only,
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


@protected.get("/memory/{mid}", response_class=HTMLResponse)
def memory_detail(request: Request, mid: int, analyst: dict = Depends(require_analyst)):
    row = memory.get_memory(mid)
    if row is None:
        return templates.TemplateResponse(
            request, "not_found.html", {"analyst": analyst, "inv_id": f"memory {mid}"},
            status_code=404)
    return templates.TemplateResponse(request, "memory_detail.html", {
        "analyst": analyst, "nav": "memory", "m": row,
        "analysis_json": json.dumps(row.get("analysis") or {}, indent=2),
        "msg": request.query_params.get("msg"), "err": request.query_params.get("err"),
    })


def _mem_back(mid: int, *, msg=None, err=None) -> RedirectResponse:
    qs = f"?msg={msg}" if msg else (f"?err={err}" if err else "")
    return RedirectResponse(f"/console/memory/{mid}{qs}", status_code=303)


@protected.post("/memory/{mid}/analysis")
def memory_edit_analysis(
    request: Request, mid: int, analyst: dict = Depends(require_analyst),
    analysis: str = Form(...),
):
    before = memory.get_memory(mid)
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    try:
        parsed = json.loads(analysis)
        if not isinstance(parsed, dict):
            raise ValueError("not an object")
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
    alert_text: str = Form(...),
):
    before = memory.get_memory(mid)
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    alert_text = alert_text.strip()
    if not alert_text:
        return _mem_back(mid, err="identity+text+required")
    store.write_audit(analyst["username"], "memory_reembed_identity", target_type="memory",
                      target_id=str(mid), before={"alert_text": before.get("alert_text")},
                      after={"alert_text": alert_text}, detail="identity edit -> re-embed")
    memory.reembed_identity(mid, alert_text)  # locked rule: identity change re-embeds
    return _mem_back(mid, msg="identity+updated+reembedded")


@protected.post("/memory/bulk-delete")
def memory_bulk_delete(
    request: Request, analyst: dict = Depends(require_analyst),
    ids: list[str] = Form(default=[]), back: str = Form(""),
):
    """Delete every selected memory row. Each is audited BEFORE anything is removed —
    if an audit write fails it raises and nothing is deleted, same rule as the single
    delete. Deleting learned memory changes what the agent knows, so the audit row
    keeps the identity text and analysis that were destroyed."""
    mids = _parse_ids(ids)
    if not mids:
        return _memory_back(back, err="select+at+least+one+memory")
    rows = [(mid, memory.get_memory(mid)) for mid in mids]
    present = [(mid, row) for mid, row in rows if row is not None]
    if not present:
        return _memory_back(back, err="nothing+deleted+-+those+memories+are+already+gone")
    for mid, row in present:
        store.write_audit(
            analyst["username"], "memory_delete", target_type="memory", target_id=str(mid),
            before={"alert_text": row.get("alert_text"), "analysis": row.get("analysis")},
            detail=f"bulk delete of {len(present)} memory row(s) from the memory browser",
        )
    deleted = memory.delete_memories([mid for mid, _ in present])
    return _memory_back(back, msg=f"deleted+{len(deleted)}+memory+row(s)")


def _memory_back(back: str, *, msg: str = None, err: str = None) -> RedirectResponse:
    qs = back.lstrip("?") if _SAFE_QS.fullmatch(back.lstrip("?")) else ""
    tail = f"msg={msg}" if msg else f"err={err}"
    sep = "&" if qs else ""
    return RedirectResponse(f"/console/memory?{qs}{sep}{tail}", status_code=303)


@protected.post("/memory/{mid}/delete")
def memory_delete(request: Request, mid: int, analyst: dict = Depends(require_analyst)):
    before = memory.get_memory(mid)
    if before is None:
        return _mem_back(mid, err="memory+not+found")
    store.write_audit(analyst["username"], "memory_delete", target_type="memory",
                      target_id=str(mid),
                      before={"alert_text": before.get("alert_text"), "analysis": before.get("analysis")},
                      detail="deleted from memory store")
    memory.delete_memory(mid)
    return RedirectResponse("/console/memory?msg=memory+deleted", status_code=303)


router.include_router(protected)
