"""Console router. Step B adds two read-only views over the write-once
investigation records: the triage queue and the investigation detail page.
Analyst actions (overrides/feedback/case control) come in Step C.

All routes are session-authenticated; kept entirely separate from the webhook.
"""
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import agent, memory, thehive
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


def _queue_summary(rows: list[dict]) -> dict[str, int]:
    high = flagged = linked_cases = 0
    for row in rows:
        severity = (row.get("severity_label") or "").lower()
        if severity in {"high", "critical"}:
            high += 1
        if (row.get("triage_action") or "").lower() == "create_flagged":
            flagged += 1
        if row.get("case_number"):
            linked_cases += 1
    return {"high": high, "flagged": flagged, "linked_cases": linked_cases}


@protected.get("/", response_class=HTMLResponse)
def queue(
    request: Request,
    analyst: dict = Depends(require_analyst),
    severity: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    severity = severity or None
    action = action or None
    search = (q or "").strip() or None
    offset = (page - 1) * PAGE_SIZE
    rows, total = store.list_investigations(
        severity_label=severity, triage_action=action, search=search,
        limit=PAGE_SIZE, offset=offset,
    )
    for r in rows:
        r["case_url"] = _case_url(r.get("case_id"))
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    chat = store.list_chat(analyst["username"])  # one ongoing thread per analyst
    summary = _queue_summary(rows)
    return templates.TemplateResponse(request, "queue.html", {
        "analyst": analyst, "rows": rows, "total": total,
        "page": page, "total_pages": total_pages,
        "severity": severity or "", "action": action or "", "q": search or "",
        "severity_labels": SEVERITY_LABELS, "triage_actions": TRIAGE_ACTIONS,
        "chat": chat, "summary": summary, "msg": request.query_params.get("msg"),
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
    return templates.TemplateResponse(request, "investigation.html", {
        "analyst": analyst, "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"), "retrieved": retrieved,
        "severity_labels": SEVERITY_LABELS, "close_statuses": thehive.CLOSED_STATUSES,
        **rec,
    })


def _back(inv_id: int, *, msg: str = None, err: str = None) -> RedirectResponse:
    qs = f"?msg={msg}" if msg else (f"?err={err}" if err else "")
    return RedirectResponse(f"/console/investigations/{inv_id}{qs}", status_code=303)


# --- dashboard-level analyst chat -------------------------------------------
# One ongoing thread per analyst (keyed by username), lives on the queue page.
# The analyst asks freely; the assistant looks up any case it needs by number and
# may take audited actions on a case it just looked up. Persists the conversation
# (write-once per message); any action the assistant takes is separately audited
# by its underlying tool. HTMX requests get an appended-messages partial; a plain
# POST falls back to a redirect so it works without JS.
@protected.post("/chat")
def post_chat(
    request: Request, analyst: dict = Depends(require_analyst), message: str = Form(...),
):
    message = message.strip()
    thread_key = analyst["username"]
    if not message:
        if request.headers.get("HX-Request"):
            return HTMLResponse("", status_code=204)
        return RedirectResponse("/console/?err=empty+message", status_code=303)

    prior = store.list_chat(thread_key)  # history BEFORE this turn
    store.add_chat_message(thread_key=thread_key, role="analyst",
                           actor=analyst["username"], message=message)
    try:
        reply, tool_calls, referenced = agent.run_interactive(
            message, analyst["username"],
            history=[{"role": h["role"], "message": h["message"]} for h in prior],
        )
    except Exception as exc:  # noqa: BLE001 - never lose the turn; record the failure
        logger.exception("Dashboard chat failed for analyst %s", thread_key)
        reply, tool_calls, referenced = f"(assistant error: {exc})", [], []
    store.add_chat_message(thread_key=thread_key, role="agent", actor="agent",
                           message=reply, tool_calls=tool_calls, referenced_case_ids=referenced)

    if request.headers.get("HX-Request"):
        new_messages = [
            {"role": "analyst", "actor": analyst["username"], "message": message,
             "tool_calls": [], "referenced_case_ids": []},
            {"role": "agent", "actor": "agent", "message": reply,
             "tool_calls": tool_calls, "referenced_case_ids": referenced},
        ]
        return templates.TemplateResponse(request, "_chat_messages.html",
                                          {"messages": new_messages})
    return RedirectResponse("/console/?msg=chat+updated", status_code=303)


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
    page: int = Query(1, ge=1),
):
    search = (q or "").strip() or None
    if search:
        rows = memory.search_memories(search, agent_name=agent_name or None, k=PAGE_SIZE)
        total, total_pages, page = len(rows), 1, 1
    else:
        offset = (page - 1) * PAGE_SIZE
        rows = memory.list_memories(
            agent_name=agent_name or None, source_ip=source_ip or None,
            rule_id=rule_id or None, limit=PAGE_SIZE + 1, offset=offset,
        )
        has_next = len(rows) > PAGE_SIZE
        rows = rows[:PAGE_SIZE]
        total_pages = page + 1 if has_next else page
        total = None
    return templates.TemplateResponse(request, "memory_list.html", {
        "analyst": analyst, "rows": rows, "page": page, "total_pages": total_pages,
        "total": total, "q": search or "", "agent_name": agent_name or "",
        "source_ip": source_ip or "", "rule_id": rule_id or "",
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
        "analyst": analyst, "m": row,
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
