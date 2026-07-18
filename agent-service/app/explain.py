"""Explainability: a compact, structured "why this verdict" summary for the console.

WHAT THIS FILE IS, FOR A NEWCOMER:
The investigation detail page already shows the FULL step-by-step tool trace (everything the
agent did). That's thorough but noisy. This module produces a SHORT summary — three or four
one-line facts an analyst can skim to understand why a verdict landed where it did: which past
cases pushed it, which MITRE technique matched, the single strongest enrichment signal, and a
one-phrase "confidence basis". It is pure computation over data that ALREADY exists at verdict
time (retrieved memory scores from the RAG layer, the alert's MITRE tags, and the tool results)
— there is NO extra LLM call.

TWO BUILD PATHS (same output shape, shared helpers):
  - build_explanation(...)         — INSERT time, full fidelity. Runs in the webhook pipeline
    with the live, scored memory rows in hand (exact similarity / final_score / is_exact), so
    the result is exact. Stored once under analysis['explanation'] (alert_investigations is
    write-once, so this must happen at INSERT, never a later UPDATE).
  - build_explanation_from_record  — RENDER time, best-effort. For investigations written
    before explanations were stored: recompute from the immutable row's stored fields
    (retrieved_ids, enrichment, alert_payload). Numeric scores were transient and aren't
    stored, so they're omitted; the qualitative signals (weight_type, MITRE, tool signal,
    confidence basis) are re-derived. NO database writes — the write-once guarantee is untouched.
"""
import logging  # best-effort logging; explanation failures must never break the pipeline/page
from typing import Any, Optional  # loose typing for the JSON-ish investigation/memory dicts

logger = logging.getLogger(__name__)  # module logger

MAX_TOP_MEMORIES = 3  # keep the summary to the top few precedents, not the full retrieved pool


# --------------------------------------------------------------------------- #
# Shared derivations (used by both the insert-time and render-time builders)
# --------------------------------------------------------------------------- #
def _weight_type(*, is_exact: bool, mem_analysis: Optional[dict[str, Any]]) -> str:
    """Classify WHY a retrieved memory carried weight, most-authoritative first.
    Mirrors the RAG ranking signals: an exact indicator match dominates; otherwise an
    analyst's recorded verdict (override/confirm) outranks an unverified pattern match."""
    if is_exact:
        return "exact_ioc"  # shared exact indicator (IP/hash/domain) — the hard signal
    a = mem_analysis or {}
    if a.get("human_reviewed"):
        return "override" if a.get("human_action") == "override" else "confirmed"
    return "unverified"  # auto-closed / never reviewed


_WHY_BASE = {
    "exact_ioc": "exact indicator match with a past alert",
    "override": "analyst-corrected precedent",
    "confirmed": "analyst-confirmed precedent",
    "unverified": "similar past pattern (not yet analyst-verified)",
}


def _why(weight_type: str, *, same_rule: bool, source_ip: Optional[str]) -> str:
    """One short human phrase for a single precedent, e.g. 'analyst-confirmed precedent,
    same detection rule'. Kept to one line per the summary contract."""
    if weight_type == "exact_ioc" and source_ip:
        base = f"exact indicator match (source IP {source_ip})"
    else:
        base = _WHY_BASE.get(weight_type, "related past alert")
    if same_rule:
        base += ", same detection rule"
    return base


def _key_tool_signal(enrichment: Optional[dict[str, Any]]) -> Optional[str]:
    """The single strongest external-reputation signal gathered during the investigation.
    Scans the tool-result (enrichment) dict for VirusTotal verdicts and returns the most
    severe as a one-liner. Returns None when no reputation lookup was performed."""
    if not enrichment:
        return None
    best: Optional[tuple[int, int, str]] = None  # (severity_rank, count, text) — max wins
    for res in enrichment.values():
        # VirusTotal results are the ones carrying an engine breakdown ("malicious" key).
        if not isinstance(res, dict) or not res.get("found") or "malicious" not in res:
            continue
        ident = res.get("ip") or res.get("hash") or res.get("domain") or "indicator"
        mal = int(res.get("malicious") or 0)
        susp = int(res.get("suspicious") or 0)
        total = mal + susp + int(res.get("harmless") or 0) + int(res.get("undetected") or 0)
        if mal > 0:
            cand = (2, mal, f"VirusTotal: {ident} flagged malicious by {mal}/{total} engines")
        elif susp > 0:
            cand = (1, susp, f"VirusTotal: {ident} flagged suspicious by {susp}/{total} engines")
        else:
            cand = (0, 0, f"VirusTotal: {ident} clean ({total} engines, none flagged)")
        if best is None or cand[:2] > best[:2]:  # prefer higher severity, then higher count
            best = cand
    return best[2] if best else None


def _confidence_basis(top_memories: list[dict[str, Any]]) -> str:
    """One phrase explaining what the verdict's confidence rests on, per the plan's rules:
    an exact IOC match is the strongest; else analyst-verified precedent; else pattern-only."""
    if not top_memories:
        return "no prior precedent — pattern-based verdict only"
    types = [m["weight_type"] for m in top_memories]
    verified = sum(1 for t in types if t in ("override", "confirmed"))
    plural = "s" if verified != 1 else ""
    if "exact_ioc" in types:
        return (f"exact IOC match + {verified} analyst-verified precedent{plural}"
                if verified else "exact IOC match with a past alert")
    if verified:
        kind = "corrected" if "override" in types else "confirmed"
        return f"{verified} analyst-{kind} precedent{plural}"
    return "pattern match only, no verified precedent"


def _mitre_match(mitre_ids: str, analysis_technique_ids: list[Optional[str]]) -> Optional[dict[str, Any]]:
    """The MITRE technique behind the verdict. Prefer the INPUT-side id (immutable, what the
    Wazuh rule mapped) and fall back to the agent's own analysis mapping."""
    if mitre_ids:
        return {"technique_id": mitre_ids.split(",")[0], "source": "input alert rule"}
    for tid in analysis_technique_ids:
        if tid:
            return {"technique_id": tid, "source": "agent analysis"}
    return None


def _top_entry(*, memory_id, weight_type: str, why: str,
               similarity=None, final_score=None) -> dict[str, Any]:
    """Assemble one top_memories entry, including numeric scores only when we have them
    (insert-time path). memory_id links to the console memory-detail page."""
    entry: dict[str, Any] = {"memory_id": memory_id, "weight_type": weight_type, "why": why}
    if similarity is not None:
        entry["similarity"] = round(float(similarity), 3)
    if final_score is not None:
        entry["final_score"] = round(float(final_score), 3)
    return entry


# --------------------------------------------------------------------------- #
# INSERT-time builder (full fidelity, from live scored memory rows)
# --------------------------------------------------------------------------- #
def build_explanation(alert, analysis, memories: list[dict[str, Any]],
                      enrichment: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Build the explanation from the verdict-time data. `memories` are the scored rows
    returned by memory.retrieve (carry similarity/final_score/is_exact/is_similar)."""
    from . import memory  # local import keeps module load order simple

    top: list[dict[str, Any]] = []
    for m in memories:
        if not m.get("is_similar"):
            continue  # recency-only filler isn't part of "why this verdict"
        wt = _weight_type(is_exact=bool(m.get("is_exact")), mem_analysis=m.get("analysis"))
        top.append(_top_entry(
            memory_id=m.get("id"), weight_type=wt,
            why=_why(wt, same_rule=(m.get("rule_id") == alert.rule.id),
                     source_ip=m.get("source_ip")),
            similarity=m.get("similarity"), final_score=m.get("final_score"),
        ))
        if len(top) >= MAX_TOP_MEMORIES:
            break
    return {
        "top_memories": top,
        "mitre_match": _mitre_match(memory.mitre_ids_of(alert),
                                    [mm.technique_id for mm in (analysis.mitre or [])]),
        "key_tool_signal": _key_tool_signal(enrichment),
        "confidence_basis": _confidence_basis(top),
    }


# --------------------------------------------------------------------------- #
# RENDER-time builder (best-effort, from a stored write-once record)
# --------------------------------------------------------------------------- #
def build_explanation_from_record(inv: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return a stored explanation if the investigation has one; otherwise recompute a
    best-effort explanation from the immutable row's stored fields. NO database writes.

    Numeric similarity/final_score were transient (not stored on the row) so they're omitted
    here; the qualitative signals are re-derived: exact-IOC is recomputed structurally (shared
    source IP, or an alert IOC appearing in the memory text), MITRE from the retained alert
    payload (or the analysis), and the tool signal from the stored enrichment."""
    from . import memory  # get_memory / extract_iocs / mitre_ids_of
    from .schemas import WazuhAlert  # reconstruct the alert from the retained payload

    analysis = inv.get("analysis") or {}
    stored = analysis.get("explanation")
    if stored:
        return stored  # new-path insert already stored a full-fidelity explanation

    inv_ip = inv.get("source_ip")
    inv_rule = inv.get("rule_id")
    # Reconstruct the alert (for MITRE + IOC recompute) when its payload was retained.
    alert = None
    payload = inv.get("alert_payload")
    if payload:
        try:
            alert = WazuhAlert.model_validate(payload)
        except Exception:  # noqa: BLE001 - a malformed payload just means less to work with
            alert = None
    iocs = memory.extract_iocs(alert) if alert is not None else {"ips": [], "hashes": [], "domains": []}
    alert_ips = set(iocs["ips"]) | ({inv_ip} if inv_ip else set())  # exact-IP indicators
    text_tokens = set(iocs["hashes"]) | set(iocs["domains"])  # hash/domain: safe substring match

    top: list[dict[str, Any]] = []
    for mid in (inv.get("retrieved_ids") or [])[:MAX_TOP_MEMORIES]:
        row = memory.get_memory(mid)
        if row is None:
            continue  # memory deleted since — skip
        mem_ip = row.get("source_ip")
        mem_text = row.get("alert_text") or ""
        is_exact = bool(
            (mem_ip and mem_ip in alert_ips)
            or (text_tokens and any(tok in mem_text for tok in text_tokens))
        )
        wt = _weight_type(is_exact=is_exact, mem_analysis=row.get("analysis"))
        top.append(_top_entry(
            memory_id=mid, weight_type=wt,
            why=_why(wt, same_rule=(row.get("rule_id") == inv_rule), source_ip=mem_ip),
        ))
    mitre_ids = memory.mitre_ids_of(alert) if alert is not None else ""
    analysis_tids = [(m or {}).get("technique_id") for m in (analysis.get("mitre") or [])]
    return {
        "top_memories": top,
        "mitre_match": _mitre_match(mitre_ids, analysis_tids),
        "key_tool_signal": _key_tool_signal(inv.get("enrichment")),
        "confidence_basis": _confidence_basis(top),
    }
