"""Pydantic models describing the data that flows through the service.

Pydantic models are Python classes that define the SHAPE of some data (which fields
exist and their types). When you feed raw JSON into a model, Pydantic validates it,
converts types, applies defaults, and rejects anything invalid — so the rest of the
code can trust the data instead of hand-checking every field. Two flavours here:
the *incoming* Wazuh alert (kept lenient, since we don't control its shape) and the
*outgoing* structured analysis the agent must produce (kept strict).
"""
# Typing helpers used in the field annotations below:
#   Any      — "any type at all" (for free-form nested JSON we don't pin down).
#   Literal  — restricts a value to a fixed set of allowed constants (see SeverityLabel).
#   Optional — shorthand for "this type OR None" (i.e. the field may be missing/null).
from typing import Any, Literal, Optional

# The core Pydantic tools:
#   BaseModel  — subclass it to define a validated data model.
#   ConfigDict — per-model settings (e.g. what to do with unexpected fields).
#   Field      — attaches extra rules/defaults to a single field (ranges, factories, docs).
from pydantic import BaseModel, ConfigDict, Field

# A reusable type alias: severity_label may ONLY be one of these five strings. Using it
# as a field type makes Pydantic reject any other value automatically.
SeverityLabel = Literal["info", "low", "medium", "high", "critical"]


# --------------------------------------------------------------------------- #
# Incoming Wazuh alert
# --------------------------------------------------------------------------- #
# Wazuh alerts are large, nested, and vary by rule/decoder. We model only the
# fields we rely on and allow everything else through (extra="allow") so we never
# reject a valid alert just because its shape differs.
# Rule metadata sub-object of a Wazuh alert (severity level, description, MITRE mapping, etc).
class WazuhRule(BaseModel):
    # extra="allow": keep any fields we didn't declare instead of dropping or rejecting
    # them. Wazuh sends far more than we model here, and we never want to reject a valid
    # alert just because it carries an extra field we didn't anticipate.
    model_config = ConfigDict(extra="allow")
    # `Optional[int] = None` means: an integer if present, otherwise None. Every field
    # here is optional because different Wazuh rules/decoders emit different subsets.
    level: Optional[int] = None
    # Human-readable rule description.
    description: Optional[str] = None
    # Rule identifier string.
    id: Optional[str] = None
    # Raw MITRE ATT&CK mapping data as Wazuh provides it, left unstructured.
    mitre: Optional[dict[str, Any]] = None
    # Rule group tags (e.g. "authentication_failed").
    groups: Optional[list[str]] = None


# Agent (the Wazuh-monitored host) metadata sub-object of a Wazuh alert.
class WazuhAgent(BaseModel):
    # Allow unknown fields through unchanged rather than rejecting the alert.
    model_config = ConfigDict(extra="allow")
    # Wazuh's internal agent id.
    id: Optional[str] = None
    # Hostname of the monitored agent.
    name: Optional[str] = None
    # IP address of the monitored agent.
    ip: Optional[str] = None


# Top-level incoming Wazuh alert payload, as posted to /webhook/wazuh.
class WazuhAlert(BaseModel):
    # Allow unknown fields through unchanged rather than rejecting the alert.
    model_config = ConfigDict(extra="allow")
    # Wazuh's alert id.
    id: Optional[str] = None
    # Alert timestamp as a raw string (format varies by Wazuh version/decoder).
    timestamp: Optional[str] = None
    # Log source location/path.
    location: Optional[str] = None
    # The raw original log line that triggered the rule.
    full_log: Optional[str] = None
    # A model can nest other models. `default_factory=WazuhRule` means "if this field is
    # missing, build a fresh empty WazuhRule()". A factory (not a plain default) is used
    # because every alert needs its OWN object; sharing one mutable default would be a bug.
    rule: WazuhRule = Field(default_factory=WazuhRule)
    # Nested agent details; same pattern — an empty WazuhAgent when the field is absent.
    agent: WazuhAgent = Field(default_factory=WazuhAgent)
    # Decoder-specific extra fields (e.g. srcip, dstip). Free-form dict, defaults to empty.
    data: dict[str, Any] = Field(default_factory=dict)

    # A @property is accessed like an attribute (alert.rule_level, no parentheses). This
    # one hides the "the level might be missing" detail so callers always get a plain int.
    @property
    def rule_level(self) -> int:
        # Coalesce None to 0 so callers can always treat this as an int.
        return self.rule.level or 0

    # Convenience accessor: human-readable description with a safe fallback.
    @property
    def description(self) -> str:
        # Coalesce missing/empty description to a placeholder string.
        return self.rule.description or "(no description)"


# --------------------------------------------------------------------------- #
# Structured analysis output (the agent's deliverable)
# --------------------------------------------------------------------------- #
# MITRE ATT&CK is a public catalogue of attacker tactics and techniques (each with an
# id like T1566). One instance of this model links an alert to one such technique.
class MitreMapping(BaseModel):
    # extra="ignore": silently discard unexpected fields. The output here is generated by
    # the LLM, so we tolerate it emitting extra keys — we just keep the ones we declared.
    # (Contrast with extra="allow" on the incoming alert, which KEEPS the extras.)
    model_config = ConfigDict(extra="ignore")
    # MITRE tactic name (e.g. "Initial Access").
    tactic: Optional[str] = None
    # MITRE technique name (e.g. "Phishing").
    technique: Optional[str] = None
    # MITRE technique id (e.g. "T1566"); required since this is the canonical identifier.
    technique_id: str


# The structured output the LLM agent must produce for each alert. Modelling it as a
# Pydantic class means we can validate the model's answer and fail loudly if it's
# malformed, instead of passing bad data downstream.
class AnalysisResult(BaseModel):
    # Drop any unexpected fields the model might emit rather than failing validation.
    model_config = ConfigDict(extra="ignore")
    # Field(ge=0, le=100) enforces 0 <= score <= 100 at validation time (ge = "greater/equal",
    # le = "less/equal"). This 0-100 scale is fixed; the triage thresholds in config.py
    # assume it. `description` documents the field in the auto-generated API schema.
    severity_score: int = Field(ge=0, le=100, description="0-100")
    # Human-facing severity bucket, constrained to the SeverityLabel literal set.
    severity_label: SeverityLabel
    # Short classification of the attack/activity type.
    attack_type: str
    # Zero or more MITRE mappings; empty list if none apply.
    mitre: list[MitreMapping] = Field(default_factory=list)
    # Free-text summary of the analysis.
    summary: str
    # Free-text recommended remediation/next action.
    recommended_action: str
    # The concrete findings the agent established during THIS investigation, one per entry.
    # `submit_analysis` marks this REQUIRED for the model, but it defaults to [] here on
    # purpose: the rule-based `_fallback_analysis` never runs an investigation and so has no
    # findings to cite, and analyses recorded before this field existed must still validate
    # when they are read back out of the database.
    evidence: list[str] = Field(default_factory=list)


# Request body for POST /memory/search. FastAPI uses this model to parse and validate
# the incoming JSON body automatically — the route just receives a ready MemorySearchRequest.
class MemorySearchRequest(BaseModel):
    # `query: str` with no default makes it required — the request is rejected without it.
    query: str
    # Optional scoping to a specific agent/host's memories.
    agent_name: Optional[str] = None
    # How many top matches to return. Field bounds it to 1..50 (ge/le) so a caller can't
    # request 0 or an absurdly large number; default is 5.
    k: int = Field(default=5, ge=1, le=50)


# Request body for PATCH /memory/{memory_id}.
class MemoryUpdateRequest(BaseModel):
    """Edit a memory. analysis-only edits do NOT re-embed; changing alert_text
    (the identity) forces a re-embed. At least one field is required."""
    # extra="forbid": reject any field we didn't declare. This is the STRICTEST of the
    # three modes (allow / ignore / forbid). Used here because a human operator writes
    # this edit, so a typo'd field name should be an error, not silently swallowed.
    model_config = ConfigDict(extra="forbid")
    # New analysis JSON to store; None means "don't touch analysis".
    analysis: Optional[dict[str, Any]] = None
    # New identity/alert text; None means "don't touch identity" (and thus no re-embed).
    alert_text: Optional[str] = None


# The deterministic triage router's decision for one alert. "Deterministic" = fixed
# rules based on the score/thresholds, not the LLM — so the routing is predictable/auditable.
class TriageDecision(BaseModel):
    # Literal[...] again constrains the value to exactly these strings. branch = which
    # severity bucket this alert fell into.
    branch: Literal["low", "medium", "high"]
    # The concrete action taken as a result of the branch (create a case, suppress, etc).
    action: Literal["auto_close", "create_open", "create_flagged", "suppress_duplicate"]
    # Human-readable explanation of why this branch/action was chosen.
    reason: str
    # The severity score the decision was based on (duplicated here for convenience/auditing).
    severity_score: int
    # Deduplication key used to detect repeat alerts; None if dedup doesn't apply.
    dedup_key: Optional[str] = None
    # Whether this alert type is eligible for deduplication at all.
    dedup_eligible: bool = False
    # Whether this specific alert was suppressed as a duplicate.
    suppressed: bool = False
    # How many times this same alert (by dedup_key) has occurred in the window, if tracked.
    occurrence_count: Optional[int] = None
    # If a duplicate matched an existing open case, its case number for reference.
    existing_case_number: Optional[int] = None


# The full response body returned by POST /webhook/wazuh. Bundles every stage's output
# (analysis, triage, case, memory, tool trace) into one validated JSON reply.
class WebhookResponse(BaseModel):
    # Overall pipeline status string (e.g. "ok").
    status: str
    # Echo of the original alert id, if present.
    alert_id: Optional[str] = None
    # Echo of the alert's rule level.
    rule_level: int
    # Enrichment data gathered during analysis (e.g. VirusTotal results), free-form.
    enrichment: dict[str, Any] = Field(default_factory=dict)
    # The structured analysis result produced by the agent.
    analysis: AnalysisResult
    case: Optional[dict[str, Any]] = None  # populated when TheHive case creation runs
    memory: Optional[dict[str, Any]] = None  # retrieval/write-back summary
    triage: Optional[TriageDecision] = None  # deterministic routing decision
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)  # ordered tool calls
