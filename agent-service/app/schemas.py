"""Pydantic models: incoming Wazuh alert (lenient) and the structured analysis output."""
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SeverityLabel = Literal["info", "low", "medium", "high", "critical"]


# --------------------------------------------------------------------------- #
# Incoming Wazuh alert
# --------------------------------------------------------------------------- #
# Wazuh alerts are large, nested, and vary by rule/decoder. We model only the
# fields we rely on and allow everything else through (extra="allow") so we never
# reject a valid alert just because its shape differs.
class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="allow")
    level: Optional[int] = None
    description: Optional[str] = None
    id: Optional[str] = None
    mitre: Optional[dict[str, Any]] = None
    groups: Optional[list[str]] = None


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    timestamp: Optional[str] = None
    location: Optional[str] = None
    full_log: Optional[str] = None
    rule: WazuhRule = Field(default_factory=WazuhRule)
    agent: WazuhAgent = Field(default_factory=WazuhAgent)
    data: dict[str, Any] = Field(default_factory=dict)

    @property
    def rule_level(self) -> int:
        return self.rule.level or 0

    @property
    def description(self) -> str:
        return self.rule.description or "(no description)"


# --------------------------------------------------------------------------- #
# Structured analysis output (the agent's deliverable)
# --------------------------------------------------------------------------- #
class MitreMapping(BaseModel):
    model_config = ConfigDict(extra="ignore")
    tactic: Optional[str] = None
    technique: Optional[str] = None
    technique_id: str


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    severity_score: int = Field(ge=0, le=100, description="0-100")
    severity_label: SeverityLabel
    attack_type: str
    mitre: list[MitreMapping] = Field(default_factory=list)
    summary: str
    recommended_action: str


class MemorySearchRequest(BaseModel):
    query: str
    agent_name: Optional[str] = None
    k: int = Field(default=5, ge=1, le=50)


class MemoryUpdateRequest(BaseModel):
    """Edit a memory. analysis-only edits do NOT re-embed; changing alert_text
    (the identity) forces a re-embed. At least one field is required."""
    model_config = ConfigDict(extra="forbid")
    analysis: Optional[dict[str, Any]] = None
    alert_text: Optional[str] = None


class TriageDecision(BaseModel):
    branch: Literal["low", "medium", "high"]
    action: Literal["auto_close", "create_open", "create_flagged", "suppress_duplicate"]
    reason: str
    severity_score: int
    dedup_key: Optional[str] = None
    dedup_eligible: bool = False
    suppressed: bool = False
    occurrence_count: Optional[int] = None
    existing_case_number: Optional[int] = None


class WebhookResponse(BaseModel):
    status: str
    alert_id: Optional[str] = None
    rule_level: int
    enrichment: dict[str, Any] = Field(default_factory=dict)
    analysis: AnalysisResult
    case: Optional[dict[str, Any]] = None  # populated when TheHive case creation runs
    memory: Optional[dict[str, Any]] = None  # retrieval/write-back summary
    triage: Optional[TriageDecision] = None  # deterministic routing decision
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)  # ordered tool calls
