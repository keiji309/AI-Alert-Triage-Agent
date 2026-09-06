from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

__all__ = [
    "Disposition", "Severity", "PrefilterAction", "CaseStatus", "PrefilterDecision",
    "Event", "Alert", "EntitySet", "Case", "EvidenceRef",
    "RecommendedAction", "ToolCallRecord", "Verdict",
]


class Disposition(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"
    INVESTIGATE = "investigate"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PrefilterAction(str, enum.Enum):
    SUPPRESS = "suppress"     # deterministic auto-resolve, no LLM tokens
    ESCALATE = "escalate"     # always reach the agent tier
    CLASSIFY = "classify"     # ambiguous -> agent decides


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    RESOLVED = "resolved"
    AUTO_RESOLVED = "auto_resolved"


class PrefilterDecision(BaseModel):
    alert_id: str
    action: PrefilterAction
    reason: str
    disposition_hint: str = ""
    confidence: float = 0.0
    rule_hits: List[str] = Field(default_factory=list)


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def max_severity(sev: List[Severity]) -> Severity:
    return max(sev, key=lambda s: _SEVERITY_RANK[s])


class Event(BaseModel):
    """A normalized log event from any source (auth, endpoint, network, ...)."""

    id: str
    source: str
    timestamp: datetime
    event_type: str
    action: str = "allow"
    outcome: str = "success"
    actor_user: Optional[str] = None
    actor_ip: Optional[str] = None
    actor_host: Optional[str] = None
    target_user: Optional[str] = None
    target_host: Optional[str] = None
    target_ip: Optional[str] = None
    geo: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)
    risk: float = 0.0


class Alert(BaseModel):
    """A detection produced by the (mini-)SIEM, pointing at evidence events."""

    id: str
    rule_name: str
    title: str
    severity: Severity
    description: str
    timestamp: datetime
    source: str  # detection source, e.g. auth, edr, ids, email
    mitre: List[str] = Field(default_factory=list)
    entity_user: Optional[str] = None
    entity_ip: Optional[str] = None
    entity_host: Optional[str] = None
    event_ids: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)


class EntitySet(BaseModel):
    users: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)


class Case(BaseModel):
    """A correlated incident: one or more alerts stitched by shared entities/time."""

    id: str
    title: str
    alerts: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    entities: EntitySet = Field(default_factory=EntitySet)
    window_start: datetime
    window_end: datetime
    implied_severity: Severity = Severity.LOW
    signals: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)


class EvidenceRef(BaseModel):
    id: str
    label: str
    kind: str = "event"  # event | alert | intel | context
    detail: str = ""
    tool: str = ""
    timestamp: Optional[datetime] = None


class RecommendedAction(BaseModel):
    action: str
    description: str
    requires_approval: bool = True


class ToolCallRecord(BaseModel):
    step: int
    tool: str
    input: Dict[str, Any] = Field(default_factory=dict)
    output: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Verdict(BaseModel):
    """Structured, auditable outcome of an investigation."""

    case_id: str
    disposition: Disposition
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    investigation_summary: str = ""
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[EvidenceRef] = Field(default_factory=list)
    mitre_relevance: List[str] = Field(default_factory=list)
    indicators: List[Dict[str, str]] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    tool_trace: List[ToolCallRecord] = Field(default_factory=list)
    model: str = ""
    llm_used: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str = ""