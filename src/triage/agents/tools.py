from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from ..intel.reputation import ThreatIntel
from ..models import Alert, Case, Disposition, Event, EvidenceRef, RecommendedAction, Severity, Verdict
from . import context

TOOL_NAMES = [
    "query_logs",
    "get_user_context",
    "get_asset_context",
    "lookup_ip_reputation",
    "get_mitre_technique",
    "submit_verdict",
]

VERDICT_TOOL_SCHEMA: Dict[str, Any] = {
    "name": "submit_verdict",
    "description": (
        "Finalize the investigation with a structured verdict. This is the ONLY way to "
        "finish — call it when you have gathered enough evidence. All fields are required."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "disposition": {
                "type": "string",
                "enum": ["true_positive", "false_positive", "suspicious", "investigate"],
                "description": "true_positive = real attack; false_positive = benign; "
                               "suspicious = likely but needs human review; investigate = cannot conclude.",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "How confident you are in the disposition (0.0-1.0).",
            },
            "summary": {"type": "string", "description": "One-paragraph plain-English explanation of the incident."},
            "investigation_summary": {
                "type": "string",
                "description": "What you did to investigate and what evidence you relied on.",
            },
            "mitre_relevance": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique IDs most relevant to this incident.",
            },
            "indicators": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "description": "e.g. ipv4, domain, file-hash, username"},
                        "value": {"type": "string"},
                    },
                    "required": ["type", "value"],
                },
            },
            "recommended_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "description": {"type": "string"},
                        "requires_approval": {
                            "type": "boolean",
                            "description": "True if this action is destructive/impactful and a human must approve.",
                        },
                    },
                    "required": ["action", "description", "requires_approval"],
                },
            },
            "notes": {"type": "string", "description": "Anything unusual, data gaps, or assumptions."},
        },
        "required": [
            "disposition", "severity", "confidence", "summary", "investigation_summary",
            "mitre_relevance", "indicators", "recommended_actions", "notes",
        ],
    },
}


@dataclass
class ToolContext:
    case: Case
    alerts: Dict[str, Alert]
    events: Dict[str, Event]
    intel: ThreatIntel
    submitted_verdict: Optional[Verdict] = None
    tool_trace: List[Dict] = field(default_factory=list)

    def event(self, eid: str) -> Optional[Event]:
        return self.events.get(eid)

    def case_events(self) -> List[Event]:
        return [self.events[eid] for eid in self.case.event_ids if eid in self.events]

    def case_alerts(self) -> List[Alert]:
        return [self.alerts[a] for a in self.case.alerts if a in self.alerts]


def _to_event_dict(ev: Event) -> Dict[str, Any]:
    return {
        "id": ev.id, "source": ev.source, "timestamp": ev.timestamp.isoformat(),
        "event_type": ev.event_type, "action": ev.action, "outcome": ev.outcome,
        "actor_user": ev.actor_user, "actor_ip": ev.actor_ip, "actor_host": ev.actor_host,
        "target_user": ev.target_user, "target_host": ev.target_host, "target_ip": ev.target_ip,
        "geo": ev.geo, "detail": ev.detail,
    }


def _emit(ctx: ToolContext, tool: str, inp: Dict[str, Any], output: Any) -> str:
    text = output if isinstance(output, str) else json.dumps(output, indent=2, default=str)
    ctx.tool_trace.append({"tool": tool, "input": inp, "output": text,
                           "timestamp": datetime.utcnow().isoformat()})
    return text


def tool_query_logs(ctx: ToolContext, **kw: Any) -> str:
    source = kw.get("source")
    users = kw.get("users", [])
    hosts = kw.get("hosts", [])
    ips = kw.get("ips", [])
    event_types = kw.get("event_types", [])
    window_minutes = int(kw.get("window_minutes", 60))
    limit = int(kw.get("limit", 50))

    if isinstance(users, str):
        users = [users]
    if isinstance(hosts, str):
        hosts = [hosts]
    if isinstance(ips, str):
        ips = [ips]
    if isinstance(event_types, str):
        event_types = [event_types]

    ts = ctx.case.window_end
    cutoff = ts - timedelta(minutes=window_minutes)
    end_forward = ts + timedelta(minutes=window_minutes + 120)

    matches: List[Event] = []
    for ev in ctx.events.values():
        if ev.timestamp < cutoff or ev.timestamp > end_forward:
            continue
        if source and ev.source != source:
            continue
        if users and ev.actor_user not in users and ev.target_user not in users:
            continue
        if hosts and ev.actor_host not in hosts and ev.target_host not in hosts:
            continue
        if ips and ev.actor_ip not in ips and ev.target_ip not in ips:
            continue
        if event_types and ev.event_type not in event_types:
            continue
        matches.append(ev)

    matches.sort(key=lambda e: e.timestamp)
    return _emit(ctx, "query_logs", kw, {
        "matched": len(matches),
        "events": [_to_event_dict(e) for e in matches[:limit]],
        "note": f"Showing up to {limit} of {len(matches)} matching events.",
    })


def tool_get_user_context(ctx: ToolContext, **kw: Any) -> str:
    user = kw.get("user", "")
    ret = context.get_user(user) or {"role": "unknown", "known_locations": [], "expected_devices": []}
    events = [e for e in ctx.events.values() if e.actor_user == user]
    ret["recent_auth_count"] = sum(1 for e in events if e.source == "auth")
    ret["recent_event_count"] = len(events)
    ret["is_service_account"] = bool(ret.get("service"))
    return _emit(ctx, "get_user_context", kw, ret)


def tool_get_asset_context(ctx: ToolContext, **kw: Any) -> str:
    host = kw.get("host", "")
    ret = context.get_asset(host)
    if ret is None:
        return _emit(ctx, "get_asset_context", kw, {"host": host, "found": False})
    return _emit(ctx, "get_asset_context", kw, {"host": host, "found": True, **ret})


def tool_lookup_ip_reputation(ctx: ToolContext, **kw: Any) -> str:
    ip = kw.get("ip", "")
    return _emit(ctx, "lookup_ip_reputation", kw, ctx.intel.lookup(ip) or {"ip": ip, "no_data": True})


def tool_get_mitre_technique(ctx: ToolContext, **kw: Any) -> str:
    tid = kw.get("technique_id", "").upper()
    ret = context.get_mitre_technique(tid) or {"technique_id": tid, "found": False}
    if "found" not in ret:
        ret = {"technique_id": tid, "found": True, **ret}
    return _emit(ctx, "get_mitre_technique", kw, ret)


def tool_submit_verdict(ctx: ToolContext, **kw: Any) -> str:
    v = Verdict(case_id=ctx.case.id, **kw)
    v.confidence = max(0.0, min(1.0, float(v.confidence)))
    ctx.submitted_verdict = v
    return _emit(ctx, "submit_verdict", kw, {"accepted": True, "disposition": v.disposition.value,
                                             "confidence": v.confidence})


TOOL_FUNCS: Dict[str, Callable[..., str]] = {
    "query_logs": tool_query_logs,
    "get_user_context": tool_get_user_context,
    "get_asset_context": tool_get_asset_context,
    "lookup_ip_reputation": tool_lookup_ip_reputation,
    "get_mitre_technique": tool_get_mitre_technique,
    "submit_verdict": tool_submit_verdict,
}


def tool_schemas() -> List[Dict[str, Any]]:
    return [
        {
            "name": "query_logs",
            "description": "Query the unified log store for events. Filters combine with AND. "
                           "A window around the case is the default; be specific to find proof.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "auth | endpoint | network | email | vuln"},
                    "users": {"type": "array", "items": {"type": "string"}},
                    "hosts": {"type": "array", "items": {"type": "string"}},
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "event_types": {"type": "array", "items": {"type": "string"}},
                    "window_minutes": {"type": "integer", "description": "Look back window from the incident."},
                    "limit": {"type": "integer"},
                },
            },
        },
        {
            "name": "get_user_context",
            "description": "Get directory/profile context for a user (role, admin status, "
                           "service account, known locations, recent activity).",
            "input_schema": {
                "type": "object",
                "properties": {"user": {"type": "string"}},
                "required": ["user"],
            },
        },
        {
            "name": "get_asset_context",
            "description": "Get asset inventory context for a host (owner, role, criticality, OS).",
            "input_schema": {
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
        },
        {
            "name": "lookup_ip_reputation",
            "description": "Threat-intel reputation for an IP address (score 0-100, categorization, "
                           "malicious flag). Corruption of sources should be treated seriously.",
            "input_schema": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
        {
            "name": "get_mitre_technique",
            "description": "Resolve a MITRE ATT&CK technique ID to name, tactic and description.",
            "input_schema": {
                "type": "object",
                "properties": {"technique_id": {"type": "string"}},
                "required": ["technique_id"],
            },
        },
        VERDICT_TOOL_SCHEMA,
    ]


MAX_LOOKUP_IPS = 12


def case_ips(case: Case) -> List[str]:
    seen, out = set(), []
    for ip in case.entities.ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out[:MAX_LOOKUP_IPS]


def build_evidence_from_case(ctx: ToolContext, verdict: Verdict) -> List[EvidenceRef]:
    evidence: List[EvidenceRef] = []
    seen_ids = set()
    for ev in ctx.case_events():
        label = f"{ev.timestamp.isoformat()} {ev.source}/{ev.event_type}"
        detail = f"{ev.actor_user or ev.actor_ip or ev.actor_host or '-'} -> {ev.target_host or ev.target_ip or ev.target_user or '-'}"
        if ev.id not in seen_ids:
            seen_ids.add(ev.id)
            evidence.append(EvidenceRef(id=ev.id, label=label, kind="event",
                                        detail=detail, timestamp=ev.timestamp))
    for ip in case_ips(ctx.case):
        rep = ctx.intel.lookup(ip)
        if rep and rep.get("score", 0) > 0:
            evidence.append(EvidenceRef(
                id=f"intel:{ip}", label=f"Threat intel for {ip}", kind="intel",
                detail=f"score={rep.get('score')} cat={rep.get('categorization')} feed={rep.get('_feed')}"))
    return evidence


def build_timeline_from_case(ctx: ToolContext) -> List[Dict[str, Any]]:
    known = {e.id for e in ctx.case_events()}
    extra = sorted(
        (e for a in ctx.case_alerts() for e in ctx.events.values()
         if e.id in a.event_ids and e.id not in known),
        key=lambda e: e.timestamp,
    )
    events = sorted(ctx.case_events() + extra, key=lambda e: e.timestamp)
    return [{"time": e.timestamp.isoformat(), "source": e.source, "event_type": e.event_type,
             "actor": e.actor_user or e.actor_ip or e.actor_host or "",
             "target": e.target_host or e.target_ip or e.target_user or "",
             "detail": e.detail} for e in events[:60]]