from __future__ import annotations

from typing import Dict, List, Optional

from .. import settings
from ..models import (
    Alert, Disposition, RecommendedAction, Severity, Verdict,
)
from .tools import ToolContext, case_ips, tool_lookup_ip_reputation

# technique -> recommended actions (deterministic library for the fail-safe tier)
_ACTION_BY_TECHNIQUE: Dict[str, List[RecommendedAction]] = {
    "T1110": [RecommendedAction(action="Enable account lockout after 5 failures",
                                 description="Reduce brute-force dwell time on all services.",
                                 requires_approval=True)],
    "T1078": [RecommendedAction(action="Reset account credentials and require MFA re-enrollment",
                                 description="Assume the account may be compromised.",
                                 requires_approval=True)],
    "T1566.002": [RecommendedAction(action="Quarantine the phishing email and notify the recipient",
                                    description="Block sender and domain at the email gateway.",
                                    requires_approval=False),
                  RecommendedAction(action="Scan the recipient's endpoint for delivered payloads",
                                    description="Check for follow-up malware.",
                                    requires_approval=True)],
    "T1621": [RecommendedAction(action="Force MFA re-enrollment and review sign-in risk",
                                 description="Reset sessions on the affected account.",
                                 requires_approval=True)],
    "T1090.003": [RecommendedAction(action="Block the anonymizer IP at the perimeter",
                                     description="Deny egress/ingress to the flagged proxy/Tor node.",
                                     requires_approval=True)],
    "T1053.005": [RecommendedAction(action="Remove the scheduled task and quarantine the binary",
                                     description="Confirm with the host owner before deleting.",
                                     requires_approval=True)],
    "T1059.001": [RecommendedAction(action="Review the PowerShell execution and block obfuscated invocations",
                                     description="Audit 4104 script-block logs for the encoded command.",
                                     requires_approval=False)],
    "T1048.003": [RecommendedAction(action="Block outbound HTTPS to the exfil destination",
                                     description="Add egress deny rule; assess what data left the org.",
                                     requires_approval=True)],
    "T1003.001": [RecommendedAction(action="Isolate the host and reset credentials of logged-in users",
                                     description="Assume LSASS contents may be compromised.",
                                     requires_approval=True)],
    "T1021.001": [RecommendedAction(action="Investigate lateral movement path and isolate affected hosts",
                                     description="Revoke admin-share access if not required.",
                                     requires_approval=True)],
    "T1562.001": [RecommendedAction(action="Treat host as compromised and alert incident response",
                                     description="Log clearing destroys evidence; begin IR.",
                                     requires_approval=True)],
    "T1496": [RecommendedAction(action="Terminate mining process and patch the hosting application",
                                       description="Find the initial-access vector that dropped xmrig.",
                                       requires_approval=True)],
    "T1505.003": [RecommendedAction(action="Take the web server offline and run IR",
                                   description="Active web shell with beacon; isolate now.",
                                   requires_approval=True)],
}


def _severity_rank(sev: Severity) -> int:
    return {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}[sev]


def run_deterministic_investigation(ctx: ToolContext, suppress_hint: Optional[str] = None) -> Verdict:
    """Rule-based fail-safe. Used when no API key is configured, when the LLM
    errors out, or when the pre-filter already resolved the alert."""
    case = ctx.case
    alerts = ctx.case_alerts()
    techniques = set(case.techniques)
    sev_rank = _severity_rank(case.implied_severity)

    # gather intel for case IPs through the tool layer (for the trace)
    intel_results: Dict[str, dict] = {}
    for ip in case_ips(case):
        raw = ctx.intel.lookup(ip)
        tool_lookup_ip_reputation(ctx, ip=ip)
        intel_results[ip] = raw or {}
    any_malicious = any(e.get("malicious") for e in intel_results.values())
    high_signal = set(settings.ALWAYS_ESCALATE_TECHNIQUES) | set(settings.HIGH_SIGNAL_NOISE)
    advanced = ("likely-advanced-adversary" in case.signals
                or bool(techniques & {"T1562.001", "T1505.003", "T1003.001", "T1621"})
                or bool(techniques & high_signal))

    if suppress_hint == "false_positive":
        disposition, confidence = Disposition.FALSE_POSITIVE, 0.95
    elif any_malicious and (advanced or sev_rank >= _severity_rank(Severity.HIGH)):
        disposition, confidence = Disposition.TRUE_POSITIVE, 0.93
    elif any_malicious:
        disposition, confidence = Disposition.TRUE_POSITIVE, 0.85
    elif advanced:
        disposition, confidence = Disposition.TRUE_POSITIVE, 0.80
    elif bool(techniques & set(settings.ALWAYS_ESCALATE_TECHNIQUES)):
        disposition, confidence = Disposition.SUSPICIOUS, 0.72
    else:
        disposition, confidence = Disposition.INVESTIGATE, 0.55

    severity = case.implied_severity
    if any_malicious and sev_rank < _severity_rank(Severity.HIGH):
        severity = Severity.HIGH

    malicious_ips = [ip for ip, e in intel_results.items() if e.get("malicious")]
    intel_note = ("threat intel flagged " + ", ".join(malicious_ips)) if malicious_ips else "no malicious intel"
    ev_sources = sorted({e.source for e in ctx.case_events()})

    if disposition == Disposition.FALSE_POSITIVE:
        summary = (f"Deterministic pre-filter resolved this alert as benign: {suppress_hint or 'known noise'}."
                   " No LLM tokens were consumed.")
        actions: List[RecommendedAction] = []
        mitre = sorted(techniques)
    else:
        summary = (
            f"{len(alerts)} alert(s) across {len(ev_sources)} source(s) correlate into this incident "
            f"(window {case.window_start.strftime('%H:%M')}-{case.window_end.strftime('%H:%M')}). "
            f"Signals: {', '.join(case.signals) or 'none'}. {intel_note}. "
            f"Verdict produced by the deterministic fail-safe engine."
        )
        actions = []
        for tech in sorted(techniques):
            for act in _ACTION_BY_TECHNIQUE.get(tech, []):
                if act.action not in {a.action for a in actions}:
                    actions.append(act)
        if not actions and disposition in (Disposition.TRUE_POSITIVE, Disposition.SUSPICIOUS):
            actions.append(RecommendedAction(action="Escalate to Tier-2 with full case timeline",
                                             description="Insufficient deterministic action library coverage.",
                                             requires_approval=True))
        mitre = sorted(techniques)

    indicators: List[Dict[str, str]] = []
    for ip, e in intel_results.items():
        indicators.append({"type": "ipv4", "value": ip, "category": e.get("categorization", "unknown")})
    if disposition != Disposition.FALSE_POSITIVE:
        non_intel_ips = [ip for ip in case.entities.ips if ip not in malicious_ips and ip not in indicators]
        for ip in case.entities.ips:
            if ip not in {i["value"] for i in indicators}:
                indicators.append({"type": "ipv4", "value": ip, "category": "observable"})

    verdict = Verdict(
        case_id=case.id,
        disposition=disposition,
        severity=severity,
        confidence=confidence,
        summary=summary,
        investigation_summary=(
            f"Deterministic tier. {len(ctx.tool_trace)} tool calls performed: reputation lookups for "
            f"{', '.join(intel_results.keys()) or 'no external IPs'}; technique mapping for "
            f"{', '.join(sorted(techniques)) or 'none'}."
        ),
        mitre_relevance=mitre,
        indicators=indicators,
        recommended_actions=actions,
        model="deterministic-fail-safe",
        llm_used=False,
        notes="Generated offline; no LLM calls. Confidence reflects rule coverage, not deep analysis.",
    )
    from .investigator import finalize_verdict
    return finalize_verdict(ctx, verdict, model="deterministic-fail-safe", llm_used=False)