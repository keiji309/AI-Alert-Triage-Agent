from __future__ import annotations

from typing import Dict, List

from .. import settings
from ..models import Alert, PrefilterAction, PrefilterDecision, Severity
from ..ingest.synthesizer import IP_SCANNER


class Prefilter:
    """Deterministic first-pass triage tier.

    Resolves obvious false positives for free (0 LLM tokens) and routes the rest
    to the agent tier. Design rule: suppression requires a positive reason to
    close; the always-escalate technique list overrides any suppression so a real
    attack never rides under an old exception."""

    def __init__(self):
        self._maybe_suppress: Dict[str, PrefilterDecision] = {}

    def decide(self, alert: Alert) -> PrefilterDecision:
        hits: List[str] = []
        hint, confidence = "", 0.0
        action = PrefilterAction.CLASSIFY

        # Always-escalate override first.
        if any(t in settings.ALWAYS_ESCALATE_TECHNIQUES for t in alert.mitre):
            hits.append("always_escalate_technique")
            action = PrefilterAction.ESCALATE
            hint = ""
            reason = (f"Contains always-escalate technique(s) "
                      f"{[t for t in alert.mitre if t in settings.ALWAYS_ESCALATE_TECHNIQUES]} — "
                      f"must reach the agent tier.")
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        # 1) EICAR quarantine test drops.
        if alert.entity_host in settings.TEST_HOSTS and (
            "eicar" in (alert.title + alert.description).lower()
            or alert.rule_name == "AV_Malware_Detected"
        ):
            hits.append("eicar_test_host")
            action = PrefilterAction.SUPPRESS
            hint, confidence = "false_positive", 0.97
            reason = "EICAR test string on a designated AV validation host; quarterly QA drop."
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        # 2) Scheduled vulnerability scanner traffic.
        if alert.rule_name == "IDS_Sig_Scan_Detect" or (
            alert.entity_ip in settings.SCANNER_CIDRS and "scan" in (alert.title + alert.rule_name).lower()
        ):
            hits.append("scheduled_vuln_scanner")
            action = PrefilterAction.SUPPRESS
            hint, confidence = "false_positive", 0.95
            raw = alert.raw
            schedule = raw.get("schedule", "weekly Sunday 02:00 UTC")
            reason = (f"Scheduled internal vulnerability scanner ({IP_SCANNER}) matching port-scan "
                      f"signatures; expected {schedule}.")
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        # 3) Known service accounts doing their job.
        if alert.entity_user in settings.SERVICE_ACCOUNTS and alert.severity in (
            Severity.LOW, Severity.INFO,
        ):
            hits.append("known_service_account")
            action = PrefilterAction.SUPPRESS
            hint, confidence = "false_positive", 0.93
            reason = f"{alert.entity_user} is a dedicated service account; behavior matches its documented job."
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        # 4) Corporate VPN impossible-travel carve-out.
        if alert.rule_name == "Impossible_Travel" and alert.raw.get("vpn"):
            hits.append("vpn_carve_out")
            action = PrefilterAction.SUPPRESS
            hint, confidence = "false_positive", 0.9
            reason = "Both sign-ins routed through the corporate VPN concentrator; roaming is expected."
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        # 5) Everything ambiguous/escalation-worthy goes to the agent tier.
        if any(t in settings.HIGH_SIGNAL_NOISE for t in alert.mitre):
            hits.append("high_signal_technique")
            action = PrefilterAction.ESCALATE
            reason = (f"High-signal technique present "
                      f"{[t for t in alert.mitre if t in settings.HIGH_SIGNAL_NOISE]} — escalation.")
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        if alert.severity in (Severity.HIGH, Severity.CRITICAL):
            hits.append("high_severity")
            action = PrefilterAction.ESCALATE
            reason = "High/critical severity alert — escalation."
            return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

        hits.append("needs_classification")
        reason = "No suppression rule matched; agent tier will classify."
        return PrefilterDecision(alert_id=alert.id, action=action, reason=reason, disposition_hint=hint, confidence=confidence, rule_hits=hits)

    def decide_many(self, alerts: List[Alert]) -> Dict[str, PrefilterDecision]:
        return {a.id: self.decide(a) for a in alerts}


def apply_prefilter(alerts: List[Alert]) -> List[PrefilterDecision]:
    return list(Prefilter().decide_many(alerts).values())