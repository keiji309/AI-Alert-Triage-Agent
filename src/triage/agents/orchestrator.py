from __future__ import annotations

from typing import Dict, List, Optional

from .. import settings
from ..correlate.engine import build_cases
from ..ingest.normalizers import normalize_batch
from ..ingest.synthesizer import generate_demo
from ..intel.reputation import ThreatIntel
from ..models import (
    Alert, Case, CaseStatus, EntitySet, Event, PrefilterAction, Verdict,
)
from ..report.builder import ReportBuilder
from ..store.storage import Store
from .deterministic import run_deterministic_investigation
from .investigator import run_claude_investigation
from .prefilter import Prefilter
from .tools import ToolContext


class TriagePipeline:
    """End-to-end: generate synthetic telemetry, correlate, pre-filter, then
    investigate each case with the LLM (or the deterministic fail-safe)."""

    def __init__(self, store: Optional[Store] = None, intel: Optional[ThreatIntel] = None):
        self.store = store or Store()
        self.intel = intel or ThreatIntel()
        self.report = ReportBuilder(self.store)

    # ---- data generation + correlation ----------------------------------
    def generate(self, seed: Optional[int] = None) -> Dict[str, int]:
        scenarios = generate_demo(seed)
        raw_events = [e for s in scenarios for e in s.events]
        raw_alerts = [a for s in scenarios for a in s.alerts]
        events, alerts = normalize_batch(raw_events, raw_alerts)

        self.store.reset()
        self.store.insert_events(events)
        self.store.insert_alerts(alerts)

        # tier 0: deterministic pre-filter
        prefilter = Prefilter()
        decisions = prefilter.decide_many(alerts)
        for decision in decisions.values():
            self.store.apply_prefilter(decision)

        active = [a for a in alerts if decisions[a.id].action != PrefilterAction.SUPPRESS]
        suppressed_ids = {a.id for a in alerts
                          if decisions[a.id].action == PrefilterAction.SUPPRESS}
        suppressed_event_ids: set = set()
        for a in alerts:
            if a.id in suppressed_ids:
                suppressed_event_ids.update(a.event_ids)
        cases = build_cases(active, events, exclude_event_ids=suppressed_event_ids)
        self.store.replace_cases(cases)

        # build auto-resolved cases for suppressed alerts (0 LLM tokens)
        by_id = {a.id: a for a in alerts}
        for decision in decisions.values():
            if decision.action != PrefilterAction.SUPPRESS:
                continue
            alert = by_id[decision.alert_id]
            case = self._suppressed_case(alert, events)
            self.store.upsert_case(case)
            ctx = ToolContext(case, by_id, self.store.get_events(), self.intel)
            verdict = run_deterministic_investigation(ctx, suppress_hint=decision.disposition_hint)
            self.store.auto_resolve(case, verdict)
            self.report.write(case, verdict, ctx)

        self.store.log_run("generate", {"events": len(events), "alerts": len(alerts),
                                        "cases": len(cases), "suppressed": sum(
            1 for d in decisions.values() if d.action == PrefilterAction.SUPPRESS)})
        return self.store.stats()

    def _suppressed_case(self, alert: Alert, events: List[Event]) -> Case:
        event_ids = [e.id for e in events if e.id in alert.event_ids]
        entities = EntitySet()
        for e in events:
            if e.id not in set(alert.event_ids):
                continue
            for u in (e.actor_user, e.target_user):
                if u and u not in entities.users:
                    entities.users.append(u)
            for ip in (e.actor_ip, e.target_ip):
                if ip and ip not in entities.ips:
                    entities.ips.append(ip)
            for h in (e.actor_host, e.target_host):
                if h and h not in entities.hosts:
                    entities.hosts.append(h)
        for ent, val in ((entities.users, alert.entity_user), (entities.ips, alert.entity_ip),
                         (entities.hosts, alert.entity_host)):
            if val and val not in ent:
                ent.append(val)
        return Case(
            id=f"case-{alert.id}",
            title=f"Auto-resolved: {alert.title}",
            alerts=[alert.id],
            event_ids=event_ids,
            entities=entities,
            window_start=alert.timestamp,
            window_end=alert.timestamp,
            implied_severity=alert.severity,
            signals=[f"suppressed:{alert.rule_name}"],
            techniques=alert.mitre,
        )

    # ---- investigation -----------------------------------------------------
    def triage_case(self, case_id: str, llm: bool = True) -> Verdict:
        case = self.store.get_case(case_id)
        if case is None:
            raise KeyError(f"unknown case {case_id}")

        alerts = self.store.get_alerts()
        events = self.store.get_events()
        ctx = ToolContext(case, alerts, events, self.intel)

        use_llm = llm and bool(settings.ANTHROPIC_API_KEY)
        try:
            if use_llm:
                verdict = run_claude_investigation(ctx)
            else:
                verdict = run_deterministic_investigation(ctx)
        except Exception as exc:
            verdict = run_deterministic_investigation(ctx)
            verdict.notes = (verdict.notes + f" | LLM failed, fail-safe engine used: {exc}").strip()
            verdict.model = "deterministic-fail-safe"
            verdict.llm_used = False

        self.store.save_verdict(case_id, verdict)
        self.report.write(case, verdict, ctx)
        return verdict

    def triage_all(self, llm: bool = True) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for case_spec in self.store.list_cases():
            if case_spec["status"] in ("auto_resolved", "resolved"):
                continue
            case_id = case_spec["id"]
            try:
                v = self.triage_case(case_id, llm=llm)
                results[case_id] = f"{v.disposition.value} ({v.confidence:.0%}, {v.model})"
            except Exception as exc:
                results[case_id] = f"ERROR: {exc}"
        return results

    def open_cases(self) -> List[Dict]:
        return [c for c in self.store.list_cases()
                if c["status"] not in ("resolved", "auto_resolved")]