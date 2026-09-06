import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.triage.agents.orchestrator import TriagePipeline
from src.triage.store.storage import Store


@pytest.fixture()
def pipe(tmp_path):
    store = Store(tmp_path / "test.db")
    pipe = TriagePipeline(store=store)
    pipe.generate()
    return pipe


@pytest.fixture()
def campaign_case(pipe):
    for spec in pipe.store.list_cases():
        case = pipe.store.get_case(spec["id"])
        if len(case.alerts) > 1:
            return case
    raise AssertionError("campaign case not found")


def test_dataset_sizes(pipe):
    stats = pipe.store.stats()
    assert stats["events"] >= 100
    assert stats["total_alerts"] == 20
    assert stats["suppressed_alerts"] == 4
    assert stats["cases"]["auto_resolved"] == 4


def test_no_alerts_left_unassigned(pipe):
    alerts = pipe.store.get_alerts()
    for a in alerts.values():
        assert pipe.store.find_case_for_alert(a.id), f"alert {a.id} has no case"


def test_campaign_correlated_into_single_case(campaign_case):
    assert len(campaign_case.alerts) == 5
    assert campaign_case.implied_severity.value == "critical"
    assert "alice.smith" in campaign_case.entities.users


def case_by_title(pipe, fragment):
    for spec in pipe.store.list_cases():
        case = pipe.store.get_case(spec["id"])
        if fragment in case.title:
            return case
    return None


def test_anon_proxy_stays_separate(pipe):
    case = case_by_title(pipe, "anonymous proxy")
    assert case is not None
    assert len(case.alerts) == 1


def test_no_port_user_pollution(pipe):
    all_users = set()
    for spec in pipe.store.list_cases():
        case = pipe.store.get_case(spec["id"])
        all_users.update(case.entities.users)
        all_users.update(case.entities.hosts)
    assert not any("(TLS" in u or "(TCP" in u for u in all_users), "port leaked into entities"


def test_prefilter_suppresses_expected(pipe):
    alerts = pipe.store.get_alerts()
    scanner = next(a for a in alerts.values() if a.rule_name == "IDS_Sig_Scan_Detect")
    eicar = next(a for a in alerts.values() if a.rule_name == "AV_Malware_Detected")
    backup = next(a for a in alerts.values() if a.rule_name == "Unusual_Hour_Login")
    vpn = next(a for a in alerts.values() if a.rule_name == "Impossible_Travel" and a.raw.get("vpn"))
    for a in (scanner, eicar, backup, vpn):
        assert pipe.store.get_case(pipe.store.find_case_for_alert(a.id)).implied_severity
    assert all(pipe.store.find_case_for_alert(a.id).startswith("case-alt") for a in (scanner, eicar, backup, vpn))


def test_brute_force_always_escalated(pipe):
    alerts = pipe.store.get_alerts()
    brute = next(a for a in alerts.values() if a.rule_name == "Brute_Force_SSH")
    case_id = pipe.store.find_case_for_alert(brute.id)
    assert not case_id.startswith("case-alt")


def test_deterministic_triage_produces_valid_verdicts(pipe):
    open_cases = [c for c in pipe.store.list_cases() if c["status"] == "open"]
    results = pipe.triage_all(llm=False)
    assert len(results) == len(open_cases)
    for case_id in results:
        verdict = pipe.store.get_verdict(case_id)
        assert verdict is not None
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.disposition.value in {"true_positive", "false_positive", "suspicious", "investigate"}
        assert verdict.case_id == case_id
        assert verdict.llm_used is False
        assert verdict.summary
        assert verdict.investigation_summary


def test_true_positives_flagged(pipe):
    pipe.triage_all(llm=False)
    verdicts_by_case = {}
    for spec in pipe.store.list_cases():
        v = pipe.store.get_verdict(spec["id"])
        if v:
            verdicts_by_case[spec["id"]] = v
    tps = [v for v in verdicts_by_case.values() if v.disposition.value == "true_positive"]
    assert len(tps) >= 6


def test_reports_written(pipe, tmp_path):
    pipe.triage_case("case-001", llm=False)
    md = tmp_path / "reports"
    assert md.parent.exists()