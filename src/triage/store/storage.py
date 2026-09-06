from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from .. import settings
from ..models import Alert, Case, CaseStatus, Event, PrefilterDecision, Verdict


def _now() -> str:
    return datetime.utcnow().isoformat()


def _dump(obj: Any) -> str:
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump(mode="json"), default=str)
    return json.dumps(obj, default=str)


class Store:
    def __init__(self, db_path=None):
        self.path = str(db_path or settings.DB_PATH)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._schema()

    def _schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT,
                status TEXT,
                implied_severity TEXT,
                created_at TEXT,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                case_id TEXT,
                status TEXT,
                prefilter_action TEXT,
                prefilter_reason TEXT,
                prefilter_hint TEXT,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                data TEXT
            );
            CREATE TABLE IF NOT EXISTS verdicts (
                case_id TEXT PRIMARY KEY,
                data TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                created_at TEXT,
                meta TEXT
            );
            """
        )
        self.conn.commit()

    # ---- lifecycle -----------------------------------------------------
    def reset(self) -> None:
        for t in ("verdicts", "cases", "alerts", "events"):
            self.conn.execute(f"DELETE FROM {t}")
        self.conn.commit()

    def log_run(self, kind: str, meta: Dict[str, Any] = None) -> None:
        self.conn.execute(
            "INSERT INTO runs (kind, created_at, meta) VALUES (?,?,?)",
            (kind, _now(), json.dumps(meta or {})),
        )
        self.conn.commit()

    # ---- events / alerts ----------------------------------------------
    def insert_events(self, events: List[Event]) -> None:
        rows = [(e.id, _dump(e)) for e in events]
        self.conn.executemany(
            "INSERT OR REPLACE INTO events (id, data) VALUES (?,?)", rows)
        self.conn.commit()

    def insert_alerts(self, alerts: List[Alert]) -> None:
        rows = [(a.id, None, "ingested", None, None, None, _dump(a)) for a in alerts]
        self.conn.executemany(
            "INSERT OR REPLACE INTO alerts (id, case_id, status, prefilter_action, "
            "prefilter_reason, prefilter_hint, data) VALUES (?,?,?,?,?,?,?)", rows)
        self.conn.commit()

    def get_events(self, ids: Optional[List[str]] = None) -> Dict[str, Event]:
        if ids:
            q = [self.conn.execute("SELECT data FROM events WHERE id = ?", (i,)).fetchone() for i in ids]
            rows = [r for r in q if r]
        else:
            rows = self.conn.execute("SELECT data FROM events").fetchall()
        return {ev.id: ev for ev in (Event(**json.loads(r["data"])) for r in rows)}

    def get_alerts(self, ids: Optional[List[str]] = None) -> Dict[str, Alert]:
        if ids:
            q = [self.conn.execute("SELECT data FROM alerts WHERE id = ?", (i,)).fetchone() for i in ids]
            rows = [r for r in q if r]
        else:
            rows = self.conn.execute("SELECT data FROM alerts").fetchall()
        return {a.id: a for a in (Alert(**json.loads(r["data"])) for r in rows)}

    # ---- prefilter / case assignment -----------------------------------
    def apply_prefilter(self, decision: PrefilterDecision) -> None:
        self.conn.execute(
            "UPDATE alerts SET prefilter_action=?, prefilter_reason=?, prefilter_hint=?, status=? "
            "WHERE id=?",
            (decision.action.value, decision.reason, decision.disposition_hint,
             decision.action.value, decision.alert_id),
        )
        self.conn.commit()

    def replace_cases(self, cases: List[Case]) -> None:
        self.conn.execute("DELETE FROM cases")
        self.conn.execute("UPDATE alerts SET case_id=NULL, status='unassigned'")
        for case in cases:
            self.conn.execute(
                "INSERT OR REPLACE INTO cases (id, title, status, implied_severity, created_at, data) "
                "VALUES (?,?,?,?,?,?)",
                (case.id, case.title, CaseStatus.OPEN.value, case.implied_severity.value,
                 _now(), _dump(case)),
            )
            for aid in case.alerts:
                self.conn.execute(
                    "UPDATE alerts SET case_id=?, status='in_case' WHERE id=?", (case.id, aid))
        self.conn.commit()

    def upsert_case(self, case: Case) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO cases (id, title, status, implied_severity, created_at, data) "
            "VALUES (?,?,?,?,?,?)",
            (case.id, case.title, CaseStatus.OPEN.value, case.implied_severity.value,
             _now(), _dump(case)),
        )
        self.conn.commit()

    # ---- case reads ------------------------------------------------------
    def get_case(self, case_id: str) -> Optional[Case]:
        row = self.conn.execute("SELECT data FROM cases WHERE id=?", (case_id,)).fetchone()
        return Case(**json.loads(row["data"])) if row else None

    def find_case_for_alert(self, alert_id: str) -> Optional[str]:
        row = self.conn.execute("SELECT case_id FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return row["case_id"] if row and row["case_id"] else None

    def list_cases(self, include_auto: bool = True) -> List[Dict[str, Any]]:
        status_filter = "" if include_auto else "WHERE status != 'auto_resolved'"
        rows = self.conn.execute(
            f"SELECT id, title, status, implied_severity, created_at FROM cases {status_filter} "
            "ORDER BY ROWID DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- verdicts ---------------------------------------------------------
    def save_verdict(self, case_id: str, verdict: Verdict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO verdicts (case_id, data, created_at) VALUES (?,?,?)",
            (case_id, _dump(verdict), _now()),
        )
        self.conn.execute("UPDATE cases SET status=? WHERE id=?",
                          (CaseStatus.RESOLVED.value, case_id))
        self.conn.execute("UPDATE alerts SET status='triaged' WHERE case_id=? AND status!='suppress'",
                          (case_id,))
        self.conn.commit()

    def get_verdict(self, case_id: str) -> Optional[Verdict]:
        row = self.conn.execute("SELECT data FROM verdicts WHERE case_id=?", (case_id,)).fetchone()
        return Verdict(**json.loads(row["data"])) if row else None

    # ---- aggregations ------------------------------------------------------
    def stats(self) -> Dict[str, int]:
        row = self.conn.execute(
            "SELECT status, COUNT(*) n FROM cases GROUP BY status").fetchall()
        alerts = self.conn.execute(
            "SELECT COUNT(*) n, "
            "SUM(CASE WHEN status IN ('suppress','suppressed') THEN 1 ELSE 0 END) suppressed "
            "FROM alerts").fetchone()
        return {
            "cases": {r["status"]: r["n"] for r in row},
            "total_alerts": alerts["n"] or 0,
            "suppressed_alerts": alerts["suppressed"] or 0,
            "events": self.conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"] or 0,
        }

    def auto_resolve(self, case: Case, verdict: Verdict) -> None:
        self.save_verdict(case.id, verdict)
        self.conn.execute(
            "UPDATE alerts SET case_id=?, status='suppressed' WHERE id=?", (case.id, case.alerts[0]))
        self.conn.execute("UPDATE cases SET status='auto_resolved' WHERE id=?", (case.id,))
        self.conn.commit()