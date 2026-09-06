from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..models import Alert, Event

_NON_ATTACK_RISK = {
    "auth_success": 1.0,
    "auth_failure": 2.5,
    "auth_mfa_push": 4.0,
    "login_tor": 8.0,
    "process_start": 2.0,
    "process_suspicious": 7.0,
    "scheduled_task_create": 8.0,
    "lsass_access": 9.0,
    "log_clear": 10.0,
    "outbound_connection": 2.0,
    "blocked_connection": 3.0,
    "ids_alert": 4.0,
    "email_click": 6.0,
    "email_quarantine": 2.0,
    "file_write_temp": 3.0,
    "dns_query": 1.0,
}


def _bucket(dt: object, secs: int) -> str:  # pragma: no cover - trivial
    return str(int(dt.timestamp()) // secs)


def normalize_event(raw: Dict[str, Any]) -> Event:
    """Coerce a raw log record into the canonical Event schema and score risk."""
    ev = Event(**raw)
    if not ev.risk and ev.event_type in _NON_ATTACK_RISK:
        ev.risk = _NON_ATTACK_RISK[ev.event_type]
    return ev


def normalize_alert(raw: Dict[str, Any]) -> Alert:
    """Coerce a raw detection into the canonical Alert schema."""
    return Alert(**raw)


def normalize_batch(
    raw_events: List[Dict[str, Any]],
    raw_alerts: List[Dict[str, Any]],
) -> Tuple[List[Event], List[Alert]]:
    return [normalize_event(r) for r in raw_events], [normalize_alert(r) for r in raw_alerts]