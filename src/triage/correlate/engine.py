from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from .. import settings
from ..models import Alert, Case, EntitySet, Event, Severity, max_severity


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _entity_keys(ev: Event) -> List[str]:
    keys: List[str] = []
    for u in (ev.actor_user, ev.target_user):
        if u:
            keys.append(f"u:{u}")
    for ip in (ev.actor_ip, ev.target_ip):
        if ip:
            keys.append(f"ip:{ip}")
    for h in (ev.actor_host, ev.target_host):
        if h:
            keys.append(f"h:{h}")
    return keys


def cluster_events(
    events: List[Event],
    window_minutes: Optional[int] = None,
    exclude_event_ids: Optional[set] = None,
) -> List[List[Event]]:
    """Union events that share an entity and fall within the correlation window.

    Uses transitive closure so attacker pivots across users/hosts/ips chain into a
    single cluster. Baseline/noise events are left unclustered so they never
    swallow real clusters. Events listed in exclude_event_ids are skipped."""
    window = timedelta(minutes=window_minutes or settings.CORRELATION_WINDOW_MINUTES)
    exclude = exclude_event_ids or set()

    interesting = [ev for ev in events
                   if not ev.detail.get("baseline") and ev.id not in exclude]
    index: Dict[str, List[Tuple[int, object]]] = defaultdict(list)
    for i, ev in enumerate(interesting):
        for k in _entity_keys(ev):
            index[k].append((i, ev.timestamp))

    uf = UnionFind(len(interesting))
    for items in index.values():
        for j in range(1, len(items)):
            idx, ts = items[j]
            for m in range(j):
                other = items[m]
                if abs((ts - other[1]).total_seconds()) <= window.total_seconds():
                    uf.union(idx, other[0])

    groups: Dict[int, List[Event]] = defaultdict(list)
    for i, ev in enumerate(interesting):
        groups[uf.find(i)].append(ev)
    return [list(g) for g in groups.values()]


def _window_seconds(window_minutes: Optional[int]) -> float:
    return (window_minutes or settings.CORRELATION_WINDOW_MINUTES) * 60.0


def build_cases(
    alerts: List[Alert],
    events: List[Event],
    window_minutes: Optional[int] = None,
    exclude_event_ids: Optional[set] = None,
) -> List[Case]:
    """Stitch alerts onto event clusters; alerts referencing the same cluster
    become one correlated incident (a case)."""
    clusters = cluster_events(events, window_minutes, exclude_event_ids)

    cluster_of_event: Dict[str, int] = {}
    for ci, cluster in enumerate(clusters):
        for ev in cluster:
            cluster_of_event[ev.id] = ci

    entity_index: Dict[str, List[int]] = defaultdict(list)
    for ci, cluster in enumerate(clusters):
        for ev in cluster:
            for k in _entity_keys(ev):
                entity_index[k].append((ci, ev.timestamp))

    # 1. decide each alert's cluster (or None -> singleton)
    alert_cluster: Dict[str, Optional[int]] = {}
    for alert in alerts:
        chosen: Optional[int] = None
        for eid in alert.event_ids:
            ci = cluster_of_event.get(eid)
            if ci is not None:
                chosen = ci
                break
        if chosen is None:
            for ci, cluster in enumerate(clusters):
                cstart = min(ev.timestamp for ev in cluster)
                cend = max(ev.timestamp for ev in cluster)
                if not _overlaps(alert, cstart, cend, window_minutes):
                    continue
                ev = cluster[0]
                if (
                    (alert.entity_user and alert.entity_user in (ev.actor_user, ev.target_user))
                    or (alert.entity_host and alert.entity_host in (ev.actor_host, ev.target_host))
                    or (alert.entity_ip and alert.entity_ip in (ev.actor_ip, ev.target_ip))
                ):
                    chosen = ci
                    break
        alert_cluster[alert.id] = chosen

    # 2. group alerts by their cluster (union-find over cluster indices)
    alert_by_cluster: Dict[int, List[Alert]] = defaultdict(list)
    singletons: List[Alert] = []
    for alert in alerts:
        ci = alert_cluster[alert.id]
        if ci is None:
            singletons.append(alert)
        else:
            alert_by_cluster[ci].append(alert)

    cases: List[Case] = []
    for ci, group in alert_by_cluster.items():
        cases.append(_assemble_case(group, clusters[ci]))
    for alert in singletons:
        evs = [e for e in events if e.id in alert.event_ids]
        cases.append(_assemble_case([alert], evs))

    for n, c in enumerate(cases):
        c.id = f"case-{n + 1:03d}"
    cases.sort(key=lambda c: c.window_start)
    return cases


def _overlaps(alert: Alert, cstart, cend, window_minutes: Optional[int]) -> bool:
    w = timedelta(seconds=_window_seconds(window_minutes))
    return (cstart - w) <= alert.timestamp <= (cend + w)


def _assemble_case(alerts: List[Alert], cluster: List[Event]) -> Case:
    event_ids = sorted({ev.id for ev in cluster})
    ts = [ev.timestamp for ev in cluster] + [a.timestamp for a in alerts]
    start, end = min(ts), max(ts)

    entities = EntitySet()
    for ev in cluster:
        _collect_entities(entities, ev)
    for alert in alerts:
        for u in (alert.entity_user,):
            if u and u not in entities.users:
                entities.users.append(u)
        for ip in (alert.entity_ip,):
            if ip and ip not in entities.ips:
                entities.ips.append(ip)
        for h in (alert.entity_host,):
            if h and h not in entities.hosts:
                entities.hosts.append(h)

    techniques = sorted({t for a in alerts for t in a.mitre})
    priorities = set(settings.ALWAYS_ESCALATE_TECHNIQUES) | set(settings.HIGH_SIGNAL_NOISE)
    signals = [f"technique:{t}" for t in techniques if t in priorities]
    if "T1562.001" in techniques or "T1505.003" in techniques:
        signals.append("likely-advanced-adversary")

    if len(alerts) > 1:
        title = "Campaign: " + " -> ".join(a.rule_name for a in sorted(alerts, key=lambda a: a.timestamp))
    else:
        title = alerts[0].title

    return Case(
        id="",  # assigned by build_cases
        title=title,
        alerts=[a.id for a in sorted(alerts, key=lambda a: a.timestamp)],
        event_ids=event_ids,
        entities=entities,
        window_start=start,
        window_end=end,
        implied_severity=max_severity([a.severity for a in alerts]),
        signals=signals,
        techniques=techniques,
    )


def _collect_entities(entities: EntitySet, ev: Event) -> None:
    for u in (ev.actor_user, ev.target_user):
        if u and u not in entities.users:
            entities.users.append(u)
    for ip in (ev.actor_ip, ev.target_ip):
        if ip and ip not in entities.ips:
            entities.ips.append(ip)
    for h in (ev.actor_host, ev.target_host):
        if h and h not in entities.hosts:
            entities.hosts.append(h)