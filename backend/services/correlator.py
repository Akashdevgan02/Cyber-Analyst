"""Correlation engine — group flagged events into incidents by time window, host, and user."""

from typing import List, Dict, Optional
from collections import defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session
from backend.db.models import Event, Incident
from backend.config import CORRELATION_WINDOW_MINUTES


def correlate_events(
    events: List[Event],
    all_events: List[Event],
    db: Session,
    session_id: Optional[str] = None,
) -> List[Incident]:
    """Group flagged events (rule-matched or anomalous) into incidents."""
    flagged = [e for e in all_events if e.rule_matched or e.is_anomaly]
    if not flagged:
        return []

    host_groups: Dict[str, List[Event]] = defaultdict(list)
    for e in flagged:
        host_groups[e.host].append(e)

    incidents = []
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    for host, host_events in host_groups.items():
        host_events.sort(key=lambda e: e.timestamp)

        current_group: List[Event] = [host_events[0]]
        for e in host_events[1:]:
            if e.timestamp - current_group[-1].timestamp <= window:
                current_group.append(e)
            else:
                incidents.append(_create_incident(current_group, host, db, session_id))
                current_group = [e]

        if current_group:
            incidents.append(_create_incident(current_group, host, db, session_id))

    db.commit()
    for inc in incidents:
        db.refresh(inc)
    return incidents


def _create_incident(
    events: List[Event],
    host: str,
    db: Session,
    session_id: Optional[str] = None,
) -> Incident:
    max_severity = max(events, key=lambda e: _sev(e.severity))
    users = {e.user for e in events if e.user}

    incident = Incident(
        session_id=session_id,
        severity=max_severity.severity,
        host=host,
        user=", ".join(users) if users else None,
        event_count=len(events),
    )
    db.add(incident)
    db.flush()

    incident._correlated_events = events
    return incident


def _sev(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0)
