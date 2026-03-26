"""Extract ML-ready features from normalized events."""

import re
from typing import List, Dict
from collections import Counter, defaultdict

from sqlalchemy.orm import Session
from backend.db.models import Event

_PORT_RE = re.compile(r"(?:dst_port:|port:|Port\s*')['\"]?(\d+)")


def extract_features(events: List[Event], db: Session) -> List[Dict]:
    """Compute per-event features and store them on each event record.

    Features:
      - event_count_per_host: total events from the same host in this batch
      - failed_auth_ratio: fraction of auth failures from this host
      - avg_time_delta: average seconds between consecutive events on this host
      - unique_ports: number of distinct port references in events from this host
    """
    host_events = defaultdict(list)
    for e in events:
        host_events[e.host].append(e)

    host_event_count = {h: len(evts) for h, evts in host_events.items()}

    host_failed_auth: Dict[str, float] = {}
    for h, evts in host_events.items():
        auth_events = [e for e in evts if "login" in e.event_type.lower() or "auth" in e.event_type.lower()]
        if auth_events:
            failed = sum(1 for e in auth_events if "fail" in e.event_type.lower() or "fail" in (e.raw_message or "").lower())
            host_failed_auth[h] = failed / len(auth_events)
        else:
            host_failed_auth[h] = 0.0

    host_avg_delta: Dict[str, float] = {}
    for h, evts in host_events.items():
        sorted_evts = sorted(evts, key=lambda e: e.timestamp)
        if len(sorted_evts) > 1:
            deltas = [(sorted_evts[i + 1].timestamp - sorted_evts[i].timestamp).total_seconds()
                      for i in range(len(sorted_evts) - 1)]
            host_avg_delta[h] = sum(deltas) / len(deltas)
        else:
            host_avg_delta[h] = 0.0

    host_unique_ports: Dict[str, int] = {}
    for h, evts in host_events.items():
        ports = set()
        for e in evts:
            msg = e.raw_message or ""
            for match in _PORT_RE.findall(msg):
                ports.add(match)
            if "port" in (e.event_type or "").lower():
                ports.add(e.event_type)
        host_unique_ports[h] = len(ports) if ports else 1

    feature_list = []
    for e in events:
        features = {
            "event_count_per_host": host_event_count.get(e.host, 1),
            "failed_auth_ratio": round(host_failed_auth.get(e.host, 0.0), 4),
            "avg_time_delta": round(host_avg_delta.get(e.host, 0.0), 2),
            "unique_ports": host_unique_ports.get(e.host, 1),
        }
        e.features = features
        feature_list.append(features)

    db.commit()
    return feature_list
