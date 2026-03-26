"""Orchestrates the full ingestion-to-timeline pipeline."""

from typing import List, Optional

from sqlalchemy.orm import Session
from backend.db.models import RawLog, Event, Incident, TimelineEvent
from backend.services.ingestion import ingest_file
from backend.services.parser import parse_and_store
from backend.services.feature_extractor import extract_features
from backend.services.rule_engine import run_rules
from backend.services.ml_model import run_anomaly_detection
from backend.services.correlator import correlate_events
from backend.services.timeline_builder import build_timelines


def ingest_only(content: bytes, filename: str, db: Session, session_id: Optional[str] = None) -> int:
    """Ingest and parse a file without running analysis. Returns event count."""
    raw_log = ingest_file(content, filename, db, session_id)
    events = parse_and_store(raw_log, db)
    return len(events)


def analyze_all(db: Session, session_id: Optional[str] = None) -> List[Incident]:
    """Run the full detection pipeline across events in the DB.

    If session_id is provided, only processes that session's data.
    Clears previous incidents/timelines for the scope, then re-analyzes
    from scratch so that cross-batch correlation works correctly.
    """
    if session_id:
        te_ids = (
            db.query(TimelineEvent.id)
            .join(Incident, TimelineEvent.incident_id == Incident.id)
            .filter(Incident.session_id == session_id)
            .subquery()
        )
        db.query(TimelineEvent).filter(TimelineEvent.id.in_(te_ids)).delete(synchronize_session="fetch")
        db.query(Incident).filter(Incident.session_id == session_id).delete()
        db.execute(
            Event.__table__.update()
            .where(Event.session_id == session_id)
            .values(rule_matched=None, mitre_technique=None, is_anomaly=False, features=None)
        )
        db.commit()

        events: List[Event] = (
            db.query(Event)
            .filter(Event.session_id == session_id)
            .order_by(Event.timestamp)
            .all()
        )
    else:
        db.query(TimelineEvent).delete()
        db.query(Incident).delete()
        db.execute(
            Event.__table__.update().values(
                rule_matched=None, mitre_technique=None, is_anomaly=False, features=None
            )
        )
        db.commit()
        events = db.query(Event).order_by(Event.timestamp).all()

    if not events:
        return []

    extract_features(events, db)
    rule_flagged = run_rules(events, db)
    anomalies = run_anomaly_detection(events, db)
    incidents = correlate_events(rule_flagged + anomalies, events, db, session_id)
    build_timelines(incidents, db)

    return incidents


def run_pipeline(content: bytes, filename: str, db: Session, session_id: Optional[str] = None) -> List[Incident]:
    """Single-file pipeline: ingest + analyze in one shot."""
    raw_log = ingest_file(content, filename, db, session_id)
    events = parse_and_store(raw_log, db)

    if not events:
        return []

    extract_features(events, db)
    rule_flagged = run_rules(events, db)
    anomalies = run_anomaly_detection(events, db)
    incidents = correlate_events(rule_flagged + anomalies, events, db, session_id)
    build_timelines(incidents, db)

    return incidents
