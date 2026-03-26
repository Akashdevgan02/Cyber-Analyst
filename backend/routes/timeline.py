from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db.models import Incident, TimelineEvent, Event

router = APIRouter()


@router.get("/timeline/{incident_id}")
def get_timeline(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = (
        db.query(TimelineEvent, Event)
        .join(Event, TimelineEvent.event_id == Event.id)
        .filter(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.position)
        .all()
    )

    return {
        "incident_id": incident_id,
        "severity": incident.severity,
        "host": incident.host,
        "events": [
            {
                "position": te.position,
                "mitre_stage": te.mitre_stage,
                "timestamp": evt.timestamp.isoformat(),
                "host": evt.host,
                "user": evt.user,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "raw_message": evt.raw_message,
                "rule_matched": evt.rule_matched,
                "mitre_technique": evt.mitre_technique,
                "is_anomaly": evt.is_anomaly,
            }
            for te, evt in timeline
        ],
    }
