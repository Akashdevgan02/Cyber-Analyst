from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db.models import Incident, TimelineEvent, Event
from backend.services.llm_adapter import get_llm_adapter

router = APIRouter()


@router.get("/incidents")
def list_incidents(
    session_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if session_id:
        query = query.filter(Incident.session_id == session_id)
    incidents = query.order_by(Incident.created_at.asc()).all()

    return [
        {
            "id": i.id,
            "number": idx,
            "severity": i.severity,
            "host": i.host,
            "user": i.user,
            "event_count": i.event_count,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "has_explanation": i.explanation is not None,
        }
        for idx, i in enumerate(incidents, 1)
    ]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
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

    timeline_data = [
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
    ]

    if incident.explanation is None:
        try:
            adapter = get_llm_adapter()
            result = adapter.explain_incident({
                "host": incident.host,
                "user": incident.user,
                "severity": incident.severity,
                "event_count": incident.event_count,
                "timeline": timeline_data,
            })
            incident.summary = result.get("summary", "")
            incident.explanation = result.get("summary", "")
            incident.suggested_actions = result.get("suggested_actions", [])
            if result.get("severity"):
                incident.severity = result["severity"]
            db.commit()
            db.refresh(incident)
        except Exception as e:
            incident.explanation = f"LLM explanation unavailable: {str(e)}"
            db.commit()

    return {
        "id": incident.id,
        "severity": incident.severity,
        "host": incident.host,
        "user": incident.user,
        "event_count": incident.event_count,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "summary": incident.summary,
        "explanation": incident.explanation,
        "suggested_actions": incident.suggested_actions,
        "timeline": timeline_data,
    }
