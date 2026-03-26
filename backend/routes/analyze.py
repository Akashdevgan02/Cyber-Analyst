from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db.models import Event
from backend.services.pipeline import analyze_all

router = APIRouter()


@router.post("/analyze-all")
def analyze_all_events(
    session_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Run the full detection pipeline across events in the DB.

    If session_id is provided, only that session's events are processed.
    Otherwise, all events are analyzed (legacy behaviour).
    """
    query = db.query(Event)
    if session_id:
        query = query.filter(Event.session_id == session_id)
    total_events = query.count()

    if total_events == 0:
        return {"status": "no_data", "incidents_detected": 0, "incident_ids": []}

    incidents = analyze_all(db, session_id)

    return {
        "status": "success",
        "session_id": session_id,
        "total_events_analyzed": total_events,
        "incidents_detected": len(incidents),
        "incident_ids": [i.id for i in incidents],
    }
