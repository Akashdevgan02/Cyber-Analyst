from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.database import get_db
from backend.db.models import AnalysisSession, ChatMessage, Event, Incident, RawLog, TimelineEvent

router = APIRouter()


class FinalizeRequest(BaseModel):
    name: Optional[str] = None


class RenameRequest(BaseModel):
    name: str


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db)):
    """Return finalized (saved) sessions with event and incident counts."""
    sessions = (
        db.query(AnalysisSession)
        .filter(AnalysisSession.is_active == False)  # noqa: E712
        .order_by(AnalysisSession.created_at.desc())
        .all()
    )

    result = []
    for s in sessions:
        event_count = db.query(func.count(Event.id)).filter(Event.session_id == s.id).scalar()
        incident_count = db.query(func.count(Incident.id)).filter(Incident.session_id == s.id).scalar()
        result.append({
            "id": s.id,
            "name": s.name,
            "is_active": s.is_active,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "event_count": event_count,
            "incident_count": incident_count,
        })

    return result


@router.patch("/sessions/{session_id}/finalize")
def finalize_session(
    session_id: str,
    req: FinalizeRequest,
    db: Session = Depends(get_db),
):
    """Save and finalize a session: set its name and mark it inactive."""
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if req.name and req.name.strip():
        session.name = req.name.strip()
    elif not session.name:
        ts = session.created_at.strftime("%Y-%m-%d %H:%M") if session.created_at else "unknown"
        session.name = f"Session {ts}"

    session.is_active = False
    db.commit()
    db.refresh(session)

    return {
        "id": session.id,
        "name": session.name,
        "is_active": session.is_active,
        "created_at": session.created_at.isoformat() if session.created_at else None,
    }


@router.patch("/sessions/{session_id}")
def rename_session(
    session_id: str,
    req: RenameRequest,
    db: Session = Depends(get_db),
):
    """Rename a session."""
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if not req.name or not req.name.strip():
        raise HTTPException(status_code=400, detail="Name cannot be empty")

    session.name = req.name.strip()
    db.commit()
    db.refresh(session)

    return {
        "id": session.id,
        "name": session.name,
        "is_active": session.is_active,
        "created_at": session.created_at.isoformat() if session.created_at else None,
    }


@router.delete("/sessions/{session_id}", status_code=204)
def delete_session(
    session_id: str,
    db: Session = Depends(get_db),
):
    """Delete a session and all associated data (cascade)."""
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete(synchronize_session=False)
    incident_ids = [i.id for i in db.query(Incident.id).filter(Incident.session_id == session_id).all()]
    if incident_ids:
        db.query(TimelineEvent).filter(TimelineEvent.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    db.query(Incident).filter(Incident.session_id == session_id).delete(synchronize_session=False)
    db.query(Event).filter(Event.session_id == session_id).delete(synchronize_session=False)
    db.query(RawLog).filter(RawLog.session_id == session_id).delete(synchronize_session=False)
    db.delete(session)
    db.commit()

    return Response(status_code=204)
