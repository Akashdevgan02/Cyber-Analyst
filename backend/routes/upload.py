from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, Depends
from sqlalchemy.orm import Session as DBSession

from backend.db.database import get_db
from backend.db.models import AnalysisSession
from backend.services.pipeline import run_pipeline, ingest_only

router = APIRouter()


def _ensure_session(db: DBSession, session_id: Optional[str]) -> str:
    """Return an existing session_id or create a new session."""
    if session_id:
        existing = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
        if existing:
            return existing.id
    new_session = AnalysisSession()
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session.id


@router.post("/upload-logs")
async def upload_logs(
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
    db: DBSession = Depends(get_db),
):
    """Ingest + full analysis in one call. Creates a session if not provided."""
    sid = _ensure_session(db, session_id)
    content = await file.read()
    incidents = run_pipeline(content, file.filename or "upload.json", db, sid)

    return {
        "status": "success",
        "session_id": sid,
        "filename": file.filename,
        "incidents_detected": len(incidents),
        "incident_ids": [i.id for i in incidents],
    }


@router.post("/ingest")
async def ingest(
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
    db: DBSession = Depends(get_db),
):
    """Ingest and parse a file without running analysis.

    Use for multi-file workflows: upload all files first, then
    call POST /analyze-all to run detection across the full dataset.
    """
    sid = _ensure_session(db, session_id)
    content = await file.read()
    event_count = ingest_only(content, file.filename or "upload", db, sid)

    return {
        "status": "ingested",
        "session_id": sid,
        "filename": file.filename,
        "events_parsed": event_count,
    }
