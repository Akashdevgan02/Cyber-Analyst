from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db.models import Incident, TimelineEvent, Event, ChatMessage
from backend.services.llm_adapter import get_llm_adapter

router = APIRouter()


class ChatRequest(BaseModel):
    question: str
    session_id: Optional[str] = None


@router.post("/chat")
def chat(req: ChatRequest, db: Session = Depends(get_db)):
    query = db.query(Incident)
    if req.session_id:
        query = query.filter(Incident.session_id == req.session_id)
    incidents = query.order_by(Incident.created_at.asc()).all()

    if not incidents:
        return {"response": "No incidents found. Upload some logs first."}

    context_parts = []
    for num, inc in enumerate(incidents, 1):
        timeline = (
            db.query(TimelineEvent, Event)
            .join(Event, TimelineEvent.event_id == Event.id)
            .filter(TimelineEvent.incident_id == inc.id)
            .order_by(TimelineEvent.position)
            .limit(5)
            .all()
        )
        events_summary = [
            f"  [{te.mitre_stage}] {evt.event_type} on {evt.host} by {evt.user} at {evt.timestamp}"
            for te, evt in timeline
        ]
        context_parts.append(
            f"Incident #{num} (severity={inc.severity}, host={inc.host}, user={inc.user}):\n"
            + "\n".join(events_summary)
        )

    context = "\n\n".join(context_parts)

    adapter = get_llm_adapter()
    try:
        response = adapter.chat(req.question, context)
    except Exception as e:
        response = f"Error communicating with LLM: {str(e)}\n\nHere is the raw context:\n{context[:1000]}"

    if req.session_id:
        db.add(ChatMessage(session_id=req.session_id, role="user", content=req.question))
        db.add(ChatMessage(session_id=req.session_id, role="assistant", content=response))
        db.commit()

    return {"response": response}


@router.get("/sessions/{session_id}/chat-history")
def get_chat_history(session_id: str, db: Session = Depends(get_db)):
    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    return [{"role": m.role, "content": m.content} for m in messages]
