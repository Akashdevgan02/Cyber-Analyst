import uuid

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from backend.db.database import Base


def _new_uuid() -> str:
    return str(uuid.uuid4())


class AnalysisSession(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=_new_uuid)
    name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    raw_logs = relationship("RawLog", back_populates="session")
    events = relationship("Event", back_populates="session")
    incidents = relationship("Incident", back_populates="session")
    chat_messages = relationship("ChatMessage", back_populates="session")


class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True)
    filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    content = Column(JSON, nullable=False)

    session = relationship("AnalysisSession", back_populates="raw_logs")
    events = relationship("Event", back_populates="raw_log")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True)
    log_id = Column(Integer, ForeignKey("raw_logs.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    host = Column(String, nullable=False)
    user = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="low")
    raw_message = Column(Text, nullable=True)

    features = Column(JSON, nullable=True)
    wazuh_rule_id = Column(Integer, nullable=True)
    rule_matched = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    is_anomaly = Column(Boolean, default=False)

    session = relationship("AnalysisSession", back_populates="events")
    raw_log = relationship("RawLog", back_populates="events")
    timeline_entries = relationship("TimelineEvent", back_populates="event")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True)
    severity = Column(String, nullable=False, default="medium")
    host = Column(String, nullable=True)
    user = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    event_count = Column(Integer, default=0)

    summary = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    suggested_actions = Column(JSON, nullable=True)

    session = relationship("AnalysisSession", back_populates="incidents")
    timeline_events = relationship("TimelineEvent", back_populates="incident", order_by="TimelineEvent.position")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    role = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    session = relationship("AnalysisSession", back_populates="chat_messages")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    mitre_stage = Column(String, nullable=False)
    position = Column(Integer, nullable=False)

    incident = relationship("Incident", back_populates="timeline_events")
    event = relationship("Event", back_populates="timeline_entries")
