"""Ingest raw log files (JSON or CSV) and store in the database."""

import json
import csv
import io
from typing import Optional

from sqlalchemy.orm import Session
from backend.db.models import RawLog


def ingest_json(content: bytes, filename: str, db: Session, session_id: Optional[str] = None) -> RawLog:
    data = json.loads(content)
    if isinstance(data, dict):
        data = data.get("logs", data.get("events", [data]))
    raw_log = RawLog(filename=filename, content=data, session_id=session_id)
    db.add(raw_log)
    db.commit()
    db.refresh(raw_log)
    return raw_log


def ingest_csv(content: bytes, filename: str, db: Session, session_id: Optional[str] = None) -> RawLog:
    text = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    data = [row for row in reader]
    raw_log = RawLog(filename=filename, content=data, session_id=session_id)
    db.add(raw_log)
    db.commit()
    db.refresh(raw_log)
    return raw_log


def ingest_file(content: bytes, filename: str, db: Session, session_id: Optional[str] = None) -> RawLog:
    if filename.endswith(".csv"):
        return ingest_csv(content, filename, db, session_id)
    return ingest_json(content, filename, db, session_id)
