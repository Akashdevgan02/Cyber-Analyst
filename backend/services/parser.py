"""Parse and normalize raw log entries into the common event schema.

Supports two formats:
  1. Generic logs (JSON/CSV with fields like host, user, event_type, etc.)
  2. Wazuh CSV exports (agent.name, rule.id, rule.description, etc.)
"""

import re
from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from backend.db.models import RawLog, Event

WAZUH_COLUMNS = {"agent.name", "rule.id", "rule.description", "rule.level"}

WAZUH_RULE_TYPE_MAP = {
    range(510, 515): "rootcheck_anomaly",
    range(550, 554): "integrity_check",
    range(5501, 5504): "login_event",
    range(5710, 5717): "ssh_auth_failure",
    range(5402, 5404): "sudo_event",
    range(5551, 5553): "multiple_auth_failure",
    range(2501, 2503): "syscheck_change",
    range(31100, 31200): "web_attack",
}

FIELD_ALIASES = {
    "ts": "timestamp",
    "time": "timestamp",
    "datetime": "timestamp",
    "src_ip": "host",
    "source_ip": "host",
    "hostname": "host",
    "src_host": "host",
    "username": "user",
    "account": "user",
    "src_user": "user",
    "type": "event_type",
    "action": "event_type",
    "event": "event_type",
    "level": "severity",
    "priority": "severity",
    "message": "raw_message",
    "msg": "raw_message",
    "description": "raw_message",
}


def _is_wazuh(entry: Dict[str, Any]) -> bool:
    return bool(WAZUH_COLUMNS & set(entry.keys()))


def _wazuh_severity(rule_level: Any) -> str:
    try:
        lvl = int(rule_level)
    except (TypeError, ValueError):
        return "low"
    if lvl >= 12:
        return "critical"
    if lvl >= 8:
        return "high"
    if lvl >= 4:
        return "medium"
    return "low"


def _wazuh_event_type(rule_id: Any) -> str:
    try:
        rid = int(rule_id)
    except (TypeError, ValueError):
        return "unknown"
    for id_range, etype in WAZUH_RULE_TYPE_MAP.items():
        if rid in id_range:
            return etype
    return f"wazuh_rule_{rid}"


def _parse_wazuh_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    title = str(entry.get("data.title", ""))
    desc = str(entry.get("rule.description", ""))
    raw_message = f"{title} | {desc}" if title else desc

    return {
        "timestamp": entry.get("timestamp"),
        "host": str(entry.get("agent.name", "unknown")),
        "user": _extract_user_from_wazuh(entry),
        "event_type": _wazuh_event_type(entry.get("rule.id")),
        "severity": _wazuh_severity(entry.get("rule.level")),
        "raw_message": raw_message,
        "wazuh_rule_id": entry.get("rule.id"),
    }


def _extract_user_from_wazuh(entry: Dict[str, Any]) -> Optional[str]:
    """Try to pull a username from Wazuh fields that sometimes contain one."""
    for field in ("data.srcuser", "data.dstuser", "data.user"):
        if field in entry and entry[field]:
            return str(entry[field])
    for field in ("data.title", "rule.description"):
        text = str(entry.get(field, ""))
        m = re.search(r"(?:user|User)\s+['\"]?(\w+)['\"]?", text)
        if m:
            return m.group(1)
    return None


def _resolve_field(entry: Dict[str, Any], canonical: str) -> Any:
    if canonical in entry:
        return entry[canonical]
    for alias, target in FIELD_ALIASES.items():
        if target == canonical and alias in entry:
            return entry[alias]
    return None


def _parse_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.utcnow()
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d, %Y @ %H:%M:%S.%f",
        "%b %d, %Y @ %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _parse_generic_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": _resolve_field(entry, "timestamp"),
        "host": str(_resolve_field(entry, "host") or "unknown"),
        "user": _resolve_field(entry, "user"),
        "event_type": str(_resolve_field(entry, "event_type") or "unknown"),
        "severity": str(_resolve_field(entry, "severity") or "low"),
        "raw_message": str(_resolve_field(entry, "raw_message") or ""),
        "wazuh_rule_id": None,
    }


def parse_and_store(raw_log: RawLog, db: Session) -> List[Event]:
    entries = raw_log.content if isinstance(raw_log.content, list) else [raw_log.content]
    events = []

    for entry in entries:
        if _is_wazuh(entry):
            parsed = _parse_wazuh_entry(entry)
        else:
            parsed = _parse_generic_entry(entry)

        wazuh_rule_id = None
        raw_rid = parsed.get("wazuh_rule_id")
        if raw_rid is not None:
            try:
                wazuh_rule_id = int(raw_rid)
            except (TypeError, ValueError):
                pass

        event = Event(
            log_id=raw_log.id,
            session_id=raw_log.session_id,
            timestamp=_parse_timestamp(parsed["timestamp"]),
            host=parsed["host"],
            user=parsed["user"],
            event_type=parsed["event_type"],
            severity=parsed["severity"],
            raw_message=parsed["raw_message"],
            wazuh_rule_id=wazuh_rule_id,
        )
        db.add(event)
        events.append(event)

    db.commit()
    for e in events:
        db.refresh(e)
    return events
