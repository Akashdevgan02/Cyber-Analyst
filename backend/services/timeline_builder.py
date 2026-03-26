"""Build ordered attack timelines with MITRE ATT&CK stage labels."""

from typing import List

from sqlalchemy.orm import Session
from backend.db.models import Event, Incident, TimelineEvent

MITRE_STAGE_MAP = {
    "T1110": "Initial Access",
    "T1548": "Privilege Escalation",
    "T1021": "Lateral Movement",
    "T1041": "Exfiltration",
    "T1014": "Defense Evasion",
    "T1190": "Initial Access",
}

EVENT_TYPE_STAGE_MAP = {
    "scan": "Reconnaissance",
    "recon": "Reconnaissance",
    "probe": "Reconnaissance",
    "login_success": "Initial Access",
    "auth_success": "Initial Access",
    "login_failure": "Initial Access",
    "auth_failure": "Initial Access",
    "ssh": "Lateral Movement",
    "rdp": "Lateral Movement",
    "remote": "Lateral Movement",
    "privilege": "Privilege Escalation",
    "sudo": "Privilege Escalation",
    "escalat": "Privilege Escalation",
    "exec": "Execution",
    "command": "Execution",
    "exfil": "Exfiltration",
    "transfer": "Exfiltration",
    "upload": "Exfiltration",
    "outbound": "Exfiltration",
    "persist": "Persistence",
    "cron": "Persistence",
    "scheduled": "Persistence",
    "rootcheck": "Defense Evasion",
    "hidden": "Defense Evasion",
    "integrity": "Defense Evasion",
    "web_attack": "Initial Access",
}

STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Lateral Movement",
    "Defense Evasion",
    "Collection",
    "Exfiltration",
    "Unknown",
]


def _infer_stage(event: Event) -> str:
    if event.mitre_technique and event.mitre_technique in MITRE_STAGE_MAP:
        return MITRE_STAGE_MAP[event.mitre_technique]

    etype = event.event_type.lower()
    for keyword, stage in EVENT_TYPE_STAGE_MAP.items():
        if keyword in etype:
            return stage

    msg = (event.raw_message or "").lower()
    for keyword, stage in EVENT_TYPE_STAGE_MAP.items():
        if keyword in msg:
            return stage

    return "Unknown"


def build_timelines(incidents: List[Incident], db: Session) -> None:
    """For each incident, create ordered TimelineEvent records."""
    for incident in incidents:
        events: List[Event] = getattr(incident, "_correlated_events", [])
        if not events:
            continue

        events.sort(key=lambda e: e.timestamp)

        for position, event in enumerate(events):
            stage = _infer_stage(event)
            te = TimelineEvent(
                incident_id=incident.id,
                event_id=event.id,
                mitre_stage=stage,
                position=position,
            )
            db.add(te)

    db.commit()
