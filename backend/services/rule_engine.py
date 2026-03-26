"""Rule-based detection engine with MITRE ATT&CK-mapped rules.

Supports both generic keyword matching and Wazuh rule.id-based detection.
"""

from typing import List
from collections import defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session
from backend.db.models import Event
from backend.config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_MINUTES


def _detect_brute_force(events: List[Event]) -> List[Event]:
    """T1110 — 5+ failed logins from same host within 5 minutes."""
    host_failures = defaultdict(list)
    for e in events:
        etype = e.event_type.lower()
        msg = (e.raw_message or "").lower()
        rid = e.wazuh_rule_id or 0
        is_auth_fail = (
            ("fail" in etype and ("login" in etype or "auth" in etype))
            or etype in ("ssh_auth_failure", "multiple_auth_failure")
            or rid in range(5710, 5717)
            or rid in range(5551, 5553)
            or ("authentication fail" in msg)
        )
        if is_auth_fail:
            host_failures[e.host].append(e)

    flagged = []
    for host, fails in host_failures.items():
        fails.sort(key=lambda x: x.timestamp)
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        for i, event in enumerate(fails):
            count_in_window = sum(
                1 for f in fails[i:]
                if f.timestamp - event.timestamp <= window
            )
            if count_in_window >= BRUTE_FORCE_THRESHOLD:
                for f in fails[i:]:
                    if f.timestamp - event.timestamp <= window:
                        flagged.append(f)
                break
    return flagged


def _detect_privilege_escalation(events: List[Event]) -> List[Event]:
    """T1548 — sudo/su or privilege change event."""
    flagged = []
    for e in events:
        etype = e.event_type.lower()
        msg = (e.raw_message or "").lower()
        rid = e.wazuh_rule_id or 0
        is_privesc = (
            any(kw in etype or kw in msg for kw in ["privilege", "sudo", "su ", "escalat", "root"])
            or etype == "sudo_event"
            or rid in range(5402, 5404)
        )
        if is_privesc:
            flagged.append(e)
    return flagged


def _detect_lateral_movement(events: List[Event]) -> List[Event]:
    """T1021 — SSH/RDP to a different host."""
    flagged = []
    for e in events:
        etype = e.event_type.lower()
        msg = (e.raw_message or "").lower()
        is_lateral = any(kw in etype or kw in msg for kw in [
            "ssh", "rdp", "remote", "lateral", "psexec",
        ])
        if is_lateral:
            flagged.append(e)
    return flagged


def _detect_data_exfiltration(events: List[Event]) -> List[Event]:
    """T1041 — Unusual outbound data transfer."""
    flagged = []
    for e in events:
        etype = e.event_type.lower()
        msg = (e.raw_message or "").lower()
        is_exfil = any(kw in etype or kw in msg for kw in [
            "exfil", "upload", "outbound", "transfer", "large_transfer",
        ])
        if is_exfil:
            flagged.append(e)
    return flagged


def _detect_rootcheck_anomaly(events: List[Event]) -> List[Event]:
    """T1014 — Rootkit / hidden process or port (Wazuh rootcheck)."""
    flagged = []
    for e in events:
        rid = e.wazuh_rule_id or 0
        msg = (e.raw_message or "").lower()
        is_rootcheck = (
            rid in range(510, 515)
            or e.event_type == "rootcheck_anomaly"
            or ("hidden" in msg and ("port" in msg or "process" in msg))
        )
        if is_rootcheck:
            flagged.append(e)
    return flagged


def _detect_web_attack(events: List[Event]) -> List[Event]:
    """T1190 — Web application attack (Wazuh rule 31100-31199)."""
    flagged = []
    for e in events:
        rid = e.wazuh_rule_id or 0
        msg = (e.raw_message or "").lower()
        is_web = (
            rid in range(31100, 31200)
            or e.event_type == "web_attack"
            or any(kw in msg for kw in ["sql injection", "xss", "directory traversal"])
        )
        if is_web:
            flagged.append(e)
    return flagged


RULES = [
    {"name": "Brute Force", "mitre": "T1110", "severity": "high", "detect": _detect_brute_force},
    {"name": "Privilege Escalation", "mitre": "T1548", "severity": "critical", "detect": _detect_privilege_escalation},
    {"name": "Lateral Movement", "mitre": "T1021", "severity": "high", "detect": _detect_lateral_movement},
    {"name": "Data Exfiltration", "mitre": "T1041", "severity": "critical", "detect": _detect_data_exfiltration},
    {"name": "Rootkit / Hidden Object", "mitre": "T1014", "severity": "high", "detect": _detect_rootcheck_anomaly},
    {"name": "Web Application Attack", "mitre": "T1190", "severity": "high", "detect": _detect_web_attack},
]


def run_rules(events: List[Event], db: Session) -> List[Event]:
    """Run all detection rules. Tag matching events in-place and return the set of flagged events."""
    all_flagged = set()

    for rule in RULES:
        matches = rule["detect"](events)
        for event in matches:
            event.rule_matched = rule["name"]
            event.mitre_technique = rule["mitre"]
            if event.severity == "low" or _severity_rank(rule["severity"]) > _severity_rank(event.severity):
                event.severity = rule["severity"]
            all_flagged.add(event.id)

    db.commit()
    return [e for e in events if e.id in all_flagged]


def _severity_rank(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0)
