from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Dict, List, Any

from sqlalchemy.orm import Session
from app.models.model import LogEvent, Incident

FAILED_LOGIN = 4625
SUCCESS_LOGIN = 4624


def _within_time_window(
    events: List[Dict[str, Any]], window_minutes: int, threshold: int
) -> int:
    """
    Returns the maximum number of events that occurred within any sliding
    window of `window_minutes`. Expects events to have a 'timestamp' key
    with a datetime value.
    """
    if not events:
        return 0

    events = [e for e in events if isinstance(e.get("timestamp"), datetime)]
    if not events:
        return 0

    events.sort(key=lambda x: x["timestamp"])

    window = timedelta(minutes=window_minutes)
    max_in_window = 0
    start = 0

    for end in range(len(events)):
        while (
            events[end]["timestamp"] - events[start]["timestamp"] > window
            and start < end
        ):
            start += 1

        count = end - start + 1
        max_in_window = max(max_in_window, count)

        if max_in_window >= threshold:
            break

    return max_in_window


def detect_bruteforce(
    events: List[Dict[str, Any]],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> List[Dict[str, Any]]:
    """
    Detect brute-force login attempts based on Windows Security events.

    Rule:
      - If an IP generates at least `threshold` failed login events (4625)
        within any `window_minutes`‑minute window, raise a High severity incident.
    """
    incidents: List[Dict[str, Any]] = []
    failures_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for e in events:
        if e.get("event_id") == FAILED_LOGIN:
            ip = e.get("ip", "unknown")
            failures_by_ip[ip].append(e)

    for ip, fails in failures_by_ip.items():
        max_count = _within_time_window(fails, window_minutes, threshold)
        if max_count >= threshold:
            incidents.append(
                {
                    "type": "Brute Force Attack",
                    "severity": "High",
                    "ip": ip,
                    "count": max_count,
                    "rule": "FAILED_LOGIN_THRESHOLD",
                    "window_minutes": window_minutes,
                    "description": f"{max_count} failed login attempts detected from {ip} within {window_minutes} minutes",
                }
            )

    return incidents



def run_detection(db: Session):
    """
    Run rule‑based + simple ML‑style anomaly detection over all stored logs.

    Returns a list of incident dictionaries that were created during this run.
    """

    logs = db.query(LogEvent).all()

    ip_fail_count: Dict[str, int] = defaultdict(int)
    ip_ports: Dict[str, set] = defaultdict(set)
    ip_event_count: Dict[str, int] = defaultdict(int)

    created_incidents: List[Incident] = []

    for log in logs:
        ip = log.ip or "unknown"
        ip_event_count[ip] += 1

        # SSH brute force (rule‑based)
        if log.source == "ssh" and log.action and "Failed" in log.action:
            ip_fail_count[ip] += 1

        # Port scanning (rule‑based)
        if log.source == "firewall" and log.action == "BLOCK":
            if log.resource:
                ip_ports[ip].add(log.resource)

        # Directory traversal (rule‑based)
        if log.action and ("../" in log.action or "/etc/passwd" in log.action):
            incident = Incident(
                type="DIRECTORY_TRAVERSAL",
                severity="CRITICAL",
                source_ip=ip,
                description="Suspicious file path access",
            )
            db.add(incident)
            created_incidents.append(incident)

    # SSH brute‑force threshold (rule‑based)
    for ip, count in ip_fail_count.items():
        if count >= 5:
            incident = Incident(
                type="SSH_BRUTE_FORCE",
                severity="HIGH",
                source_ip=ip,
                description="Multiple failed SSH attempts",
            )
            db.add(incident)
            created_incidents.append(incident)

    # Port scan threshold (rule‑based)
    for ip, ports in ip_ports.items():
        if len(ports) >= 3:
            incident = Incident(
                type="PORT_SCAN",
                severity="HIGH",
                source_ip=ip,
                description="Multiple blocked ports detected",
            )
            db.add(incident)
            created_incidents.append(incident)

    # --- Simple ML‑style anomaly detection (no external deps) ---
    # Treat IPs with unusually high event volume as anomalies.
    if ip_event_count:
        counts = list(ip_event_count.values())
        if len(counts) >= 2:
            avg = mean(counts)
            std = pstdev(counts)
            # Avoid zero‑std edge cases
            if std > 0:
                threshold = avg + 2 * std
                for ip, count in ip_event_count.items():
                    if count > threshold:
                        incident = Incident(
                            type="ANOMALY_ML",
                            severity="MEDIUM",
                            source_ip=ip,
                            description=(
                                f"IP generated {count} events, which is above the "
                                f"anomaly threshold ({threshold:.1f}) based on peer activity"
                            ),
                        )
                        db.add(incident)
                        created_incidents.append(incident)

    db.commit()

    # Return a lightweight representation for APIs
    return [
        {
            "id": incident.id,
            "type": incident.type,
            "severity": incident.severity,
            "source_ip": incident.source_ip,
            "description": incident.description,
        }
        for incident in created_incidents
    ]