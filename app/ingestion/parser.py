import re
import json
import csv
from typing import List
from app.models.event import LogEvent


def parse_logs(raw_text: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    lines = raw_text.splitlines()

    # ---------- WINDOWS SECURITY CSV EXPORT ----------
    # Detect typical Event Viewer CSV exports which have an "Event ID" column.
    if lines and "," in lines[0] and "Event ID" in lines[0]:
        reader = csv.DictReader(lines)
        for row in reader:
            if not any(row.values()):
                continue

            timestamp = (
                row.get("Date and Time")
                or row.get("Date")
                or row.get("TimeCreated")
                or "unknown"
            )
            event_id = row.get("Event ID") or row.get("EventID") or "unknown"
            level = row.get("Level") or row.get("Keywords") or "Info"
            task = row.get("Task Category") or row.get("Task") or ""
            user = row.get("Account Name") or row.get("User") or None
            description = row.get("Description") or ""

            # Try to pull a source IP from the description if present.
            ip = None
            m_ip = re.search(r"Source Network Address:\s*([\d\.]+)", description)
            if m_ip:
                ip = m_ip.group(1)

            level_lower = level.lower()
            if "fail" in level_lower:
                severity = "HIGH"
            elif "warn" in level_lower:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            events.append(
                LogEvent(
                    timestamp=timestamp,
                    source="security",
                    event_type=str(event_id),
                    severity=severity,
                    user=user,
                    ip=ip,
                    # Store level ("Information", "Failure Audit", etc.) as action,
                    # and Task Category ("Logon", "Account Management") as resource.
                    action=level,
                    resource=task or None,
                    raw=json.dumps(row),
                )
            )

        return events

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ---------- JSON LOGS ----------
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                events.append(LogEvent(
                    timestamp=data.get("timestamp", "unknown"),
                    source="application",
                    event_type=data.get("level", "info"),
                    severity=data.get("level", "INFO"),
                    user=data.get("user"),
                    ip=data.get("ip"),
                    action=data.get("message"),
                    raw=line
                ))
                continue
            except:
                pass

        # ---------- APACHE LOGS ----------
        apache_match = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3})', line)
        if apache_match:
            ip, timestamp, request, status = apache_match.groups()
            severity = "HIGH" if status.startswith("4") or status.startswith("5") else "LOW"
            events.append(LogEvent(
                timestamp=timestamp,
                source="apache",
                event_type="http_request",
                severity=severity,
                ip=ip,
                action=request,
                raw=line
            ))
            continue

        # ---------- SSH LOGS ----------
        ssh_match = re.search(r"sshd.*(Accepted|Failed).*for (\w+) from (\S+)", line)
        if ssh_match:
            status, user, ip = ssh_match.groups()
            severity = "HIGH" if status == "Failed" else "LOW"
            events.append(LogEvent(
                timestamp="unknown",
                source="ssh",
                event_type="authentication",
                severity=severity,
                user=user,
                ip=ip,
                action=status,
                raw=line
            ))
            continue

        # ---------- FIREWALL LOGS ----------
        fw_match = re.match(r"(\S+) (ALLOW|BLOCK) (\S+) (\S+) -> (\S+)", line)
        if fw_match:
            timestamp, action, proto, src, dst = fw_match.groups()
            ip = src.split(":")[0]
            severity = "HIGH" if action == "BLOCK" else "LOW"
            events.append(LogEvent(
                timestamp=timestamp,
                source="firewall",
                event_type="network",
                severity=severity,
                ip=ip,
                action=action,
                resource=dst,
                raw=line
            ))
            continue

        # ---------- GENERIC WEB SECURITY LOGS ----------
        # Example pattern (similar to your security log screenshot):
        # 16/Feb/2026:10:17:33 +0000 192.168.1.200 POST /admin/login HTTP/1.1 HIGH
        sec_match = re.match(
            r"(\d{1,2}/[A-Za-z]{3}/\d{4}[:\s]\S+)\s+(\S+)\s+"
            r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(\S+)\s+(\w+)",
            line,
        )
        if sec_match:
            ts, ip, method, endpoint, proto_or_status, severity = sec_match.groups()
            events.append(LogEvent(
                timestamp=ts,
                source="security",
                event_type="http_request",
                severity=severity.upper(),
                ip=ip,
                action=f"{method} {endpoint} {proto_or_status}",
                resource=endpoint,
                raw=line,
            ))
            continue

        # ---------- FALLBACK (generic events, try to keep timestamp) ----------
        timestamp = "unknown"
        # ISO‑like: 2026-02-16 10:17:33
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if not m:
            # Apache‑style date: 16/Feb/2026:10:17:33 +0000
            m = re.match(r"(\d{1,2}/[A-Za-z]{3}/\d{4}[:\s]\S+)", line)
        if m:
            timestamp = m.group(1)

        events.append(LogEvent(
            timestamp=timestamp,
            source="generic",
            event_type="event",
            severity="LOW",
            raw=line
        ))

    return events
    