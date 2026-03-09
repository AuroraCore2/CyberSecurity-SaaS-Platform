import re
from collections import Counter, defaultdict
from typing import Dict, Any

from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from app.storage.database import get_db
from app.models.model import LogEvent
from app.detection.rules import run_detection
from app.ingestion.parser import parse_logs, _classify_ua

router = APIRouter(prefix="/logs", tags=["Logs"])


# ── Helpers ────────────────────────────────────────────────────────────────────

_ATTACK_PATTERNS = {
    'SQLi':           re.compile(r"(select\s+|union\s+|insert\s+|drop\s+|\'|--|\bor\b\s+\d|benchmark\()", re.I),
    'XSS':            re.compile(r"(<script|javascript:|onload=|onerror=|alert\(|document\.cookie)", re.I),
    'Path Traversal': re.compile(r"(\.\./|/etc/passwd|/etc/shadow|/proc/self|\.env|\.git|backup\.)", re.I),
    'BruteForce':     re.compile(r"(/login|/wp-login|/admin|/auth|/signin)", re.I),
    'Scanner':        re.compile(r"(/wp-admin|/phpmyadmin|/xmlrpc\.php|/config\.php|/.env|/shell)", re.I),
    'RCE':            re.compile(r"(/exec|/cmd|/eval|/upload\.php|/api/exec|shell_exec|passthru)", re.I),
    'CSRF':           re.compile(r"(/api/.*\b(delete|update|modify)\b)", re.I),
    'DDoS':           re.compile(r"(/health|/ping|/status|/robots\.txt)", re.I),
}

def _classify_attack_vectors(endpoints) -> Dict[str, int]:
    counts = {v: 0 for v in _ATTACK_PATTERNS}
    for ep in endpoints:
        if not ep:
            continue
        for name, pat in _ATTACK_PATTERNS.items():
            if pat.search(ep):
                counts[name] += 1
    # Remove zeros for cleaner charts
    return {k: v for k, v in counts.items() if v > 0} or {'Normal Traffic': len(endpoints)}

def _guess_country(ip: str) -> str:
    if not ip:
        return 'Unknown'
    parts = ip.split('.')
    if len(parts) < 1:
        return 'Unknown'
    try:
        first = int(parts[0])
        second = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return 'Unknown'
    # Private / RFC1918
    if first == 10:
        return 'Internal'
    if first == 172 and 16 <= second <= 31:
        return 'Internal'
    if first == 192 and second == 168:
        return 'Internal'
    if first == 127:
        return 'Localhost'
    # Public range heuristics (rough, for demo/analytics purposes)
    if first in range(1, 50):
        return 'US/NA'
    if first in range(50, 100):
        return 'EU'
    if first in range(100, 150):
        return 'CN/APAC'
    if first in range(150, 200):
        return 'RU/EMEA'
    if first in range(200, 256):
        return 'Other'
    return 'Unknown'

def _extract_hour(ts: str) -> int | None:
    """Pull hour (0-23) from an ISO or Apache timestamp."""
    m = re.search(r'(\d{2}):(\d{2}):\d{2}', ts)
    return int(m.group(1)) if m else None


# ── Upload ─────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Ingest a log file, parse it into structured events, store, then run detection."""
    print(f"Received file: {file.filename}, size: {len(await file.read())}")
    await file.seek(0)
    content = await file.read()
    text    = content.decode("utf-8", errors="ignore")
    print(f"Decoded text length: {len(text)}")

    parsed_events = parse_logs(text)
    print(f"Parsed {len(parsed_events)} events")

    try:
        for ev in parsed_events:
            db_event = LogEvent(
                timestamp=ev.timestamp,
                source=ev.source,
                event_type=ev.event_type,
                severity=ev.severity,
                user=ev.user,
                ip=ev.ip,
                action=ev.action,
                resource=ev.resource,
                raw=ev.raw,
                status_code=ev.status_code,
                user_agent=ev.user_agent,
                bytes_sent=ev.bytes_sent,
                method=ev.method,
            )
            db.add(db_event)
        db.commit()
        print(f"Committed {len(parsed_events)} events to database")
    except Exception as e:
        print(f"Database error: {e}")
        db.rollback()
        return {"error": f"Database error: {str(e)}"}

    incidents = run_detection(db)
    print(f"Created {incidents} incidents")

    return {
        "message": "Logs stored successfully",
        "events_saved": len(parsed_events),
        "incidents_created": incidents,
    }


# ── Raw log list ───────────────────────────────────────────────────────────────

@router.get("/")
def get_logs(db: Session = Depends(get_db)):
    """Return the most recent 100 log events for the dashboard."""
    try:
        total_count = db.query(LogEvent).count()
        logs = db.query(LogEvent).order_by(LogEvent.id.desc()).limit(100).all()
        return {
            "total_events": total_count,
            "logs": [
                {
                    "id": log.id,
                    "timestamp": log.timestamp,
                    "source": log.source,
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "user": log.user,
                    "ip": log.ip,
                    "action": log.action,
                    "resource": log.resource,
                    "status_code": log.status_code,
                    "user_agent": log.user_agent,
                    "method": log.method,
                }
                for log in logs
            ]
        }
    except Exception as e:
        print(f"Error in get_logs: {e}")
        return {"error": f"Failed to retrieve logs: {str(e)}", "total_events": 0, "logs": []}


# ── Analytics ──────────────────────────────────────────────────────────────────

@router.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    """
    Compute all dashboard metrics from stored events.
    Returns a single JSON object consumed by the frontend chart layer.
    """
    try:
        all_events = db.query(LogEvent).all()
        total = len(all_events)

        if total == 0:
            return _empty_analytics()

        # ── Severity counts ─────────────────────────────────────────────────
        sev_counter: Counter = Counter()
        for ev in all_events:
            s = (ev.severity or 'LOW').upper()
            sev_counter[s] += 1

        critical_threats = sev_counter.get('CRITICAL', 0) + sev_counter.get('HIGH', 0)
        risk_distribution = {
            'LOW':      sev_counter.get('LOW', 0),
            'MEDIUM':   sev_counter.get('MEDIUM', 0),
            'HIGH':     sev_counter.get('HIGH', 0),
            'CRITICAL': sev_counter.get('CRITICAL', 0),
        }

        # ── Unique attackers (IPs from HIGH/CRITICAL events) ─────────────────
        attacker_ips = set(
            ev.ip for ev in all_events
            if ev.ip and (ev.severity or '').upper() in ('CRITICAL', 'HIGH')
        )
        unique_attackers = len(attacker_ips)

        # ── System health ────────────────────────────────────────────────────
        system_health = max(0.0, round(100 - (critical_threats / total * 100), 1))

        # ── Avg response time (derived from bytes_sent, realistic heuristic) ─
        bytes_list = [ev.bytes_sent for ev in all_events if ev.bytes_sent]
        if bytes_list:
            avg_bytes = sum(bytes_list) / len(bytes_list)
            # Rough: ~10 ms base + 0.001 ms per byte (100 KB ≈ 110 ms)
            avg_response_ms = round(10 + avg_bytes * 0.001, 1)
        else:
            avg_response_ms = None  # Will trigger "N/A" on frontend

        # ── Traffic over time (up to 12 equal buckets across all events) ─────
        n_buckets = min(12, total)
        bucket_labels = [f'T{i+1}' for i in range(n_buckets)]
        bucket_values = []
        for i in range(n_buckets):
            s = int(i * total / n_buckets)
            e = int((i + 1) * total / n_buckets)
            bucket_values.append(e - s)
        traffic_analysis = {'labels': bucket_labels, 'values': bucket_values}

        # ── Hourly threat density ────────────────────────────────────────────
        hourly: Counter = Counter()
        for ev in all_events:
            h = _extract_hour(ev.timestamp or '')
            if h is not None:
                hourly[h] += 1
        hourly_labels = [f'{str(h).zfill(2)}:00' for h in range(24)]
        hourly_values = [hourly.get(h, 0) for h in range(24)]
        hourly_threat_density = {'labels': hourly_labels, 'values': hourly_values}

        # ── Top targeted endpoints ────────────────────────────────────────────
        ep_counter: Counter = Counter()
        for ev in all_events:
            ep = ev.resource or ev.action or ''
            if ep and ep not in ('ALLOW', 'BLOCK'):
                ep_counter[ep[:60]] += 1
        top_endpoints_raw = ep_counter.most_common(8)
        top_endpoints = {
            'labels': [e[0] for e in top_endpoints_raw],
            'values': [e[1] for e in top_endpoints_raw],
        }

        # ── Response code distribution ────────────────────────────────────────
        status_counter: Counter = Counter()
        for ev in all_events:
            sc = ev.status_code
            if sc and sc.isdigit():
                status_counter[sc] += 1
        if not status_counter:
            # fallback: infer from severity
            status_counter = Counter({'200': sev_counter.get('LOW', 1)})
        top_statuses = status_counter.most_common(8)
        response_codes = {
            'labels': [s[0] for s in top_statuses],
            'values': [s[1] for s in top_statuses],
        }

        # ── Protocol breakdown ─────────────────────────────────────────────────
        protocol_counter: Counter = Counter()
        for ev in all_events:
            src = (ev.source or '').lower()
            if src in ('web', 'apache', 'nginx', 'application', 'security'):
                # Guess HTTPS vs HTTP from endpoint / action
                raw = (ev.raw or '').lower()
                if 'https' in raw or '443' in raw:
                    protocol_counter['HTTPS'] += 1
                else:
                    protocol_counter['HTTP'] += 1
            elif src == 'ssh':
                protocol_counter['SSH'] += 1
            elif src == 'firewall':
                protocol_counter['Firewall'] += 1
            else:
                protocol_counter['Other'] += 1
        protocol_breakdown = {
            'labels': list(protocol_counter.keys()),
            'values': list(protocol_counter.values()),
        }

        # ── Geographic origins ────────────────────────────────────────────────
        geo_counter: Counter = Counter()
        for ev in all_events:
            geo_counter[_guess_country(ev.ip or '')] += 1
        geo_data = geo_counter.most_common(7)
        geographic_origins = {
            'labels': [g[0] for g in geo_data],
            'values': [g[1] for g in geo_data],
        }

        # ── Attack vectors ────────────────────────────────────────────────────
        all_endpoints = [ev.resource or ev.action or '' for ev in all_events]
        av_counts = _classify_attack_vectors(all_endpoints)
        attack_vectors = {
            'labels': list(av_counts.keys()),
            'values': list(av_counts.values()),
        }

        # ── User agent analysis ───────────────────────────────────────────────
        ua_counter: Counter = Counter()
        for ev in all_events:
            ua_counter[_classify_ua(ev.user_agent or '')] += 1
        ua_data = ua_counter.most_common(6)
        user_agent_analysis = {
            'labels': [u[0] for u in ua_data],
            'values': [u[1] for u in ua_data],
        }

        # ── Bandwidth usage over time (bytes_sent per bucket) ─────────────────
        bw_buckets = min(12, total)
        bw_labels  = [f'{i+1}s' for i in range(bw_buckets)]
        bw_values  = []
        events_with_bytes = [ev for ev in all_events if ev.bytes_sent]
        for i in range(bw_buckets):
            s = int(i * total / bw_buckets)
            e = int((i + 1) * total / bw_buckets)
            bucket_events = events_with_bytes[s:e] if events_with_bytes else []
            total_bytes   = sum(ev.bytes_sent for ev in bucket_events)
            # Convert bytes to MB/s (rough: assume 1 log event = ~1 second)
            bw_values.append(round(total_bytes / 1_000_000, 4))
        bandwidth_usage = {'labels': bw_labels, 'values': bw_values}

        # ── Forensics table (most recent 100 events) ──────────────────────────
        recent = sorted(all_events, key=lambda e: e.id, reverse=True)[:100]
        forensics_table = [
            {
                'timestamp': ev.timestamp,
                'ip':        ev.ip or 'N/A',
                'method':    ev.method or (ev.action.split()[0] if ev.action else 'N/A'),
                'endpoint':  ev.resource or (ev.action[:60] if ev.action else 'N/A'),
                'status':    ev.status_code or '—',
                'severity':  (ev.severity or 'LOW').upper(),
            }
            for ev in recent
        ]

        return {
            # Stat cards
            'total_events':        total,
            'critical_threats':    critical_threats,
            'unique_attackers':    unique_attackers,
            'avg_response_time_ms': avg_response_ms,
            'system_health':       system_health,

            # Charts
            'traffic_analysis':       traffic_analysis,
            'risk_distribution':      risk_distribution,
            'attack_vectors':         attack_vectors,
            'geographic_origins':     geographic_origins,
            'protocol_breakdown':     protocol_breakdown,
            'hourly_threat_density':  hourly_threat_density,
            'top_endpoints':          top_endpoints,
            'user_agent_analysis':    user_agent_analysis,
            'response_codes':         response_codes,
            'bandwidth_usage':        bandwidth_usage,

            # Table
            'forensics_table': forensics_table,
        }

    except Exception as e:
        print(f"Error in get_analytics: {e}")
        import traceback; traceback.print_exc()
        return {"error": f"Analytics computation failed: {str(e)}"}


def _empty_analytics() -> Dict[str, Any]:
    return {
        'total_events': 0,
        'critical_threats': 0,
        'unique_attackers': 0,
        'avg_response_time_ms': None,
        'system_health': 100.0,
        'traffic_analysis':      {'labels': [], 'values': []},
        'risk_distribution':     {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
        'attack_vectors':        {'labels': [], 'values': []},
        'geographic_origins':    {'labels': [], 'values': []},
        'protocol_breakdown':    {'labels': [], 'values': []},
        'hourly_threat_density': {'labels': [], 'values': []},
        'top_endpoints':         {'labels': [], 'values': []},
        'user_agent_analysis':   {'labels': [], 'values': []},
        'response_codes':        {'labels': [], 'values': []},
        'bandwidth_usage':       {'labels': [], 'values': []},
        'forensics_table': [],
    }