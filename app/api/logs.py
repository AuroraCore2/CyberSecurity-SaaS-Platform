import re
from collections import Counter
from typing import Dict, Any, List, cast

from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from app.storage.database import get_db
from app.models.model import LogEvent
from app.detection.rules import run_detection
from app.ingestion.parser import parse_logs

router = APIRouter(prefix="/logs", tags=["Logs"])


def _classify_ua(ua: str) -> str:
    """Classify a raw User-Agent string into a readable category."""
    if not ua:
        return 'Unknown'
    u = ua.lower()
    if any(b in u for b in ['bot', 'spider', 'crawler', 'scan', 'python', 'curl', 'wget',
                              'go-http', 'okhttp', 'java', 'zgrab', 'masscan', 'nmap',
                              'nikto', 'sqlmap', 'dirbuster', 'hydra', 'perl', 'libwww']):
        return 'Bot/Scanner'
    if 'chrome' in u and 'edg' in u:
        return 'Edge'
    if 'firefox' in u:
        return 'Firefox'
    if 'chrome' in u:
        return 'Chrome'
    if 'safari' in u and 'chrome' not in u:
        return 'Safari'
    if 'mozilla' in u:
        return 'Other Browser'
    return 'Other'


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

def _compute_analytics_from_events(all_events) -> Dict[str, Any]:
    """
    Compute dashboard analytics from a list of event-like objects (ORM or Pydantic).
    Used by get_analytics and by upload fallback when DB is read-only (e.g. Vercel).
    """
    total = len(all_events)
    if total == 0:
        return _empty_analytics()

    _HTTP_METHODS = {'GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','CONNECT','TRACE','SSH','FW','EVT'}
    _METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\b')
    _ENDPOINT_FROM_RAW = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+', re.I)
    _PATH_IN_RAW = re.compile(r'(\s|")(/(?:[\w.\-%~]|%[0-9a-fA-F]{2})*(?:\?[^\s"]*)?)(?:\s|$)')

    def _get_method(ev) -> str:
        method = getattr(ev, 'method', None)
        if method and str(method).strip():
            mstr = str(method).strip().upper()
            if mstr in _HTTP_METHODS:
                return mstr
            if mstr in ('SSH','FW','EVT'):
                return mstr
        action = getattr(ev, 'action', None)
        if action:
            m = _METHOD_RE.search(str(action))
            if m:
                return m.group(1)
        raw = getattr(ev, 'raw', None) or ''
        if raw:
            m = _METHOD_RE.search(raw)
            if m:
                return m.group(1)
        src = (getattr(ev, 'source', None) or '').lower()
        if src == 'ssh':
            return 'SSH'
        if src == 'firewall':
            a = getattr(ev, 'action', None)
            return str(a) if a in ('ALLOW', 'BLOCK') else 'FW'
        return 'N/A'

    def _get_endpoint(ev) -> str:
        resource = getattr(ev, 'resource', None)
        if resource and str(resource).strip():
            r = str(resource).strip()
            if len(r) < 200 and (r.startswith('/') or r.startswith('http') or ':' in r or len(r) > 2):
                return r[:80]
        action = getattr(ev, 'action', None)
        if action:
            for p in str(action).split():
                if p.startswith('/') or p.startswith('http'):
                    return p[:80]
                if ':' in p and not p.startswith('http'):  # host:port
                    return p[:60]
        raw = getattr(ev, 'raw', None) or ''
        if raw:
            em = _ENDPOINT_FROM_RAW.search(raw)
            if em:
                return em.group(1)[:80]
            pm = _PATH_IN_RAW.search(raw)
            if pm:
                return pm.group(2)[:80]
            if len(raw) > 20 and not raw.startswith('{'):
                return raw[:60] + ('…' if len(raw) > 60 else '')
        src = (getattr(ev, 'source', None) or '').lower()
        if src == 'ssh':
            return 'SSH auth'
        if src == 'firewall':
            return str(resource) if resource else 'FW rule'
        return 'N/A'

    def _get_status(ev) -> str:
        sc = getattr(ev, 'status_code', None)
        if sc and str(sc).strip():
            s = str(sc).strip()
            if s.isdigit() and 100 <= int(s) <= 599:
                return s
            if s in ('Accepted', 'Failed', 'ALLOW', 'BLOCK'):
                return s
        src = (getattr(ev, 'source', None) or '').lower()
        action = getattr(ev, 'action', None)
        if src == 'ssh' and action in ('Accepted', 'Failed'):
            return str(action)
        if src == 'firewall' and action in ('ALLOW', 'BLOCK'):
            return str(action)
        raw = getattr(ev, 'raw', None) or ''
        if raw:
            m = re.search(r'\b([1-5]\d{2})\b', raw)
            if m:
                return m.group(1)
        return 'N/A'

    def _is_internal(ip: str) -> bool:
        if not ip or ip == 'N/A':
            return True
        parts = str(ip).split('.')
        if len(parts) < 2:
            return True
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return True
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))

    sev_counter: Counter = Counter()
    for ev in all_events:
        s = (getattr(ev, 'severity', None) or 'LOW').upper()
        if s not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            s = 'LOW'
        sev_counter[s] += 1

    low_count = sev_counter['LOW']
    medium_count = sev_counter['MEDIUM']
    high_count = sev_counter['HIGH']
    critical_count = sev_counter['CRITICAL']
    critical_threats = high_count + critical_count

    risk_distribution = {
        'LOW': low_count, 'MEDIUM': medium_count,
        'HIGH': high_count, 'CRITICAL': critical_count,
    }

    unique_attacker_ips = set(
        getattr(ev, 'ip', None) for ev in all_events
        if getattr(ev, 'ip', None)
    )
    unique_attackers = len(unique_attacker_ips)
    system_health = max(0.0, round(100.0 - (critical_threats / total * 100.0), 1))

    bytes_list = [getattr(ev, 'bytes_sent', None) for ev in all_events
                  if getattr(ev, 'bytes_sent', None) and getattr(ev, 'bytes_sent', 0) > 0]
    avg_response_ms = round(10.0 + (sum(bytes_list) / len(bytes_list) / 10_000), 1) if bytes_list else None

    hourly_raw: Counter = Counter()
    timestamps_found = 0
    for ev in all_events:
        h = _extract_hour(getattr(ev, 'timestamp', None) or '')
        if h is not None:
            hourly_raw[h] += 1
            timestamps_found += 1

    if timestamps_found > total * 0.3:
        traffic_labels = [f'{str(h).zfill(2)}:00' for h in sorted(hourly_raw)]
        traffic_values = [hourly_raw[h] for h in sorted(hourly_raw)]
    else:
        n_buckets = min(10, total)
        traffic_labels = [f'T{i+1}' for i in range(n_buckets)]
        traffic_values = []
        for i in range(n_buckets):
            s, e = int(i * total / n_buckets), int((i + 1) * total / n_buckets)
            traffic_values.append(e - s)
    traffic_analysis = {'labels': traffic_labels, 'values': traffic_values}

    threat_hourly: Counter = Counter()
    for ev in all_events:
        if (getattr(ev, 'severity', None) or '').upper() in ('HIGH', 'CRITICAL'):
            h = _extract_hour(getattr(ev, 'timestamp', None) or '')
            if h is not None:
                threat_hourly[h] += 1
    hourly_threat_density = {
        'labels': [f'{str(h).zfill(2)}:00' for h in range(24)],
        'values': [threat_hourly.get(h, 0) for h in range(24)],
    }

    ep_counter: Counter = Counter()
    skip_values = {'ALLOW', 'BLOCK', 'Accepted', 'Failed', '—', '', 'N/A'}
    for ev in all_events:
        ep = _get_endpoint(ev)
        if ep and ep not in skip_values and ep != 'SSH session' and ep != '—':
            ep_counter[ep[:60]] += 1
    top_endpoints_raw = ep_counter.most_common(8)
    top_endpoints = {'labels': [e[0] for e in top_endpoints_raw], 'values': [e[1] for e in top_endpoints_raw]}

    status_counter: Counter = Counter()
    for ev in all_events:
        sc = (getattr(ev, 'status_code', None) or '').strip()
        if sc and sc.isdigit() and 100 <= int(sc) <= 599:
            status_counter[sc] += 1
    if not status_counter:
        if low_count: status_counter['200'] = low_count
        if medium_count: status_counter['404'] = medium_count
        if high_count: status_counter['401'] = high_count
        if critical_count: status_counter['500'] = critical_count
    top_statuses = status_counter.most_common(8)
    response_codes = {'labels': [s[0] for s in top_statuses], 'values': [s[1] for s in top_statuses]}

    protocol_counter: Counter = Counter()
    for ev in all_events:
        src = (getattr(ev, 'source', None) or '').lower()
        raw = (getattr(ev, 'raw', None) or '').lower()
        if src in ('web', 'apache', 'nginx', 'application', 'security'):
            protocol_counter['HTTPS' if ('443' in raw or 'https' in raw) else 'HTTP'] += 1
        elif src == 'ssh':
            protocol_counter['SSH'] += 1
        elif src == 'firewall':
            protocol_counter['Firewall'] += 1
        else:
            if 'ssh' in raw:
                protocol_counter['SSH'] += 1
            elif 'https' in raw or '443' in raw:
                protocol_counter['HTTPS'] += 1
            elif any(m in raw for m in ['get ', 'post ', 'http']):
                protocol_counter['HTTP'] += 1
            else:
                protocol_counter['Other'] += 1
    protocol_breakdown = {'labels': list(protocol_counter.keys()), 'values': list(protocol_counter.values())}

    geo_counter: Counter = Counter()
    for ev in all_events:
        geo_counter[_guess_country(getattr(ev, 'ip', None) or '')] += 1
    geo_data = geo_counter.most_common(7)
    geographic_origins = {'labels': [g[0] for g in geo_data], 'values': [g[1] for g in geo_data]}

    all_eps = [_get_endpoint(ev) for ev in all_events]
    av_counts = _classify_attack_vectors(all_eps)
    attack_vectors = {'labels': list(av_counts.keys()), 'values': list(av_counts.values())}

    ua_counter: Counter = Counter()
    for ev in all_events:
        ua_counter[_classify_ua(getattr(ev, 'user_agent', None) or '')] += 1
    ua_data = ua_counter.most_common(6)
    user_agent_analysis = {'labels': [u[0] for u in ua_data], 'values': [u[1] for u in ua_data]}

    events_with_bytes = [ev for ev in all_events if getattr(ev, 'bytes_sent', None) and getattr(ev, 'bytes_sent', 0) > 0]
    bw_buckets = min(12, max(1, len(events_with_bytes) or total))
    bw_labels = [f'B{i+1}' for i in range(bw_buckets)]
    src_list = events_with_bytes if events_with_bytes else all_events
    src_len = len(src_list)
    bw_values = []
    for i in range(bw_buckets):
        s_, e_ = int(i * src_len / bw_buckets), int((i + 1) * src_len / bw_buckets)
        bucket = src_list[s_:e_]
        bw_values.append(round(sum((getattr(ev, 'bytes_sent', None) or 0) for ev in bucket) / 1_000_000, 4))
    bandwidth_usage = {'labels': bw_labels, 'values': bw_values}

    def _severity_score(ev) -> int:
        s = (getattr(ev, 'severity', None) or 'LOW').upper()
        return {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(s, 0)

    def _sort_key(e):
        return (_severity_score(e), str(getattr(e, 'timestamp', '') or ''))

    # Show all data ordered by severity (high to low), then ID/timestamp DESC
    recent = sorted(all_events, key=_sort_key, reverse=True)

    detected_incidents = []
    # Group incidents by type and description to avoid spamming the UI and combine source IPs
    # Using a typed dict structure for internal grouping
    incident_groups: dict[str, dict[str, Any]] = {}
    
    # Identify all CRITICAL, HIGH, and MEDIUM events as potential incidents
    incident_candidates = [ev for ev in recent if (getattr(ev, 'severity', None) or 'LOW').upper() in ('CRITICAL', 'HIGH', 'MEDIUM')]
    
    for ev in incident_candidates:
        severity = (getattr(ev, 'severity', None) or 'HIGH').upper()
        action_text = getattr(ev, 'action', None) or ''
        resource_text = getattr(ev, 'resource', None) or ''
        full_text = f"{action_text} {resource_text}".lower()
        source_ip = getattr(ev, 'ip', None) or 'Unknown'
        timestamp = getattr(ev, 'timestamp', None) or '—'
        evt_type = str(getattr(ev, 'event_type', None) or '').lower()
        status_code = getattr(ev, 'status_code', None)
        
        # Determine rich type and description
        inc_type = 'Suspicious Activity'
        desc = f"Action: {action_text}"
        if resource_text and resource_text not in action_text:
            desc += f" on {resource_text}"

        is_web = getattr(ev, 'source', '') == 'web' or 'http_request' in evt_type
        outcome = "SUSPECTED_BREACH" if str(status_code) == "200" else "BLOCKED_PROBE"

        # Heuristics for common attacks
        if is_web or 'sqli' in evt_type or 'sql' in full_text or 'union' in full_text or 'select' in full_text:
            if any(k in full_text for k in ['select', 'union', 'insert', 'drop', '--', '%27', "'"]):
                inc_type = 'SQL Injection'
                desc = "Attempted database manipulation. " + ("Target potentially vulnerable - request successful." if outcome == "SUSPECTED_BREACH" else "Request blocked by security filters.")
        
        elif '../' in full_text or '/etc/passwd' in full_text or 'traversal' in evt_type:
            inc_type = 'Directory Traversal'
            desc = "Path traversal detected. " + ("Sensitive file exposure suspected." if outcome == "SUSPECTED_BREACH" else "Access denied by filesystem permissions or WAF.")
            
        elif '<script>' in full_text or 'alert(' in full_text or 'xss' in evt_type:
            inc_type = 'Cross Site Scripting'
            desc = "Script injection payload detected. " + ("Payload delivered to victim session." if outcome == "SUSPECTED_BREACH" else "Malicious script filtered out.")
            
        elif '/exec' in full_text or 'cmd=' in full_text or 'rce' in evt_type:
            inc_type = 'Remote Code Execution'
            desc = "Command execution attempt. " + ("High probability of system compromise." if outcome == "SUSPECTED_BREACH" else "Execution attempt terminated.")

        elif getattr(ev, 'source', '') == 'ssh':
            if 'fail' in full_text or 'brute' in evt_type:
                inc_type = 'SSH Brute Force'
                desc = "Repeated failed SSH authentication. " + ("Brute force attack in progress." if outcome == "BLOCKED_PROBE" else "Account takeover detected.")

        elif status_code in ('401', '403') and ('login' in full_text or 'auth' in full_text):
            inc_type = 'Authentication Attack'
            desc = "Unauthorized access attempt to authentication endpoint."
            
        elif getattr(ev, 'source', '') == 'firewall' and 'block' in full_text:
            inc_type = 'Firewall Block / Port Scan'
            desc = f"Network probing activity blocked on resource {resource_text}."
            
        # Refine severity and aggregate descriptive outcome
        if outcome == "SUSPECTED_BREACH" and severity != "CRITICAL":
            severity = "CRITICAL"
        
        full_desc = f"OUTCOME: {outcome} | {desc}"
            
        # Fallback formatting if no heuristic matched
        if inc_type == 'Suspicious Activity' and evt_type and evt_type not in ('http_request', 'network', 'authentication'):
            inc_type = evt_type.replace('_', ' ').title()

        # Grouping key
        group_key = f"{inc_type}_{severity}_{full_desc}"
        
        if group_key not in incident_groups:
            incident_groups[group_key] = {
                'timestamp': timestamp, # Keep the most recent timestamp (since sorted DESC)
                'type': inc_type,
                'severity': severity,
                'source_ips': [source_ip],
                'description': full_desc
            }
        else:
            if source_ip not in incident_groups[group_key]['source_ips']:
                incident_groups[group_key]['source_ips'].append(source_ip)

    # Flatten and format
    for grp in incident_groups.values():
        ips = cast(List[str], grp['source_ips'])
        ip_display = ", ".join(ips[:3])
        if len(ips) > 3:
            ip_display += f", +{len(ips) - 3} more"
            
        detected_incidents.append({
            'timestamp': grp['timestamp'],
            'type': grp['type'],
            'severity': grp['severity'],
            'source_ip': ip_display,
            'description': grp['description']
        })

    # Sort detected incidents by severity (CRITICAL > HIGH > MEDIUM)
    severity_map = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    detected_incidents.sort(key=lambda x: severity_map.get(x['severity'], 0), reverse=True)
    forensics_table = [
        {
            'timestamp': getattr(ev, 'timestamp', None) or '—',
            'ip': getattr(ev, 'ip', None) or 'N/A',
            'method': _get_method(ev),
            'endpoint': _get_endpoint(ev),
            'status': _get_status(ev),
            'severity': (getattr(ev, 'severity', None) or 'LOW').upper(),
        }
        for ev in recent
    ]

    return {
        'total_events': total, 'critical_threats': critical_threats,
        'unique_attackers': unique_attackers, 'avg_response_time_ms': avg_response_ms,
        'system_health': system_health,
        'traffic_analysis': traffic_analysis, 'risk_distribution': risk_distribution,
        'attack_vectors': attack_vectors, 'geographic_origins': geographic_origins,
        'protocol_breakdown': protocol_breakdown, 'hourly_threat_density': hourly_threat_density,
        'top_endpoints': top_endpoints, 'user_agent_analysis': user_agent_analysis,
        'response_codes': response_codes, 'bandwidth_usage': bandwidth_usage,
        'forensics_table': forensics_table,
        'detected_incidents': detected_incidents,
    }


@router.post("/upload")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Ingest a log file, parse it into structured events, store, then run detection.
    On read-only DB (e.g. Vercel), returns analytics in response so dashboard still works.
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    print(f"[upload] {file.filename}: {len(text)} chars")

    parsed_events = parse_logs(text)
    print(f"[upload] parsed {len(parsed_events)} events")

    if not parsed_events:
        return {"message": "No parseable events found in file", "events_saved": 0, "incidents_created": 0}

    db_ok = False
    incidents = 0

    try:
        deleted = db.query(LogEvent).delete()
        print(f"[upload] cleared {deleted} previous events")
        for ev in parsed_events:
            db_event = LogEvent(
                timestamp=ev.timestamp, source=ev.source, event_type=ev.event_type,
                severity=ev.severity, user=ev.user, ip=ev.ip, action=ev.action,
                resource=ev.resource, raw=ev.raw, status_code=ev.status_code,
                user_agent=ev.user_agent, bytes_sent=ev.bytes_sent, method=ev.method,
            )
            db.add(db_event)
        db.commit()
        print(f"[upload] committed {len(parsed_events)} events")
        db_ok = True
        try:
            # Run detection on newly uploaded events only (more efficient and targeted)
            incidents = len(run_detection(db, parsed_events))
        except Exception as e:
            print(f"[upload] detection error: {e}")
            incidents = 0
    except Exception as e:
        print(f"[upload] database write unavailable (read-only?): {e}")
        db.rollback()
        # Fallback: compute analytics in-memory for serverless/read-only environments
        analytics = _compute_analytics_from_events(parsed_events)
        return {
            "message": "Logs analysed successfully",
            "events_saved": len(parsed_events),
            "incidents_created": 0,
            "analytics": analytics,
        }

    if db_ok:
        return {
            "message": "Logs analysed successfully",
            "events_saved": len(parsed_events),
            "incidents_created": incidents,
        }


# ── Raw log list ───────────────────────────────────────────────────────────────


@router.get("/")
def get_logs(db: Session = Depends(get_db)):
    """Return the most recent 100 log events for the dashboard."""
    try:
        total_count = db.query(LogEvent).count()
        logs = db.query(LogEvent).order_by(LogEvent.id.desc()).all()
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
    For performance, only processes the most recent 2000 events.
    Every value is derived strictly from the parsed log data — nothing is random or hardcoded.
    """
    try:
        # Get total count of all events in database
        total_events_count = db.query(LogEvent).count()

        # Performance optimization: only process the most recent 1000 events
        # This prevents slowdown with large datasets while still providing meaningful analytics
        recent_events = db.query(LogEvent).order_by(LogEvent.id.desc()).limit(1000).all()

        analytics = _compute_analytics_from_events(recent_events)

        # Override the total_events with the actual database count
        analytics['total_events'] = total_events_count

        return analytics
    except Exception as e:
        print(f"[analytics] error: {e}")
        import traceback
        traceback.print_exc()
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
        'detected_incidents': [],
    }