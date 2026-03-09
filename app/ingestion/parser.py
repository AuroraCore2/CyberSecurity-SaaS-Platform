import re
import json
import csv
from typing import List, Optional, Tuple
from app.models.event import LogEvent


# ── Helper regexes ─────────────────────────────────────────────────────────────

_RE_IP       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_ISO_TS   = re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}')
_RE_APACHE_TS = re.compile(r'\d{1,2}/[A-Za-z]{3}/\d{4}[:\s]\S+')
_RE_STATUS   = re.compile(r'\b([1-5]\d{2})\b')
_RE_METHOD   = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\b')
_RE_ENDPOINT = re.compile(r'((?:/[\w.\-/%?&=+#@!*()]*)+)')
_RE_UA       = re.compile(r'"([^"]*(?:Mozilla|Chrome|Safari|Firefox|curl|python|bot|spider|wget|Go-http|okhttp|Apache|Java)[^"]*)"', re.IGNORECASE)
_RE_BYTES    = re.compile(r'\b(\d{3,9})\b')

# Apache / Nginx Combined Log:
# 1.2.3.4 - - [10/Feb/2024:10:01:05 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "UA"
_RE_COMBINED = re.compile(
    r'^(\S+)\s+'                           # ip
    r'\S+\s+\S+\s+'                        # ident auth
    r'\[([^\]]+)\]\s+'                     # timestamp
    r'"(\S+)\s+(\S+)\s+\S+"\s+'           # method endpoint proto
    r'(\d{3})\s+'                          # status
    r'(\S+)'                               # bytes (may be -)
    r'(?:\s+"[^"]*"\s+"([^"]*)")?'         # referer UA (optional)
)

# Generic web security log:
# 16/Feb/2026:10:17:33 +0000 192.168.1.200 POST /admin/login HTTP/1.1 HIGH
_RE_SECURITY = re.compile(
    r'(\d{1,2}/[A-Za-z]{3}/\d{4}[:\s]\S+)\s+(\S+)\s+'
    r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(\S+)\s+(\w+)'
)

# ISO-timestamp web security log:
# 2026-02-16 10:17:33 192.168.1.200 POST /admin/login HTTP/1.1 HIGH 1234
_RE_ISO_SEC = re.compile(
    r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(\S+)\s+'
    r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(\S+)\s+(\w+)(?:\s+(\d+))?'
)

# Apache error / SSH / normal syslog timestamp prefix
_RE_SYSLOG_TS = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s'
)


def _severity_from_level(level: str) -> str:
    l = level.lower()
    if any(w in l for w in ['crit', 'emerg', 'fail', 'error', 'block', 'deny', 'attack']):
        return 'HIGH'
    if any(w in l for w in ['warn', 'suspicious', 'notice']):
        return 'MEDIUM'
    return 'LOW'


def _severity_from_status(status: str) -> str:
    if status.startswith('5') or status in ('401', '403'):
        return 'HIGH'
    if status.startswith('4'):
        return 'MEDIUM'
    return 'LOW'


def _guess_source(line_lower: str) -> str:
    if 'ssh' in line_lower or 'sshd' in line_lower:
        return 'ssh'
    if any(w in line_lower for w in ['ufw', 'iptables', 'firewall', 'pf:', 'deny', 'block']):
        return 'firewall'
    if any(w in line_lower for w in ['apache', 'nginx', 'httpd', 'get ', 'post ']):
        return 'web'
    return 'generic'


def _classify_ua(ua: str) -> str:
    if not ua:
        return 'Unknown'
    u = ua.lower()
    if any(b in u for b in ['bot', 'spider', 'crawler', 'scan', 'python', 'curl', 'wget', 'go-http', 'okhttp', 'java', 'zgrab', 'masscan', 'nmap']):
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


# ── Main parser ────────────────────────────────────────────────────────────────

def parse_logs(raw_text: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    lines = raw_text.splitlines()

    # ── WINDOWS EVENT VIEWER CSV ───────────────────────────────────────────────
    if lines and ',' in lines[0] and 'Event ID' in lines[0]:
        reader = csv.DictReader(lines)
        for row in reader:
            if not any(row.values()):
                continue
            timestamp = (row.get('Date and Time') or row.get('Date')
                         or row.get('TimeCreated') or 'unknown')
            event_id  = row.get('Event ID') or row.get('EventID') or 'unknown'
            level     = row.get('Level') or row.get('Keywords') or 'Info'
            task      = row.get('Task Category') or row.get('Task') or ''
            user      = row.get('Account Name') or row.get('User') or None
            description = row.get('Description') or ''

            ip = None
            m = re.search(r'Source Network Address:\s*([\d\.]+)', description)
            if m:
                ip = m.group(1)

            severity = _severity_from_level(level)
            events.append(LogEvent(
                timestamp=timestamp, source='security', event_type=str(event_id),
                severity=severity, user=user, ip=ip,
                action=level, resource=task or None, raw=json.dumps(row),
            ))
        return events

    # ── PER-LINE PARSING ───────────────────────────────────────────────────────
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ── JSON line ─────────────────────────────────────────────────────────
        if line.startswith('{') and line.endswith('}'):
            try:
                data = json.loads(line)
                status = str(data.get('status', data.get('status_code', '')))
                severity = data.get('level', data.get('severity', 'INFO')).upper()
                if status and status.isdigit():
                    severity = _severity_from_status(status)
                events.append(LogEvent(
                    timestamp=data.get('timestamp', 'unknown'),
                    source='application',
                    event_type=data.get('level', 'info'),
                    severity=severity,
                    user=data.get('user'),
                    ip=data.get('ip') or data.get('remote_addr'),
                    action=data.get('message') or data.get('action'),
                    resource=data.get('path') or data.get('uri') or data.get('endpoint'),
                    raw=line,
                    status_code=status or None,
                    user_agent=data.get('user_agent') or data.get('ua'),
                    bytes_sent=int(data.get('bytes', 0)) or None,
                    method=data.get('method'),
                ))
                continue
            except Exception:
                pass

        # ── Apache / Nginx Combined Log ────────────────────────────────────────
        m = _RE_COMBINED.match(line)
        if m:
            ip, ts, method, endpoint, status, raw_bytes, ua = m.groups()
            bytes_sent = int(raw_bytes) if raw_bytes and raw_bytes.isdigit() else None
            severity   = _severity_from_status(status)
            ua_classified = _classify_ua(ua or '')
            events.append(LogEvent(
                timestamp=ts, source='web', event_type='http_request',
                severity=severity, ip=ip,
                action=f'{method} {endpoint}',
                resource=endpoint, raw=line,
                status_code=status,
                user_agent=ua or None,
                bytes_sent=bytes_sent,
                method=method,
            ))
            continue

        # ── Generic web security log (Apache-style date) ───────────────────────
        m = _RE_SECURITY.match(line)
        if m:
            ts, ip, method, endpoint, proto_or_status, sev_raw = m.groups()
            # proto_or_status is either "HTTP/1.1" or a status code
            if _RE_STATUS.match(proto_or_status):
                status = proto_or_status
                severity = _severity_from_status(status)
            else:
                status = None
                severity = sev_raw.upper() if sev_raw.upper() in ('LOW','MEDIUM','HIGH','CRITICAL') else _severity_from_level(sev_raw)
            events.append(LogEvent(
                timestamp=ts, source='security', event_type='http_request',
                severity=severity, ip=ip,
                action=f'{method} {endpoint}',
                resource=endpoint, raw=line,
                status_code=status,
                method=method,
            ))
            continue

        # ── ISO-timestamp web security log ────────────────────────────────────
        m = _RE_ISO_SEC.match(line)
        if m:
            ts, ip, method, endpoint, proto_or_status, sev_raw, raw_bytes = m.groups()
            if _RE_STATUS.match(proto_or_status):
                status = proto_or_status
                severity = _severity_from_status(status)
            else:
                status = None
                severity = sev_raw.upper() if sev_raw.upper() in ('LOW','MEDIUM','HIGH','CRITICAL') else _severity_from_level(sev_raw)
            events.append(LogEvent(
                timestamp=ts, source='security', event_type='http_request',
                severity=severity, ip=ip,
                action=f'{method} {endpoint}',
                resource=endpoint, raw=line,
                status_code=status,
                bytes_sent=int(raw_bytes) if raw_bytes else None,
                method=method,
            ))
            continue

        # ── SSH logs ──────────────────────────────────────────────────────────
        m = re.search(r'sshd.*(Accepted|Failed).*for (\w+) from (\S+)', line)
        if m:
            status_word, user, ip = m.groups()
            severity = 'HIGH' if status_word == 'Failed' else 'LOW'
            ts_m = _RE_SYSLOG_TS.match(line)
            ts   = ts_m.group(1) if ts_m else 'unknown'
            events.append(LogEvent(
                timestamp=ts, source='ssh', event_type='authentication',
                severity=severity, user=user, ip=ip, action=status_word, raw=line,
            ))
            continue

        # ── Firewall logs ─────────────────────────────────────────────────────
        m = re.match(r'(\S+) (ALLOW|BLOCK) (\S+) (\S+) -> (\S+)', line)
        if m:
            ts, action, proto, src, dst = m.groups()
            ip = src.split(':')[0]
            severity = 'HIGH' if action == 'BLOCK' else 'LOW'
            events.append(LogEvent(
                timestamp=ts, source='firewall', event_type='network',
                severity=severity, ip=ip, action=action, resource=dst, raw=line,
            ))
            continue

        # ── FALLBACK: extract what we can ─────────────────────────────────────
        timestamp = 'unknown'
        tm = _RE_ISO_TS.search(line) or _RE_APACHE_TS.search(line)
        if tm:
            timestamp = tm.group(0)

        ip = None
        im = _RE_IP.search(line)
        if im:
            ip = im.group(0)

        # status
        status = None
        sm = _RE_STATUS.search(line)
        if sm:
            status = sm.group(1)

        # method
        method = None
        mm = _RE_METHOD.search(line)
        if mm:
            method = mm.group(1)

        # endpoint
        resource = None
        em = _RE_ENDPOINT.search(line)
        if em and len(em.group(1)) > 1:
            resource = em.group(1)[:120]

        # user agent
        ua = None
        um = _RE_UA.search(line)
        if um:
            ua = um.group(1)[:200]

        # bytes
        bytes_sent = None
        if method and status:
            bm = list(_RE_BYTES.finditer(line))
            if bm:
                # last multi-digit number is likely the byte count
                try:
                    bytes_sent = int(bm[-1].group(1))
                except Exception:
                    pass

        line_lower = line.lower()
        if status:
            severity = _severity_from_status(status)
        elif any(w in line_lower for w in ['fail', 'error', 'critical', 'deny', 'block', 'attack']):
            severity = 'HIGH'
        elif any(w in line_lower for w in ['warn', 'suspicious']):
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        source = _guess_source(line_lower)

        action = line[:200]
        if source == 'firewall':
            action = 'BLOCK' if ('block' in line_lower or 'deny' in line_lower) else 'ALLOW'

        user_extracted = None
        mu = re.search(r'(?:user|for|account|uname)[:=]?\s*([a-zA-Z0-9_\-]+)', line_lower)
        if mu and mu.group(1) not in ('to', 'from', 'for', 'the', 'a'):
            user_extracted = mu.group(1)

        events.append(LogEvent(
            timestamp=timestamp, source=source, event_type='event',
            severity=severity, user=user_extracted, ip=ip,
            action=action, resource=resource, raw=line,
            status_code=status, user_agent=ua,
            bytes_sent=bytes_sent, method=method,
        ))

    return events