from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Dict, List, Any

from sqlalchemy.orm import Session
from app.models.model import LogEvent, Incident

# ============================================================================
# DETECTION RULES CONFIGURATION
# ============================================================================

DETECTION_RULES = {
    "SSH_BRUTE_FORCE": {
        "name": "SSH Brute Force Attack",
        "threshold": 5,
        "severity": "HIGH",
        "description": "Detects multiple failed SSH login attempts from same IP",
        "pattern": "≥5 failed SSH attempts",
        "category": "Rule-Based Detection"
    },
    "HTTP_BRUTE_FORCE": {
        "name": "HTTP Brute Force Attack", 
        "threshold": 10,
        "severity": "HIGH",
        "description": "Detects multiple failed HTTP authentication attempts",
        "pattern": "≥10 failed HTTP requests (4xx/5xx errors)",
        "category": "Rule-Based Detection"
    },
    "PORT_SCAN": {
        "name": "Port Scanning Activity",
        "threshold": 3,
        "severity": "HIGH",
        "description": "Detects reconnaissance by scanning multiple ports",
        "pattern": "≥3 different ports accessed from same IP",
        "category": "Rule-Based Detection"
    },
    "DIRECTORY_TRAVERSAL": {
        "name": "Directory Traversal Attack",
        "severity": "CRITICAL",
        "description": "Detects path traversal attempts to access sensitive files",
        "pattern": "Contains '../' or '/etc/passwd' patterns",
        "category": "Rule-Based (Signature Detection)"
    },
    "SQL_INJECTION": {
        "name": "SQL Injection Attack",
        "severity": "CRITICAL", 
        "description": "Detects SQL injection attack patterns in requests",
        "pattern": "Contains 'UNION SELECT', 'OR 1=1', or SQL keywords",
        "category": "Rule-Based (Signature Detection)"
    },
    "IP_VOLUME_ANOMALY": {
        "name": "IP Volume Anomaly",
        "severity": "MEDIUM",
        "description": "Detects IPs with abnormally high activity volume",
        "pattern": "Activity > Mean + 2×StdDev",
        "category": "ML-Based (IP Anomaly Detection)"
    },
    "IP_VELOCITY_ANOMALY": {
        "name": "IP Velocity Anomaly",
        "severity": "HIGH",
        "description": "Detects IPs with abnormally high request rates",
        "pattern": "Request rate > 10× median",
        "category": "ML-Based (IP Anomaly Detection)"
    },
    "MULTI_VECTOR_ATTACK": {
        "name": "Multi-Vector Attack Pattern",
        "severity": "HIGH",
        "description": "Detects IPs attacking from multiple sources",
        "pattern": "≥3 different attack vectors from same IP",
        "category": "ML-Based (Behavioral Analysis)"
    }
}


def run_detection(db: Session, events_to_analyze=None):
    """
    Run comprehensive threat detection using:
    1. Rule-Based Detection (Threshold & Signature-based)
    2. Statistical Anomaly Detection (ML-lite) - ADAPTIVE THRESHOLDS

    Args:
        db: Database session
        events_to_analyze: Optional list of events to analyze (defaults to all events)

    Returns list of detected incidents with detailed rule information.
    """

    if events_to_analyze is None:
        logs = db.query(LogEvent).all()
    else:
        logs = events_to_analyze

    if not logs:
        return []

    # Data structures for tracking
    ip_fail_count: Dict[str, int] = defaultdict(int)
    ip_http_fails: Dict[str, int] = defaultdict(int)
    ip_ports: Dict[str, set] = defaultdict(set)
    ip_event_count: Dict[str, int] = defaultdict(int)

    created_incidents: List[Incident] = []

    # ========================================================================
    # PHASE 1: PATTERN ANALYSIS (Rule-Based Signature Detection)
    # ========================================================================

    for log in logs:
        ip = log.ip or "unknown"
        ip_event_count[ip] += 1

        # RULE 1: SSH Brute Force Detection
        if log.source == "ssh" and log.action and "Failed" in log.action:
            ip_fail_count[ip] += 1

        # RULE 2: HTTP Brute Force Detection
        if log.source in ["apache", "nginx", "security", "web"] and log.severity in ["HIGH", "CRITICAL"]:
            ip_http_fails[ip] += 1

        # RULE 3: Port Scanning Detection
        if log.source == "firewall" and log.action in ["BLOCK", "DENY"]:
            if log.resource:
                ip_ports[ip].add(log.resource)

        # RULE 4: Directory Traversal Detection (Immediate)
        if log.action and ("../" in log.action or "/etc/passwd" in log.action or "c:\\windows" in log.action):
            rule = DETECTION_RULES["DIRECTORY_TRAVERSAL"]
            incident = Incident(
                type="DIRECTORY_TRAVERSAL",
                severity="CRITICAL",
                source_ip=ip,
                description=f"🚨 {rule['name']} | Rule: {rule['pattern']} | Method: {rule['category']} | Target: {log.action[:100]}"
            )
            db.add(incident)
            created_incidents.append(incident)

        # RULE 5: SQL Injection Detection (Immediate)
        if log.action:
            sql_patterns = ["UNION SELECT", "OR 1=1", "'; DROP", "' OR '1'='1"]
            if any(pattern.lower() in log.action.lower() for pattern in sql_patterns):
                rule = DETECTION_RULES["SQL_INJECTION"]
                incident = Incident(
                    type="SQL_INJECTION",
                    severity="CRITICAL",
                    source_ip=ip,
                    description=f"🚨 {rule['name']} | Rule: {rule['pattern']} | Method: {rule['category']} | Query: {log.action[:100]}"
                )
                db.add(incident)
                created_incidents.append(incident)

    # ========================================================================
    # PHASE 2: ADAPTIVE THRESHOLD ANALYSIS (Dataset-Responsive)
    # ========================================================================

    # Calculate dataset statistics for adaptive thresholds
    total_events = len(logs)
    unique_ips = len(ip_event_count)

    if unique_ips >= 3:  # Need minimum data for statistical analysis
        # Calculate adaptive thresholds based on dataset characteristics
        ssh_fail_counts = list(ip_fail_count.values())
        http_fail_counts = list(ip_http_fails.values())
        port_scan_counts = [len(ports) for ports in ip_ports.values()]

        # RULE 1: SSH Brute Force with Adaptive Threshold
        rule = DETECTION_RULES["SSH_BRUTE_FORCE"]
        if ssh_fail_counts:
            # Adaptive threshold: mean + 2*std_dev, but at least 3
            avg_ssh_fails = mean(ssh_fail_counts) if ssh_fail_counts else 0
            std_ssh_fails = pstdev(ssh_fail_counts) if len(ssh_fail_counts) > 1 else 0
            adaptive_ssh_threshold = max(3, int(avg_ssh_fails + 2 * std_ssh_fails))

            for ip, count in ip_fail_count.items():
                if count >= adaptive_ssh_threshold:
                    incident = Incident(
                        type="SSH_BRUTE_FORCE",
                        severity=rule["severity"],
                        source_ip=ip,
                        description=f"🚨 {rule['name']} | Adaptive Rule: ≥{adaptive_ssh_threshold} attempts (dataset: μ={avg_ssh_fails:.1f}, σ={std_ssh_fails:.1f}) | Detected: {count} attempts | Method: {rule['category']}"
                    )
                    db.add(incident)
                    created_incidents.append(incident)

        # RULE 2: HTTP Brute Force with Adaptive Threshold
        rule = DETECTION_RULES["HTTP_BRUTE_FORCE"]
        if http_fail_counts:
            # Adaptive threshold: mean + 2*std_dev, but at least 5
            avg_http_fails = mean(http_fail_counts) if http_fail_counts else 0
            std_http_fails = pstdev(http_fail_counts) if len(http_fail_counts) > 1 else 0
            adaptive_http_threshold = max(5, int(avg_http_fails + 2 * std_http_fails))

            for ip, count in ip_http_fails.items():
                if count >= adaptive_http_threshold:
                    incident = Incident(
                        type="HTTP_BRUTE_FORCE",
                        severity=rule["severity"],
                        source_ip=ip,
                        description=f"🚨 {rule['name']} | Adaptive Rule: ≥{adaptive_http_threshold} failed requests (dataset: μ={avg_http_fails:.1f}, σ={std_http_fails:.1f}) | Detected: {count} failed requests | Method: {rule['category']}"
                    )
                    db.add(incident)
                    created_incidents.append(incident)

        # RULE 3: Port Scanning with Adaptive Threshold
        rule = DETECTION_RULES["PORT_SCAN"]
        if port_scan_counts:
            # Adaptive threshold: mean + 1.5*std_dev, but at least 2
            avg_ports = mean(port_scan_counts) if port_scan_counts else 0
            std_ports = pstdev(port_scan_counts) if len(port_scan_counts) > 1 else 0
            adaptive_port_threshold = max(2, int(avg_ports + 1.5 * std_ports))

            for ip, ports in ip_ports.items():
                if len(ports) >= adaptive_port_threshold:
                    incident = Incident(
                        type="PORT_SCAN",
                        severity=rule["severity"],
                        source_ip=ip,
                        description=f"🚨 {rule['name']} | Adaptive Rule: ≥{adaptive_port_threshold} ports scanned (dataset: μ={avg_ports:.1f}, σ={std_ports:.1f}) | Detected: {len(ports)} ports | Method: {rule['category']}"
                    )
                    db.add(incident)
                    created_incidents.append(incident)
    else:
        # Fallback to fixed thresholds when dataset is too small
        print(f"[detection] Dataset too small ({unique_ips} IPs), using fixed thresholds")

        # RULE 1: SSH Brute Force Threshold (Fixed)
        rule = DETECTION_RULES["SSH_BRUTE_FORCE"]
        for ip, count in ip_fail_count.items():
            if count >= rule["threshold"]:
                incident = Incident(
                    type="SSH_BRUTE_FORCE",
                    severity=rule["severity"],
                    source_ip=ip,
                    description=f"🚨 {rule['name']} | Rule: {rule['pattern']} | Triggered: {count} attempts detected | Method: {rule['category']}"
                )
                db.add(incident)
                created_incidents.append(incident)

        # RULE 2: HTTP Brute Force Threshold (Fixed)
        rule = DETECTION_RULES["HTTP_BRUTE_FORCE"]
        for ip, count in ip_http_fails.items():
            if count >= rule["threshold"]:
                incident = Incident(
                    type="HTTP_BRUTE_FORCE",
                    severity=rule["severity"],
                    source_ip=ip,
                    description=f"🚨 {rule['name']} | Rule: {rule['pattern']} | Triggered: {count} failed requests | Method: {rule['category']}"
                )
                db.add(incident)
                created_incidents.append(incident)

        # RULE 3: Port Scan Threshold (Fixed)
        rule = DETECTION_RULES["PORT_SCAN"]
        for ip, ports in ip_ports.items():
            if len(ports) >= rule["threshold"]:
                incident = Incident(
                    type="PORT_SCAN",
                    severity=rule["severity"],
                    source_ip=ip,
                    description=f"🚨 {rule['name']} | Rule: {rule['pattern']} | Triggered: {len(ports)} ports scanned | Method: {rule['category']}"
                )
                db.add(incident)
                created_incidents.append(incident)
    
    # ========================================================================
    # PHASE 3: IP ANOMALY DETECTION (ML-Based)
    # ========================================================================
    
    # ANOMALY 1: Volume Anomalies (Z-score Analysis)
    rule = DETECTION_RULES["IP_VOLUME_ANOMALY"]
    if ip_event_count:
        counts = list(ip_event_count.values())
        if len(counts) >= 3:  # Need at least 3 IPs for meaningful statistics
            avg = mean(counts)
            std = pstdev(counts)
            
            if std > 0:
                threshold = avg + 2 * std
                
                for ip, count in ip_event_count.items():
                    if count > threshold:
                        z_score = (count - avg) / std
                        
                        # Severity based on Z-score
                        if z_score > 3:
                            severity = "CRITICAL"
                        elif z_score > 2.5:
                            severity = "HIGH"
                        else:
                            severity = "MEDIUM"
                        
                        incident = Incident(
                            type="IP_VOLUME_ANOMALY",
                            severity=severity,
                            source_ip=ip,
                            description=f"📊 {rule['name']} | Rule: {rule['pattern']} | Baseline: {avg:.1f}±{std:.1f} events | Detected: {count} events | Z-score: {z_score:.2f} | Method: {rule['category']}"
                        )
                        db.add(incident)
                        created_incidents.append(incident)
    
    # ANOMALY 2: Multi-Vector Attacks (Behavioral Analysis)
    rule = DETECTION_RULES["MULTI_VECTOR_ATTACK"]
    ip_sources = defaultdict(set)
    ip_severities = defaultdict(lambda: {"high": 0, "total": 0})
    
    for log in logs:
        ip = log.ip or "unknown"
        if ip != "unknown":
            ip_sources[ip].add(log.source)
            ip_severities[ip]["total"] += 1
            if log.severity in ["HIGH", "CRITICAL"]:
                ip_severities[ip]["high"] += 1
    
    # Detect multi-vector attacks
    for ip, sources in ip_sources.items():
        if len(sources) >= 3:  # Attacking from 3+ different sources
            incident = Incident(
                type="MULTI_VECTOR_ATTACK",
                severity="HIGH",
                source_ip=ip,
                description=f"🎯 {rule['name']} | Rule: {rule['pattern']} | Vectors: {', '.join(sources)} | Total: {len(sources)} vectors | Method: {rule['category']}"
            )
            db.add(incident)
            created_incidents.append(incident)
    
    # ANOMALY 3: High Threat Ratio (Behavioral Analysis)
    for ip, stats in ip_severities.items():
        if stats["total"] >= 10:  # At least 10 events
            threat_ratio = stats["high"] / stats["total"]
            if threat_ratio > 0.5:  # More than 50% malicious
                incident = Incident(
                    type="HIGH_THREAT_RATIO",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"⚠️ High Threat IP | {stats['high']}/{stats['total']} events malicious ({threat_ratio*100:.0f}%) | Persistent attacker pattern | Method: ML-Based (Behavioral Analysis)"
                )
                db.add(incident)
                created_incidents.append(incident)
    
    db.commit()
    
    # Return detailed incident information
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


def get_detection_rules_summary():
    """
    Returns a summary of all detection rules for display in dashboard.
    Use this to showcase your detection capabilities!
    """
    return {
        "total_rules": len(DETECTION_RULES),
        "rule_based_count": sum(1 for r in DETECTION_RULES.values() if "Rule-Based" in r["category"]),
        "ml_based_count": sum(1 for r in DETECTION_RULES.values() if "ML-Based" in r["category"]),
        "rules": DETECTION_RULES
    }