from app.ingestion.parser import parse_security_logs
from app.ingestion.normalizer import normalize_events
from app.detection.rules import detect_bruteforce
from app.storage.memory import INCIDENT_DB

def process_log_file(raw_text: str):
    parsed = parse_security_logs(raw_text)
    normalized = normalize_events(parsed)
    incidents = detect_bruteforce(normalized)

    INCIDENT_DB.extend(incidents)
    return incidents