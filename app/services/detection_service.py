from app.ingestion.parser import parse_security_logs
from app.ingestion.normalizer import normalize_events
from app.detection.rules import run_detection
from app.storage.memory import INCIDENT_DB

def process_log_file(raw_text: str):
    parsed = parse_security_logs(raw_text)
    normalized = normalize_events(parsed)
    incidents = run_detection(normalized)  # This would need a DB session

    INCIDENT_DB.extend(incidents)
    return incidents