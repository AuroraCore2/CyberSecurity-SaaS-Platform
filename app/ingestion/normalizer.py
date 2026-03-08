from app.schemas.logs import SecurityEvent

def normalize_events(parsed_events):
    return [SecurityEvent(**e).dict() for e in parsed_events]