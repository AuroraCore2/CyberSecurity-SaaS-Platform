from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    event_id: int
    # Let Pydantic parse the timestamp string into a datetime object.
    # This makes time‑window based detection (e.g. brute‑force within 5 minutes)
    # straightforward while still accepting various Windows date formats.
    timestamp: Optional[datetime]
    ip: str
    user: str
    raw: str