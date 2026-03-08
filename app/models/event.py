from typing import Optional
from pydantic import BaseModel


class LogEvent(BaseModel):
    timestamp: str
    source: str
    event_type: str
    severity: str
    user: Optional[str] = None
    ip: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    raw: str