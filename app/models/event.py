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
    # Extended fields for richer analytics
    status_code: Optional[str] = None   # HTTP status code (200, 403, 500 …)
    user_agent: Optional[str] = None    # Browser / bot UA string
    bytes_sent: Optional[int] = None    # Response size in bytes
    method: Optional[str] = None        # HTTP method (GET, POST …)