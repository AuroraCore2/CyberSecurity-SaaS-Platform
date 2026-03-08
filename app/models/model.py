from sqlalchemy import Column, Integer, String, Text
from app.storage.database import Base

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    source = Column(String)
    event_type = Column(String)
    severity = Column(String)
    user = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    action = Column(Text, nullable=True)
    resource = Column(Text, nullable=True)
    raw = Column(Text)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    severity = Column(String)
    source_ip = Column(String)
    description = Column(String)