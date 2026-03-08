from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.storage.database import get_db
from app.models.model import Incident

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("/")
def get_incidents(db: Session = Depends(get_db)):
    """
    Return the most recent incidents (rule‑based + ML) from PostgreSQL.
    """
    incidents = db.query(Incident).order_by(Incident.id.desc()).limit(100).all()

    return [
        {
            "id": incident.id,
            "type": incident.type,
            "severity": incident.severity,
            "source_ip": incident.source_ip,
            "description": incident.description,
        }
        for incident in incidents
    ]