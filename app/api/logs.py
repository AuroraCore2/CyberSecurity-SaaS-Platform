from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from app.storage.database import get_db
from app.models.model import LogEvent
from app.detection.rules import run_detection
from app.ingestion.parser import parse_logs

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/upload")
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Ingest a raw log file, parse it into structured events, store them,
    then run rule‑based + ML anomaly detection.
    """
    print(f"Received file: {file.filename}, size: {len(await file.read())}")
    await file.seek(0)  # Reset file pointer
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    print(f"Decoded text length: {len(text)}")


    
    # Use the real multi‑format parser
    parsed_events = parse_logs(text)
    print(f"Parsed {len(parsed_events)} events")

    try:
        for event in parsed_events:
            db_event = LogEvent(
                timestamp=event.timestamp,
                source=event.source,
                event_type=event.event_type,
                severity=event.severity,
                user=event.user,
                ip=event.ip,
                action=event.action,
                resource=event.resource,
                raw=event.raw,
            )
            db.add(db_event)

        db.commit()
        print(f"Committed {len(parsed_events)} events to database")
    except Exception as e:
        print(f"Database error: {e}")
        db.rollback()
        return {"error": f"Database error: {str(e)}"}

    incidents = run_detection(db)
    print(f"Created {incidents} incidents")

    return {
        "message": "Logs stored successfully",
        "events_saved": len(parsed_events),
        "incidents_created": incidents,
    }


@router.get("/")
def get_logs(db: Session = Depends(get_db)):
    """
    Return the most recent 100 log events for the dashboard, along with total count.
    """
    try:
        # Get total count of all logs
        total_count = db.query(LogEvent).count()
        print(f"Total logs in database: {total_count}")

        # Get the most recent 100 logs for display
        logs = db.query(LogEvent).order_by(LogEvent.id.desc()).limit(100).all()
        print(f"Retrieved {len(logs)} logs from database")

        return {
            "total_events": total_count,
            "logs": [
                {
                    "id": log.id,
                    "timestamp": log.timestamp,
                    "source": log.source,
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "user": log.user,
                    "ip": log.ip,
                    "action": log.action,
                    "resource": log.resource,
                }
                for log in logs
            ]
        }
    except Exception as e:
        print(f"Error in get_logs: {e}")
        return {"error": f"Failed to retrieve logs: {str(e)}", "total_events": 0, "logs": []}