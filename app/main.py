from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import logs, incidents
from app.storage.database import Base, engine

# Create tables (safe on first run; existing tables are left untouched)
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Warning: Database creation skipped (Likely read-only environment): {e}")

# ── SQLite column migration (add new analytics columns to existing DBs) ────────
def _migrate_sqlite():
    """Add any missing columns to an existing log_events table so that uploads
    after a schema extension don't fail with 'table has no column' errors."""
    import sqlalchemy
    try:
        with engine.connect() as conn:
            existing = {row[1] for row in conn.execute(sqlalchemy.text("PRAGMA table_info(log_events)"))}
            new_cols = {
                "status_code":  "VARCHAR",
                "user_agent":   "TEXT",
                "bytes_sent":   "INTEGER",
                "method":       "VARCHAR",
            }
            for col, tipo in new_cols.items():
                if col not in existing:
                    conn.execute(sqlalchemy.text(f"ALTER TABLE log_events ADD COLUMN {col} {tipo}"))
                    print(f"Migration: added column '{col}' to log_events")
            conn.commit()
    except Exception as e:
        print(f"Migration warning (non-fatal): {e}")

_migrate_sqlite()


app = FastAPI(title="ThreatMind backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api import logs, incidents, chat

# Mount routers
app.include_router(logs.router)
app.include_router(incidents.router)
app.include_router(chat.router)

# Mount frontend directory for static assets
# Actually, since everything is in index.html, we just need to serve the file
@app.get("/")
def read_root():
    return FileResponse("app/frontend/index.html")

@app.get("/dashboard")
def read_dashboard():
    return FileResponse("app/frontend/index.html")