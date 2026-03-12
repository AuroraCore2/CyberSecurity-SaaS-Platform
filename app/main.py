import os
from dotenv import load_dotenv
from fastapi import FastAPI

# Load environment variables from .env file if it exists
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dotenv_path = os.path.join(BASE_DIR, '.env')
if os.path.exists(dotenv_path):
    print(f"Loading environment from {dotenv_path}")
    load_dotenv(dotenv_path=dotenv_path)
else:
    print(f"No .env file found at {dotenv_path}")
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from app.api import logs, incidents, chat
from app.storage.database import Base, engine

# Create tables (safe on first run; existing tables are left untouched)
try:
    Base.metadata.create_all(bind=engine)
    print("Database tables created/verified successfully.")
except Exception as e:
    print(f"Warning: Database creation skipped: {e}")

# SQLite-only migration — skip on PostgreSQL
def _migrate_sqlite():
    """Only runs if using SQLite (local dev). Skipped on PostgreSQL (Railway)."""
    db_url = str(engine.url)
    if "sqlite" not in db_url:
        print("Skipping SQLite migration (non-SQLite database detected).")
        return

    import sqlalchemy
    try:
        with engine.connect() as conn:
            existing = {row[1] for row in conn.execute(sqlalchemy.text("PRAGMA table_info(log_events)"))}
            new_cols = {
                "status_code": "VARCHAR",
                "user_agent":  "TEXT",
                "bytes_sent":  "INTEGER",
                "method":      "VARCHAR",
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

# Mount routers
app.include_router(logs.router)
app.include_router(incidents.router)
app.include_router(chat.router)

# Resolve frontend path relative to this file
# Works locally, on Railway, and handles Vercel serverless environment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_PATH = os.path.join(BASE_DIR, "app", "frontend", "index.html")

# Root path for Vercel compatibility
@app.get("/api/health")
def health_check():
    return JSONResponse({"status": "ok", "engine": "Groq-Llama3"})

@app.get("/")
def read_root():
    if os.path.exists(FRONTEND_PATH):
        return FileResponse(FRONTEND_PATH)
    return JSONResponse({"status": "ThreatMind API is running"})

@app.get("/dashboard")
def read_dashboard():
    if os.path.exists(FRONTEND_PATH):
        return FileResponse(FRONTEND_PATH)
    return JSONResponse({"error": "Dashboard not found"}, status_code=404)