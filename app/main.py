from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import logs, incidents
from app.storage.database import Base, engine

# Vercel is mostly a read-only environment for Python.
# Catch sqlite read-only errors on serverless spin-up.
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Warning: Database creation skipped (Likely read-only environment): {e}")

app = FastAPI(title="ThreatMind backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(incidents.router)

# Mount frontend directory for static assets
# Actually, since everything is in index.html, we just need to serve the file
@app.get("/")
def read_root():
    return FileResponse("app/frontend/index.html")

@app.get("/dashboard")
def read_dashboard():
    return FileResponse("app/frontend/index.html")