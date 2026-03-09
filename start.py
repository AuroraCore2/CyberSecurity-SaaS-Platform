#!/usr/bin/env python3
"""
Local Development Startup Script for ThreatMind

Run this to start the FastAPI server locally:
python start.py
"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    print("[SYSTEM] Starting ThreatMind Backend (Local Development)...")
    print("[API] http://127.0.0.1:8000")
    print("[DASHBOARD] http://127.0.0.1:8000/dashboard")
    print("[HEALTH] http://127.0.0.1:8000")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )