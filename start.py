#!/usr/bin/env python3
"""
Local Development Startup Script for InsightGuard

Run this to start the FastAPI server locally:
python start.py
"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    print("🚀 Starting InsightGuard Backend (Local Development)...")
    print("📍 API: http://127.0.0.1:8000")
    print("📊 Dashboard: http://127.0.0.1:8000/dashboard")
    print("🔍 Health Check: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )