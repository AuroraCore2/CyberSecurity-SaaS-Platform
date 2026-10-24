"""
Vercel serverless entry point.
Vercel's @vercel/python runtime looks for an `app` variable in this file.
"""
from app.main import app  # noqa: F401
