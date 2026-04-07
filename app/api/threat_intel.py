from fastapi import APIRouter
from app.services.threat_intel import enrich_ip

router = APIRouter(
    prefix="/api/threat-intel",
    tags=["Threat Intelligence"]
)

@router.get("/ip/{ip}")
async def check_ip(ip: str):
    result = await enrich_ip(ip)
    return result
