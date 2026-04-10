import os
import httpx
from dotenv import load_dotenv

load_dotenv()  # reads your .env file

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")


async def check_ip_virustotal(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    if not VIRUSTOTAL_API_KEY:
        # Return mock data if key is missing
        return {
            "source": "VirusTotal",
            "ip": ip,
            "malicious": 8 if ip == "45.33.22.11" else (4 if ip == "91.108.4.177" else 0),
            "suspicious": 2,
            "harmless": 50,
            "country": "Mock Country",
        }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        if response.status_code != 200:
            return {"error": f"VirusTotal error: {response.status_code}"}

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "source": "VirusTotal",
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data["data"]["attributes"].get("country", "Unknown"),
        }


async def check_ip_abuseipdb(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    if not ABUSEIPDB_API_KEY:
        # Return mock data if key is missing
        abuse_score = 80 if ip == "45.33.22.11" else (45 if ip == "91.108.4.177" else 0)
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": abuse_score,
            "total_reports": 15,
            "country": "US",
            "isp": "Mock ISP",
            "last_reported": "2024-02-10",
        }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)

        if response.status_code != 200:
            return {"error": f"AbuseIPDB error: {response.status_code}"}

        d = response.json()["data"]

        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "last_reported": d.get("lastReportedAt", "Never"),
        }


async def enrich_ip(ip: str) -> dict:
    vt    = await check_ip_virustotal(ip)
    abuse = await check_ip_abuseipdb(ip)

    vt_score     = min(vt.get("malicious", 0) * 5, 50)
    abuse_score  = min(abuse.get("abuse_score", 0) // 2, 50)
    threat_score = vt_score + abuse_score

    return {
        "ip": ip,
        "threat_score": threat_score,
        "verdict": _verdict(threat_score),
        "virustotal": vt,
        "abuseipdb": abuse,
    }


def _verdict(score: int) -> str:
    res = ""
    if score >= 70:
        res = "Malicious"
    elif score >= 30:
        res = "Suspicious"
    else:
        res = "Clean"
    print(f"DEBUG: score={score} verdict={res}")
    return res