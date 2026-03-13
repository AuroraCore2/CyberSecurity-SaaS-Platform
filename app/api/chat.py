import os
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

# Router without prefix so we can define /chat and /oracle
router = APIRouter(tags=["AI"])

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def get_groq_key():
    key = os.getenv("GROQ_API_KEY")
    if not key:
        print("GROQ_API_KEY not found in os.getenv, trying load_dotenv...")
        from dotenv import load_dotenv
        env_path = os.path.join(os.path.dirname(__file__), '../../.env')
        load_dotenv(env_path)
        key = os.getenv("GROQ_API_KEY")
    
    if key:
        print(f"GROQ_API_KEY found: {key[:6]}...{key[-4:]}")
    else:
        print("GROQ_API_KEY is completely missing from environment and .env")
    return key

class SimpleChatRequest(BaseModel):
    message: str

class OracleRequest(BaseModel):
    incident: str

@router.post("/chat")
async def handle_chat(request: SimpleChatRequest):
    """
    Groq AI Chatbot endpoint.
    Uses llama3-8b-8192.
    """
    api_key = get_groq_key()
    if not api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY is missing. Please check your .env file or environment variables.")

    system_prompt = "You are ORACLE, an elite cybersecurity assistant. Explain everything simply so even non-experts can understand. Use '>>' for list items and actionable steps."
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": request.message}
        ]
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(GROQ_URL, json=payload, headers=headers, timeout=30.0)
            if response.status_code != 200:
                print(f"Groq API Error Status: {response.status_code}")
                print(f"Groq API Error Body: {response.text}")
                raise HTTPException(status_code=response.status_code, detail=f"Groq AI error: {response.text}")
            
            data = response.json()
            reply = data["choices"][0]["message"]["content"]
            
            # Compatibility with existing frontend (expects content array)
            return {
                "content": [{"text": reply}]
            }
    except httpx.HTTPError as e:
        print(f"HTTP connection error: {e}")
        raise HTTPException(status_code=503, detail=f"Connection to AI service failed: {str(e)}")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        raise HTTPException(status_code=500, detail=f"AI model error: {str(e)}")

@router.post("/oracle")
async def handle_oracle(request: OracleRequest):
    """
    Oracle Explain endpoint.
    Returns specific format: Incident Type, Severity, Explanation, Possible Cause, Recommended Fix.
    """
    api_key = get_groq_key()
    if not api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY is missing. Please check your .env file or environment variables.")

    system_prompt = (
        "You are ORACLE, an elite cybersecurity AI. Analyze incidents clearly, keeping output formatted exactly like a terminal output.\n"
        "CRITICAL: You MUST structure your response EXACTLY using these three section headers in ALL CAPS, wrapped in brackets:\n\n"
        "[ANALYSIS]\n<Provide a clear, brief technical explanation of the attack vector, source, and potential impact>\n\n"
        "[MITIGATION]\n<Provide 1-3 actionable remediation steps. MUST prefix each step with  >> >\n\n"
        "[VERDICT]\n<Provide a definitive conclusion, e.g., THREAT_CONFIRMED: ACTIVE_RECONNAISSANCE or THREAT_MITIGATED>"
    )
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this incident: {request.incident}"}
        ]
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(GROQ_URL, json=payload, headers=headers, timeout=30.0)
            if response.status_code != 200:
                print(f"Groq Oracle Error Status: {response.status_code}")
                print(f"Groq Oracle Error Body: {response.text}")
                raise HTTPException(status_code=response.status_code, detail=f"Groq Oracle error: {response.text}")

            data = response.json()
            reply = data["choices"][0]["message"]["content"]
            
            return {
                "content": [{"text": reply}]
            }
    except httpx.HTTPError as e:
        print(f"HTTP connection error: {e}")
        raise HTTPException(status_code=503, detail=f"Connection to AI service failed: {str(e)}")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        raise HTTPException(status_code=500, detail=f"Oracle engine error: {str(e)}")
