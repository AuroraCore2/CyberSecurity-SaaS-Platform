from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from duckduckgo_search import DDGS

router = APIRouter(prefix="/api/chat", tags=["chat"])

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: Optional[str] = None
    messages: List[ChatMessage]
    system: Optional[str] = None
    max_tokens: Optional[int] = None

@router.post("")
async def handle_chat(request: ChatRequest):
    try:
        # Construct the conversation string
        conversation = ""
        if request.system:
            # Tell DDGS the persona
            conversation += f"System/Persona: {request.system}\n\n"
        
        for msg in request.messages:
            role_name = "User" if msg.role == "user" else "Assistant"
            conversation += f"{role_name}: {msg.content}\n"
            
        conversation += "Assistant:"

        # Call DuckDuckGo Chat (No API Key Required!)
        response = DDGS().chat(conversation, model="gpt-4o-mini")
        
        # Format response precisely how the frontend expects (like Anthropic payload)
        return {
            "content": [
                {
                    "text": response
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
