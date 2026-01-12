"""
Option 1: Token Passthrough - Target API
=========================================
This FastAPI app simulates a backend API that:
1. Receives the Authorization header (injected by Gateway Interceptor)
2. Validates the JWT token
3. Returns user-specific data

This would be your real backend API in production.
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import json
import base64
from datetime import datetime

app = FastAPI(
    title="Target API - Option 1 Demo",
    description="Backend API that validates user tokens from Gateway",
    version="1.0.0"
)

security = HTTPBearer()

# Mock data store (keyed by user email)
USER_DATA = {
    "john.doe@company.com": {
        "tasks": [
            {"id": 1, "title": "Review Q4 report", "status": "pending"},
            {"id": 2, "title": "Team meeting prep", "status": "completed"}
        ],
        "profile": {"department": "Engineering", "role": "Senior Engineer"}
    },
    "jane.smith@company.com": {
        "tasks": [
            {"id": 3, "title": "Client presentation", "status": "in_progress"}
        ],
        "profile": {"department": "Sales", "role": "Account Manager"}
    }
}


class Task(BaseModel):
    id: int
    title: str
    status: str


class UserProfile(BaseModel):
    email: str
    name: str
    department: str
    role: str


def decode_and_validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Decode JWT and extract user info."""
    token = credentials.credentials
    
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Check expiration (in production, also verify signature with JWKS)
        if payload.get("exp", 0) < datetime.now().timestamp():
            raise HTTPException(status_code=401, detail="Token expired")
        
        return payload
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/openapi.json")
async def get_openapi():
    return app.openapi()


@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    status: Optional[str] = None,
    user: dict = Depends(decode_and_validate_token)
):
    """Get tasks for the authenticated user."""
    email = user.get("email", "")
    user_data = USER_DATA.get(email, {"tasks": []})
    tasks = user_data.get("tasks", [])
    
    if status:
        tasks = [t for t in tasks if t["status"] == status]
    
    return tasks


@app.post("/tasks", response_model=Task)
async def create_task(
    title: str,
    user: dict = Depends(decode_and_validate_token)
):
    """Create a new task for the authenticated user."""
    email = user.get("email", "")
    
    if email not in USER_DATA:
        USER_DATA[email] = {"tasks": [], "profile": {}}
    
    new_id = max([t["id"] for t in USER_DATA[email]["tasks"]] + [0]) + 1
    new_task = {"id": new_id, "title": title, "status": "pending"}
    USER_DATA[email]["tasks"].append(new_task)
    
    return new_task


@app.get("/profile", response_model=UserProfile)
async def get_profile(user: dict = Depends(decode_and_validate_token)):
    """Get profile for the authenticated user."""
    email = user.get("email", "")
    user_data = USER_DATA.get(email, {"profile": {}})
    profile = user_data.get("profile", {})
    
    return UserProfile(
        email=email,
        name=user.get("name", "Unknown"),
        department=profile.get("department", "Unknown"),
        role=profile.get("role", "Unknown")
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
