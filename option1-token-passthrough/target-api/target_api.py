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
    """
    Decode and validate the JWT token from the Authorization header.

    This token arrives via the complete authentication chain:
        1. Streamlit injected it as custom header
        2. AgentCore Runtime passed it to agent (via allowlist)
        3. Agent sent it to Gateway as MCP header
        4. Interceptor Lambda extracted it and injected as Authorization header
        5. Gateway forwarded it to this API

    ⚠️ PRODUCTION SECURITY REQUIREMENTS:
        This demo only checks expiration. In production, you MUST:
        1. Verify the JWT signature using Okta's JWKS endpoint
        2. Validate the issuer (iss) claim
        3. Validate the audience (aud) claim
        4. Check the not-before (nbf) claim if present
        5. Consider implementing token revocation checks

    Example production implementation with PyJWT:
        ```python
        import jwt
        from jwt import PyJWKClient

        jwks_client = PyJWKClient("https://your-okta-domain.com/oauth2/v1/keys")
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="your-app-id",
            issuer="https://your-okta-domain.com"
        )
        ```

    Args:
        credentials: HTTP Bearer credentials from request header

    Returns:
        dict: JWT payload with user claims

    Raises:
        HTTPException: 401 if token is invalid, expired, or malformed
    """
    token = credentials.credentials

    try:
        # JWT structure: header.payload.signature (all base64url encoded)
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Invalid token format")

        # Decode the payload (middle part)
        # Add padding if needed (base64 requires length to be multiple of 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Check expiration (DEMO: In production, verify signature first!)
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
    """
    Get tasks for the authenticated user.

    This demonstrates USER-SPECIFIC data access - each user only sees their own tasks.
    The user identity comes from the JWT token that traveled through the entire stack.

    Args:
        status: Optional filter by status (pending, in_progress, completed)
        user: User claims from validated JWT (injected by FastAPI dependency)

    Returns:
        List[Task]: User's tasks (filtered by status if provided)

    Example:
        When john.doe@company.com calls this endpoint, they only see their 2 tasks.
        When jane.smith@company.com calls it, they only see their 1 task.
    """
    # Extract user email from validated JWT claims
    email = user.get("email", "")

    # Get user-specific data from our mock database
    user_data = USER_DATA.get(email, {"tasks": []})
    tasks = user_data.get("tasks", [])

    # Apply status filter if provided
    if status:
        tasks = [t for t in tasks if t["status"] == status]

    return tasks


@app.post("/tasks", response_model=Task)
async def create_task(
    title: str,
    user: dict = Depends(decode_and_validate_token)
):
    """
    Create a new task for the authenticated user.

    Demonstrates user-scoped write operations - the task is created under
    the authenticated user's email, ensuring data isolation.

    Args:
        title: Task title
        user: User claims from validated JWT

    Returns:
        Task: The newly created task with auto-generated ID
    """
    email = user.get("email", "")

    # Initialize user data if this is a new user
    if email not in USER_DATA:
        USER_DATA[email] = {"tasks": [], "profile": {}}

    # Generate new task ID (max existing ID + 1)
    new_id = max([t["id"] for t in USER_DATA[email]["tasks"]] + [0]) + 1
    new_task = {"id": new_id, "title": title, "status": "pending"}

    # Add to user's task list
    USER_DATA[email]["tasks"].append(new_task)

    return new_task


@app.get("/profile", response_model=UserProfile)
async def get_profile(user: dict = Depends(decode_and_validate_token)):
    """
    Get profile for the authenticated user.

    Combines data from the JWT token (email, name) with application-specific
    profile data (department, role) to return complete user information.

    Args:
        user: User claims from validated JWT

    Returns:
        UserProfile: Complete user profile including both token and app data
    """
    email = user.get("email", "")
    user_data = USER_DATA.get(email, {"profile": {}})
    profile = user_data.get("profile", {})

    return UserProfile(
        email=email,  # From JWT token
        name=user.get("name", "Unknown"),  # From JWT token
        department=profile.get("department", "Unknown"),  # From app database
        role=profile.get("role", "Unknown")  # From app database
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
