# Option 1: Token Passthrough - Architecture Deep Dive

## Overview

This document explains the complete authentication flow for **Option 1: Token Passthrough**, where a user's identity (JWT token) is propagated from a Streamlit frontend through AWS Bedrock AgentCore Runtime and Gateway to a backend Target API.

## Architecture Diagram

```
┌─────────────┐
│  Streamlit  │  User generates Okta JWT token
│   Frontend  │  Adds it as custom header via boto3 event system
│   (EKS)     │
└──────┬──────┘
       │ Header: X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken: <JWT>
       ↓
┌──────────────────────┐
│  AgentCore Runtime   │  Receives custom header (via allowlist)
│  (Managed Service)   │  Passes to agent via RequestContext
└──────────┬───────────┘
           │
           ↓
    ┌──────────┐
    │  Agent   │  Extracts user token from RequestContext
    │  Code    │  Connects to Gateway with MCP client
    └────┬─────┘  Headers:
         │          - Authorization: Bearer <agent-token>
         │          - X-Custom-UserToken: <JWT>
         ↓
┌─────────────────┐
│     Gateway     │  Configured with passRequestHeaders: true
│ (Managed Service)│  Invokes REQUEST interceptor with headers
└────────┬────────┘
         │
         ↓
  ┌──────────────────┐
  │   Interceptor    │  Extracts X-Custom-UserToken
  │     Lambda       │  Injects as Authorization header
  │  (REQUEST type)  │  Returns transformedGatewayRequest
  └────────┬─────────┘
           │
           ↓
  ┌─────────────────┐
  │    Gateway      │  Forwards request to Target API
  │  (continues)    │  Header: Authorization: Bearer <JWT>
  └────────┬────────┘
           │
           ↓
    ┌───────────┐
    │  Target   │  Validates JWT signature (production should use JWKS)
    │    API    │  Extracts user email from claims
    │ (FastAPI) │  Returns user-specific data
    └───────────┘
```

## Detailed Flow: Step-by-Step

### Step 1: User Authentication (Streamlit)

**File**: `streamlit/streamlit_app.py`

#### What Happens:
1. User enters email and name in Streamlit UI
2. Clicks "Generate Token" button
3. App generates a **mock Okta JWT** with user claims:
   ```json
   {
     "sub": "okta-john-1234",
     "email": "john.doe@company.com",
     "name": "John Doe",
     "groups": ["employees", "app-users"],
     "exp": 1234567890,
     "iss": "https://company.okta.com",
     "aud": "agentcore-demo"
   }
   ```

#### Production Note:
⚠️ In production, replace `generate_mock_okta_token()` with real Okta SDK authentication:
```javascript
// Example with okta-auth-js
const authClient = new OktaAuth({issuer, clientId});
const {idToken} = await authClient.token.getWithPopup();
```

---

### Step 2: Injecting Custom Header (Streamlit → Runtime)

**File**: `streamlit/streamlit_app.py`, function `invoke_agent_with_token()`

#### What Happens:
1. Streamlit calls AWS Bedrock AgentCore Runtime using boto3
2. **Problem**: boto3 doesn't support custom headers directly
3. **Solution**: Use boto3's event system to inject header BEFORE signing

#### Code Flow:
```python
# Create boto3 client
client = boto3.client("bedrock-agentcore", region_name=AWS_REGION)
event_system = client.meta.events

# Define handler to add custom header
def add_custom_header(request, **kwargs):
    request.headers.add_header(
        "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken",
        user_token
    )

# Register handler for "before-sign" event
EVENT_NAME = "before-sign.bedrock-agentcore.InvokeAgentRuntime"
event_system.register_first(EVENT_NAME, add_custom_header)

try:
    # Call API (header is automatically added before signing)
    response = client.invoke_agent_runtime(
        agentRuntimeArn=AGENT_RUNTIME_ARN,
        payload=json.dumps({"prompt": prompt}).encode()
    )
finally:
    # CRITICAL: Unregister to prevent memory leaks
    event_system.unregister(EVENT_NAME, handler)
```

#### Why This Works:
- AWS SigV4 signature is computed AFTER the "before-sign" event
- Custom header is included in the signed request
- AgentCore Runtime receives and validates the signature

#### AWS Documentation:
- [Runtime Header Allowlist](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)

---

### Step 3: Receiving Custom Header (Agent)

**File**: `agent/agent_code.py`, function `agent_invocation()`

#### What Happens:
1. AgentCore Runtime invokes the agent with `RequestContext`
2. Custom header is available in `context.request_headers`
3. **CRITICAL**: Agent must be deployed with header allowlist!

#### Deployment Requirement:
```bash
agentcore configure -e agent_code.py \
  --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"

agentcore deploy
```

#### Without Allowlist:
- Custom header is **DROPPED** by Runtime
- `context.request_headers` will NOT contain the token
- Authentication fails

#### Code Flow:
```python
@app.entrypoint
async def agent_invocation(payload: dict, context: RequestContext) -> dict:
    # Extract user token from request headers
    user_token = context.request_headers.get(
        "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
    )

    if not user_token:
        return {"error": "No user token", "hint": "Check allowlist"}

    # Decode token to get user info (no signature verification here)
    user_info = extract_user_info(user_token)
    # {"email": "john.doe@company.com", "name": "John Doe"}
```

---

### Step 4: Header Transformation (Agent → Gateway)

**File**: `agent/agent_code.py`, function `invoke_with_tools()`

#### What Happens:
The agent needs to pass the user token to Gateway, but:
- Runtime header name: `X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken`
- Gateway doesn't understand this header
- Need to **transform** it to a Gateway-compatible header

#### Transformation:
```
Runtime Header (from Streamlit):
  X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken: <JWT>
           ↓
Agent transforms to MCP Header (to Gateway):
  X-Custom-UserToken: <JWT>
```

#### Code Flow:
```python
async with streamablehttp_client(
    GATEWAY_URL,
    headers={
        # Agent's own identity (for Gateway access control)
        "Authorization": f"Bearer {gateway_auth_token}",

        # User's identity (for end-to-end propagation)
        "X-Custom-UserToken": user_token  # ← Interceptor reads this!
    }
) as (read, write, _):
    async with ClientSession(read, write) as session:
        # Connect to Gateway via MCP protocol
        await session.initialize()

        # Load tools from Gateway (e.g., get_tasks, get_profile)
        tools = await load_mcp_tools(session)
```

#### Two Tokens:
1. **Authorization**: Agent's token (proves agent can access Gateway)
2. **X-Custom-UserToken**: User's token (proves user's identity)

---

### Step 5: Gateway Intercepts Request

**File**: `interceptor/lambda_function.py`, function `lambda_handler()`

#### What Happens:
1. Gateway receives MCP request from agent
2. **CRITICAL**: Gateway must have `passRequestHeaders: true`
3. Gateway invokes REQUEST interceptor Lambda
4. Interceptor receives event with headers

#### Gateway Configuration:
```python
interceptorConfigurations=[{
    "interceptor": {"lambda": {"arn": "<lambda-arn>"}},
    "interceptionPoints": ["REQUEST"],
    "inputConfiguration": {
        "passRequestHeaders": True  # ← REQUIRED!
    }
}]
```

#### Without `passRequestHeaders: true`:
- Headers are **NOT** included in interceptor event
- `event["mcp"]["gatewayRequest"]["headers"]` is empty/missing
- Interceptor cannot access `X-Custom-UserToken`

#### Event Structure (AWS Documented):
```json
{
  "interceptorInputVersion": "1.0",
  "mcp": {
    "rawGatewayRequest": {
      "body": "<raw_request_body>"
    },
    "gatewayRequest": {
      "path": "/mcp",
      "httpMethod": "POST",
      "headers": {
        "Authorization": "Bearer <agent-token>",
        "X-Custom-UserToken": "<user-JWT>",  ← We need this!
        "Mcp-Session-Id": "<session-id>"
      },
      "body": {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "get_tasks"}
      }
    }
  }
}
```

---

### Step 6: Token Extraction and Injection (Interceptor)

**File**: `interceptor/lambda_function.py`

#### What Happens:
1. Interceptor extracts `X-Custom-UserToken` from headers
2. Decodes JWT payload for logging (optional)
3. **Injects** token as `Authorization` header
4. Returns `transformedGatewayRequest`

#### Code Flow:
```python
# Navigate to headers (AWS documented location)
mcp_data = event.get("mcp", {})
gateway_request = mcp_data.get("gatewayRequest", {})
request_headers = gateway_request.get("headers", {})

# Extract user token
user_token = request_headers.get("X-Custom-UserToken")

# Build transformed request with Authorization header
return {
    "interceptorOutputVersion": "1.0",
    "mcp": {
        "transformedGatewayRequest": {
            "headers": {
                "Authorization": f"Bearer {user_token}"  # ← Target API receives this!
            },
            "body": gateway_request.get("body", {})
        }
    }
}
```

#### Key Insight:
- Gateway forwards `transformedGatewayRequest.headers` to Target API
- Authorization header **replaces** the agent's Authorization header
- Target API now sees the **user's JWT**, not the agent's token!

---

### Step 7: JWT Validation (Target API)

**File**: `target-api/target_api.py`, function `decode_and_validate_token()`

#### What Happens:
1. FastAPI receives request with `Authorization: Bearer <user-JWT>`
2. HTTPBearer security scheme extracts the token
3. `decode_and_validate_token()` dependency runs
4. Token is validated and user claims extracted

#### Code Flow:
```python
def decode_and_validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token = credentials.credentials  # Extract JWT from "Bearer <token>"

    # Decode JWT payload (base64 decode the middle part)
    parts = token.split(".")
    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    # Check expiration
    if payload.get("exp", 0) < datetime.now().timestamp():
        raise HTTPException(status_code=401, detail="Token expired")

    return payload  # {"email": "john.doe@company.com", "name": "John Doe"}
```

#### Production Requirements:
⚠️ **This demo only checks expiration!** In production, you MUST:

1. **Verify Signature** using Okta's JWKS:
   ```python
   import jwt
   from jwt import PyJWKClient

   jwks_client = PyJWKClient("https://your-okta.com/oauth2/v1/keys")
   signing_key = jwks_client.get_signing_key_from_jwt(token)

   payload = jwt.decode(
       token,
       signing_key.key,
       algorithms=["RS256"],
       audience="your-app-id",
       issuer="https://your-okta.com"
   )
   ```

2. **Validate Claims**:
   - `iss` (issuer): Must match your Okta domain
   - `aud` (audience): Must match your application ID
   - `nbf` (not before): Check if present
   - `exp` (expiration): Verify not expired

3. **Consider Token Revocation**:
   - Cache tokens and check revocation lists
   - Implement refresh token flow

---

### Step 8: User-Specific Data Access

**File**: `target-api/target_api.py`, endpoints `/tasks`, `/profile`

#### What Happens:
1. Endpoint receives validated user claims
2. Extracts `email` from JWT payload
3. Returns data scoped to that specific user

#### Example - Get Tasks:
```python
@app.get("/tasks")
async def get_tasks(user: dict = Depends(decode_and_validate_token)):
    # Extract user email from validated JWT
    email = user.get("email", "")  # "john.doe@company.com"

    # Get user-specific data
    user_data = USER_DATA.get(email, {"tasks": []})
    tasks = user_data.get("tasks", [])

    return tasks  # Only john.doe's tasks!
```

#### Data Isolation:
- Each user only sees their own data
- User identity flows end-to-end from Streamlit to Target API
- No possibility of accessing another user's data

---

## Security Considerations

### 1. JWT Signature Verification

**Current**: Demo decodes JWT without verifying signature
**Production**: MUST verify signature using JWKS

**Why it matters**:
- Without verification, an attacker could forge tokens
- They could impersonate any user
- All authentication would be bypassed

**Fix**:
```python
# Install: pip install pyjwt[crypto] cryptography
import jwt
from jwt import PyJWKClient

# Verify with Okta's public keys
jwks_url = "https://your-okta-domain.com/oauth2/v1/keys"
jwks_client = PyJWKClient(jwks_url)
signing_key = jwks_client.get_signing_key_from_jwt(token)

payload = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="your-app-id",
    issuer="https://your-okta-domain.com"
)
```

### 2. Token Expiration

**Current**: Checked at Target API only
**Best practice**: Check at each hop

**Recommendations**:
- Agent should reject expired tokens early
- Set reasonable expiration times (1 hour typical)
- Implement refresh token flow for long sessions

### 3. Transport Security

**Current**: Relies on AWS infrastructure TLS
**Required**: HTTPS everywhere

**Ensure**:
- Streamlit → Runtime: HTTPS (AWS-managed)
- Agent → Gateway: HTTPS (AWS-managed)
- Gateway → Target API: HTTPS (configure in Gateway target)

### 4. Header Allowlist Security

**Current**: Single header allowed
**Best practice**: Minimal allowlist

**Why restrict**:
- Prevents header injection attacks
- Limits attack surface
- Enforces least privilege

**Configuration**:
```bash
# Only allow specific headers needed for auth
agentcore configure --request-header-allowlist \
  "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
```

### 5. Gateway Configuration

**Critical settings**:
```python
{
    "inputConfiguration": {
        "passRequestHeaders": True  # Required for this pattern
    }
}
```

**Security note**:
- Only enable `passRequestHeaders` when needed
- Interceptor should validate all headers
- Don't blindly forward all headers

---

## Troubleshooting

### Token Not Reaching Agent

**Symptom**: `context.request_headers` doesn't contain token

**Checks**:
1. Verify header allowlist in agent deployment:
   ```bash
   agentcore describe-agent-runtime --agent-runtime-arn <arn>
   # Look for: requestHeaderAllowlist
   ```

2. Verify Streamlit is sending header:
   ```python
   # Add logging in add_custom_header()
   logger.info(f"Adding header: {CUSTOM_TOKEN_HEADER}")
   ```

3. Verify header name matches exactly (case-sensitive)

### Token Not Reaching Interceptor

**Symptom**: `event["mcp"]["gatewayRequest"]["headers"]` empty

**Checks**:
1. Verify Gateway configuration:
   ```python
   # Must have:
   "inputConfiguration": {"passRequestHeaders": True}
   ```

2. Check CloudWatch logs for interceptor invocations

3. Verify agent is sending `X-Custom-UserToken` header:
   ```python
   # Add logging in agent
   logger.info(f"Sending headers: {list(headers.keys())}")
   ```

### Token Not Reaching Target API

**Symptom**: Target API returns 401 Unauthorized

**Checks**:
1. Verify interceptor is returning correct structure:
   ```json
   {
     "interceptorOutputVersion": "1.0",
     "mcp": {
       "transformedGatewayRequest": {
         "headers": {"Authorization": "Bearer <token>"}
       }
     }
   }
   ```

2. Check Target API logs for received headers

3. Test interceptor locally:
   ```bash
   cd interceptor
   python lambda_function.py  # Runs test event
   ```

### JWT Validation Fails

**Symptom**: "Token validation failed" error

**Checks**:
1. Token not expired: Check `exp` claim
2. Token format: Should be three base64 parts separated by dots
3. Payload decoding: Try manual decode:
   ```python
   import base64, json
   parts = token.split(".")
   payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
   print(payload)
   ```

---

## Performance Considerations

### Latency Breakdown

Typical request flow:
1. **Streamlit → Runtime**: ~50-100ms
2. **Runtime → Agent**: ~10-20ms
3. **Agent → Gateway (MCP)**: ~30-50ms
4. **Gateway → Interceptor**: ~20-30ms (cold start: +1-2s)
5. **Gateway → Target API**: ~20-40ms
6. **Total**: ~130-240ms (cold start: +1-2s)

### Optimization Tips

1. **Lambda Cold Starts** (Interceptor):
   - Use provisioned concurrency for critical paths
   - Keep Lambda lightweight (no heavy dependencies)
   - Consider Lambda SnapStart (Java only currently)

2. **MCP Session Reuse**:
   - Agent can reuse MCP connections for multiple requests
   - Implement connection pooling where possible

3. **Token Caching**:
   - Cache decoded JWT payloads (with expiration)
   - Avoid re-decoding on every request
   - Invalidate cache on token refresh

4. **Target API Optimization**:
   - Implement response caching for user data
   - Use database connection pooling
   - Consider read replicas for high traffic

---

## Testing

### Unit Tests

**Interceptor**:
```bash
cd interceptor
python lambda_function.py  # Runs built-in test
```

**Target API**:
```bash
cd target-api
pytest test_target_api.py  # If tests exist
```

### Integration Tests

**End-to-End Flow**:
1. Generate test JWT with known user
2. Call Streamlit endpoint directly
3. Verify response contains user-specific data
4. Check CloudWatch logs for each component

**Test Script**:
```python
import boto3
import json

client = boto3.client("bedrock-agentcore")

# Use test token
test_token = "eyJ..."  # Your test JWT

# Add token via event system
def add_test_header(request, **kwargs):
    request.headers.add_header(
        "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken",
        test_token
    )

event_system = client.meta.events
handler = event_system.register_first(
    "before-sign.bedrock-agentcore.InvokeAgentRuntime",
    add_test_header
)

try:
    response = client.invoke_agent_runtime(
        agentRuntimeArn=AGENT_ARN,
        payload=json.dumps({"prompt": "Get my tasks"}).encode()
    )

    print(response)
    assert "john.doe@company.com" in str(response)
finally:
    event_system.unregister(
        "before-sign.bedrock-agentcore.InvokeAgentRuntime",
        handler
    )
```

---

## AWS Documentation References

### AgentCore Runtime
- [Header Allowlist](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)
- [Invoke Agent Runtime API](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeAgentRuntime.html)

### Gateway
- [Interceptor Types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html)
- [Header Propagation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html)
- [Agent Integration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-agent-integration.html)

### General
- [MCP Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

## Summary

This architecture enables **end-user identity propagation** through a complex AgentCore stack by:

1. **Injecting** user JWT as custom header (Streamlit)
2. **Propagating** through Runtime via header allowlist (Agent)
3. **Transforming** header format for Gateway (Agent → MCP)
4. **Extracting** and re-injecting as Authorization (Interceptor)
5. **Validating** and using for data access (Target API)

The pattern preserves user identity end-to-end while leveraging AWS-managed services for orchestration, ensuring:
- ✅ User-specific data access
- ✅ Audit trail of user actions
- ✅ Per-user authorization
- ✅ Compliance with data isolation requirements
