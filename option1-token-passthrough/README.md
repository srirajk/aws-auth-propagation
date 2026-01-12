# Option 1: Token Passthrough - AgentCore Gateway Authentication

**Verified against AWS Documentation - January 2026**

## Overview

This pattern enables end-user identity propagation from a Streamlit frontend through AgentCore Runtime and Gateway to a backend Target API.

```
Streamlit (EKS) → AgentCore Runtime → Gateway → Interceptor Lambda → Target API
     │                    │              │              │              │
     │                    │              │              │              │
  Okta JWT ────────► Custom Header ──► MCP Header ──► Authorization ──► Validated
```

## Files

| Component | File | Purpose |
|-----------|------|---------|
| Streamlit | `streamlit/streamlit_app.py` | Frontend, boto3 header injection |
| Agent | `agent/agent_code.py` | AgentCore Runtime, MCP client |
| **Interceptor** | `interceptor/lambda_function.py` | **Token extraction (CORRECTED)** |
| Target API | `target-api/target_api.py` | Backend API, JWT validation |
| Deploy | `deploy.py` | Deployment script |
| Guide | `Option1-Token-Passthrough-Guide.docx` | Full documentation |

## Critical Configuration

### 1. Gateway Creation - passRequestHeaders MUST be true
```python
interceptorConfigurations=[{
    "interceptor": {"lambda": {"arn": "<lambda-arn>"}},
    "interceptionPoints": ["REQUEST"],
    "inputConfiguration": {"passRequestHeaders": True}  # CRITICAL
}]
```

### 2. Interceptor Lambda - CORRECT Event Structure
```python
# Headers are at event["mcp"]["gatewayRequest"]["headers"]
mcp_data = event.get("mcp", {})
gateway_request = mcp_data.get("gatewayRequest", {})
request_headers = gateway_request.get("headers", {})
```

### 3. Interceptor Lambda - CORRECT Response Structure
```python
return {
    "interceptorOutputVersion": "1.0",
    "mcp": {
        "transformedGatewayRequest": {
            "headers": {"Authorization": f"Bearer {user_token}"},
            "body": request_body
        }
    }
}
```

### 4. Agent Deployment - Header Allowlist Required
```bash
agentcore configure -e agent_code.py \
  --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
```

## Deployment

```bash
# 1. Deploy Target API to EKS/ECS

# 2. Deploy Interceptor Lambda
python deploy.py --action deploy-interceptor --region us-west-2

# 3. Create Gateway (via Console or boto3)

# 4. Deploy Agent to AgentCore Runtime
cd agent
agentcore configure -e agent_code.py --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
agentcore deploy

# 5. Deploy Streamlit to EKS
kubectl apply -f streamlit/k8s-deployment.yaml
```

## AWS Documentation

- [Runtime Headers](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)
- [Interceptor Types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html)
- [Header Propagation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html)
