# Option 1: Token Passthrough

**User Okta Token Propagation via AgentCore Gateway**

**Verified against AWS Documentation - January 2026**

## Architecture

![Option 1: Token Passthrough Architecture](../images/option1-architecture.png)

## Overview

This pattern enables end-user identity propagation from a Streamlit frontend through AgentCore Runtime and Gateway to a backend Target API. The user's Okta JWT token flows end-to-end, allowing the Target API to authorize requests based on user identity.

## Token Flow

| Step | Component | Header | Value |
|------|-----------|--------|-------|
| 1 | Streamlit → Runtime | `X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken` | Okta JWT |
| 2 | Agent → Gateway | `X-Custom-UserToken` | Okta JWT |
| 3 | Interceptor → Target | `Authorization` | `Bearer <Okta JWT>` |

## Files

| Component | File | Purpose |
|-----------|------|---------|
| Streamlit | `streamlit/streamlit_app.py` | Frontend, boto3 header injection |
| Agent | `agent/agent_code.py` | AgentCore Runtime, MCP client |
| **Interceptor** | `interceptor/lambda_function.py` | Token extraction (**AWS-verified format**) |
| Target API | `target-api/target_api.py` | Backend API, JWT validation |
| Deploy | `deploy.py` | Deployment script |
| Guide | `Option1-Token-Passthrough-Guide.docx` | Full documentation |

## Critical Configuration

### 1. Gateway Creation - `passRequestHeaders` MUST be `true`

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

## IAM Trust Chain (3-Hop)

```
EKS Pod Role → Runtime Execution Role → Gateway Service Role → Target
```

| Role | Trust | Key Permission |
|------|-------|----------------|
| EKS Pod Role (IRSA) | `eks.amazonaws.com` | `bedrock-agentcore:InvokeAgentRuntime` |
| Runtime Execution Role | `bedrock-agentcore.amazonaws.com` | `bedrock-agentcore:InvokeGateway` |
| Gateway Service Role | `bedrock-agentcore.amazonaws.com` | `lambda:InvokeFunction` |

## Deployment

```bash
# 1. Deploy Target API to EKS/ECS

# 2. Deploy Interceptor Lambda
python deploy.py --action deploy-interceptor --region us-west-2

# 3. Create Gateway (via Console or boto3)

# 4. Deploy Agent to AgentCore Runtime
cd agent
agentcore configure -e agent_code.py \
  --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
agentcore deploy

# 5. Deploy Streamlit to EKS
kubectl apply -f streamlit/k8s-deployment.yaml
```

## Why This Pattern?

✅ User identity preserved at target  
✅ No secrets storage required  
✅ Per-user authorization possible  
✅ Simple architecture  

## AWS Documentation

- [Runtime Headers](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html)
- [Interceptor Types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html)
- [Header Propagation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html)
