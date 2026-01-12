# Option 2: Token Broker

**Centralized Credential Retrieval for Cross-Account Secrets**

## Overview

This pattern enables service-to-service authentication where the Gateway Interceptor calls a Token Broker service in a central account to retrieve service account credentials from Secrets Manager.

```
┌─────────────────────────────────┐      ┌─────────────────────────────────┐
│       Workload Account          │      │        Central Account          │
├─────────────────────────────────┤      ├─────────────────────────────────┤
│                                 │      │                                 │
│  ┌──────────────────────┐       │      │  ┌──────────────────────┐       │
│  │ Streamlit Application │       │      │  │  Token Broker Service │       │
│  │ (Running on EKS)      │       │      │  │  (Lambda or API GW)   │       │
│  └──────────┬───────────┘       │      │  └──────────┬───────────┘       │
│             │ Invokes Runtime    │      │             │ Calls             │
│             ▼                   │      │             ▼                   │
│  ┌──────────────────────┐       │      │  ┌──────────────────────┐       │
│  │  AgentCore Runtime    │       │      │  │   Secrets Manager    │       │
│  │                       │       │      │  │  (Service Credentials)│       │
│  └──────────┬───────────┘       │      │  └──────────────────────┘       │
│             │ Invokes Gateway   │      │                                 │
│             ▼                   │      │                                 │
│  ┌──────────────────────┐       │      │                                 │
│  │   AgentCore Gateway   │───────┼──────┼─► Calls Token Broker API       │
│  │  + Interceptor Lambda │       │      │                                 │
│  └──────────┬───────────┘       │      │                                 │
│             │ Authorization:    │      │                                 │
│             │ Bearer <svc-token>│      │                                 │
│             ▼                   │      │                                 │
│  ┌──────────────────────┐       │      │                                 │
│  │    OpenAPI Target     │       │      │                                 │
│  │ (Service-to-Service)  │       │      │                                 │
│  └──────────────────────┘       │      │                                 │
└─────────────────────────────────┘      └─────────────────────────────────┘
```

## Why Token Broker?

AgentCore credential providers only allow same-account Secrets Manager access. Cross-account secrets require an external Token Broker service.

## IAM Trust Chain (5-Hop)

```
EKS Pod Role → Runtime Execution Role → Gateway Service Role → Interceptor Lambda Role → Token Broker Role
```

### IAM Roles Required

| Role | Trust | Permissions |
|------|-------|-------------|
| EKS Pod Role (IRSA) | eks.amazonaws.com | bedrock-agentcore:InvokeAgentRuntime |
| Runtime Execution Role | bedrock-agentcore.amazonaws.com | bedrock-agentcore:InvokeGateway |
| Gateway Service Role | bedrock-agentcore.amazonaws.com | lambda:InvokeFunction |
| Interceptor Lambda Role | lambda.amazonaws.com | execute-api:Invoke, sts:AssumeRole |
| Token Broker Role | lambda.amazonaws.com | secretsmanager:GetSecretValue, kms:Decrypt |

## When to Use This Pattern

✅ **Use Token Broker when:**
- Cross-account secrets are required
- Service-to-service authentication needed
- Centralized credential rotation is desired
- User identity is NOT needed at target

❌ **Don't use when:**
- User identity must be preserved at target (use Option 1)
- Same-account secrets only (use AgentCore credential providers)
- Simple architecture is preferred

## Implementation Status

📋 **Planned** - This pattern is documented but not yet implemented.

## Planned Structure

```
option2-token-broker/
├── workload-account/
│   ├── streamlit/                # Frontend application
│   ├── agent/                    # AgentCore Runtime agent
│   ├── interceptor/              # Interceptor that calls Token Broker
│   └── target-api/               # Backend API (service auth)
├── central-account/
│   ├── token-broker/             # Lambda or API Gateway
│   └── secrets-manager/          # Terraform/CloudFormation for secrets
├── iam-roles/                    # Cross-account IAM roles
├── deploy.py                     # Multi-account deployment
└── README.md
```

## Key Differences from Option 1

| Aspect | Option 1 | Option 2 |
|--------|----------|----------|
| Token at Target | User's Okta JWT | Service account token |
| Interceptor Action | Pass through user token | Call Token Broker for service token |
| Secrets | None | Secrets Manager in central account |
| Cross-Account | No | Yes |
| User Identity | Preserved | Not preserved |
