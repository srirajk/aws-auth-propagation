"""
Option 1: Token Passthrough - AgentCore Runtime Agent
======================================================
This agent runs in AgentCore Runtime and:
1. Receives user's token from request headers (via RequestContext)
2. Passes the token to Gateway via MCP client headers
3. Uses Gateway tools to fulfill user requests

Deploy with:
    agentcore configure -e agent_code.py --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
    agentcore deploy
"""

import os
import json
import base64

from bedrock_agentcore import BedrockAgentCoreApp, RequestContext
from langchain_aws import ChatBedrock
from langchain_core.messages import HumanMessage, SystemMessage
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from langchain_mcp_adapters.tools import load_mcp_tools

# Configuration
GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://your-gateway.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp")
CUSTOM_TOKEN_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"
GATEWAY_TOKEN_HEADER = "X-Custom-UserToken"
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

app = BedrockAgentCoreApp()


def extract_user_info(token: str) -> dict:
    """
    Decode JWT payload for user info (without cryptographic verification).

    ⚠️ IMPORTANT: This decodes the JWT to read user claims, but does NOT verify
    the signature. This is acceptable here because:
        1. The token was already sent through HTTPS (transport security)
        2. It will be cryptographically validated by the Target API
        3. We only use it for logging and personalization in the agent

    In production, if you need to trust the token at the agent level,
    use a proper JWT library with JWKS validation.

    Args:
        token: JWT token string in format header.payload.signature

    Returns:
        dict: User claims (sub, email, name) or defaults if decode fails
    """
    try:
        # JWT structure: header.payload.signature (all base64url encoded)
        parts = token.split(".")
        if len(parts) != 3:
            return {"sub": "unknown", "email": "unknown", "name": "Unknown"}

        # Decode the payload (middle part)
        # Add padding if needed (base64 requires length to be multiple of 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        return {
            "sub": payload.get("sub", "unknown"),
            "email": payload.get("email", "unknown"),
            "name": payload.get("name", "Unknown")
        }
    except Exception as e:
        app.logger.warning(f"Failed to decode token: {e}")
        return {"sub": "unknown", "email": "unknown", "name": "Unknown"}


async def invoke_with_tools(prompt: str, user_token: str, gateway_auth_token: str) -> str:
    """
    Invoke Claude with Gateway MCP tools, passing user token for authentication.

    This is where the TOKEN TRANSFORMATION happens:
        Runtime header: X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken
               ↓
        Agent receives it, extracts user info
               ↓
        MCP header: X-Custom-UserToken (sent to Gateway)
               ↓
        Interceptor Lambda extracts it
               ↓
        Authorization: Bearer <token> (sent to Target API)

    Args:
        prompt: User's question/request
        user_token: JWT token from Streamlit (user's identity)
        gateway_auth_token: Agent's own auth token for Gateway access

    Returns:
        str: Claude's response (potentially using tool results)
    """

    user_info = extract_user_info(user_token)
    app.logger.info(f"Processing request for: {user_info.get('email')}")

    # Initialize Claude model
    model = ChatBedrock(model_id=BEDROCK_MODEL_ID, region_name=AWS_REGION)

    try:
        # Connect to Gateway with BOTH tokens:
        # 1. Authorization: Agent's token (for Gateway access control)
        # 2. X-Custom-UserToken: User's token (for end-to-end identity)
        async with streamablehttp_client(
            GATEWAY_URL,
            headers={
                "Authorization": f"Bearer {gateway_auth_token}",  # Agent identity
                GATEWAY_TOKEN_HEADER: user_token  # User identity (Interceptor reads this!)
            }
        ) as (read, write, _):
            # Establish MCP session with Gateway
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Load tools from Gateway (e.g., get_tasks, get_profile from Target API)
                tools = await load_mcp_tools(session)
                app.logger.info(f"Loaded {len(tools)} tools from Gateway")

                # Bind tools to Claude if available
                model_with_tools = model.bind_tools(tools) if tools else model

                # Build messages with user context
                messages = [
                    SystemMessage(content=f"You are helping {user_info.get('name')} ({user_info.get('email')})."),
                    HumanMessage(content=prompt)
                ]

                # Invoke Claude (may trigger tool calls)
                response = await model_with_tools.ainvoke(messages)

                # Handle tool calls if Claude decides to use them
                if hasattr(response, "tool_calls") and response.tool_calls:
                    for tool_call in response.tool_calls:
                        app.logger.info(f"Calling tool: {tool_call['name']}")
                        # Call tool through MCP session
                        # Gateway forwards to Target API with Authorization header
                        result = await session.call_tool(tool_call["name"], arguments=tool_call["args"])
                        app.logger.info(f"Tool result received")

                return response.content

    except Exception as e:
        app.logger.error(f"Error with tools: {e}")
        # Fallback: Invoke Claude without tools
        response = await model.ainvoke([
            SystemMessage(content=f"You are helping {user_info.get('name')}."),
            HumanMessage(content=prompt)
        ])
        return f"{response.content}\n\n(Note: Could not connect to tools)"


@app.entrypoint
async def agent_invocation(payload: dict, context: RequestContext) -> dict:
    """
    Main entrypoint for AgentCore Runtime.

    This function is called by AgentCore when Streamlit invokes the agent.

    CRITICAL DEPLOYMENT REQUIREMENT:
        This agent MUST be deployed with the header allowlist:

        agentcore configure -e agent_code.py \\
          --request-header-allowlist "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"

        Without the allowlist, the custom header will be DROPPED and won't
        appear in context.request_headers!

    Args:
        payload: dict from Streamlit's invoke call (contains "prompt")
        context: RequestContext with:
            - request_headers: dict of allowed custom headers
            - session_id: str for conversation continuity
            - identity: caller identity information

    Returns:
        dict: Response sent back to Streamlit
    """

    app.logger.info("=" * 60)
    app.logger.info("AGENT INVOCATION")
    app.logger.info("=" * 60)

    # Extract user token from request headers
    # This header was sent by Streamlit via boto3 event system
    # and passed through by AgentCore Runtime (because it's in the allowlist)
    request_headers = context.request_headers
    app.logger.info(f"Headers received: {list(request_headers.keys())}")

    user_token = request_headers.get(CUSTOM_TOKEN_HEADER)
    if not user_token:
        return {
            "error": "No user token found",
            "expected_header": CUSTOM_TOKEN_HEADER,
            "hint": "Ensure agent is deployed with --request-header-allowlist"
        }

    user_info = extract_user_info(user_token)
    app.logger.info(f"User: {user_info.get('email')}")

    # Extract prompt from payload
    prompt = payload.get("prompt", "Hello")

    # Get Gateway authentication token
    # Option 1: From environment variable (set during deployment)
    # Option 2: From AgentCore's workload identity (recommended for production)
    # Option 3: Fallback to demo token
    gateway_auth_token = os.environ.get("GATEWAY_AUTH_TOKEN", "")
    if not gateway_auth_token:
        try:
            # Get token from AgentCore's built-in identity service
            from bedrock_agentcore.identity import get_workload_access_token
            gateway_auth_token = await get_workload_access_token()
        except Exception:
            gateway_auth_token = "demo-token"

    # Call Claude with tools, passing both tokens
    response = await invoke_with_tools(prompt, user_token, gateway_auth_token)

    return {
        "response": response,
        "user": user_info.get("email"),
        "session_id": context.session_id
    }


if __name__ == "__main__":
    app.run()
