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
    """Decode JWT payload for user info (without verification)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"sub": "unknown", "email": "unknown", "name": "Unknown"}
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
    """Invoke agent with Gateway tools."""
    
    user_info = extract_user_info(user_token)
    app.logger.info(f"Processing request for: {user_info.get('email')}")
    
    model = ChatBedrock(model_id=BEDROCK_MODEL_ID, region_name=AWS_REGION)
    
    try:
        # Connect to Gateway with user's token as custom header
        async with streamablehttp_client(
            GATEWAY_URL,
            headers={
                "Authorization": f"Bearer {gateway_auth_token}",
                GATEWAY_TOKEN_HEADER: user_token  # Interceptor reads this
            }
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await load_mcp_tools(session)
                app.logger.info(f"Loaded {len(tools)} tools")
                
                model_with_tools = model.bind_tools(tools) if tools else model
                
                messages = [
                    SystemMessage(content=f"You are helping {user_info.get('name')} ({user_info.get('email')})."),
                    HumanMessage(content=prompt)
                ]
                
                response = await model_with_tools.ainvoke(messages)
                
                # Handle tool calls if any
                if hasattr(response, "tool_calls") and response.tool_calls:
                    for tool_call in response.tool_calls:
                        app.logger.info(f"Calling tool: {tool_call['name']}")
                        result = await session.call_tool(tool_call["name"], arguments=tool_call["args"])
                        app.logger.info(f"Tool result received")
                
                return response.content
                
    except Exception as e:
        app.logger.error(f"Error with tools: {e}")
        response = await model.ainvoke([
            SystemMessage(content=f"You are helping {user_info.get('name')}."),
            HumanMessage(content=prompt)
        ])
        return f"{response.content}\n\n(Note: Could not connect to tools)"


@app.entrypoint
async def agent_invocation(payload: dict, context: RequestContext) -> dict:
    """Main entrypoint for AgentCore Runtime."""
    
    app.logger.info("=" * 60)
    app.logger.info("AGENT INVOCATION")
    app.logger.info("=" * 60)
    
    # Get user token from custom header
    request_headers = context.request_headers
    app.logger.info(f"Headers received: {list(request_headers.keys())}")
    
    user_token = request_headers.get(CUSTOM_TOKEN_HEADER)
    if not user_token:
        return {"error": "No user token", "expected_header": CUSTOM_TOKEN_HEADER}
    
    user_info = extract_user_info(user_token)
    app.logger.info(f"User: {user_info.get('email')}")
    
    prompt = payload.get("prompt", "Hello")
    
    # Get Gateway auth token (from environment or AgentCore Identity)
    gateway_auth_token = os.environ.get("GATEWAY_AUTH_TOKEN", "")
    if not gateway_auth_token:
        try:
            from bedrock_agentcore.identity import get_workload_access_token
            gateway_auth_token = await get_workload_access_token()
        except Exception:
            gateway_auth_token = "demo-token"
    
    response = await invoke_with_tools(prompt, user_token, gateway_auth_token)
    
    return {
        "response": response,
        "user": user_info.get("email"),
        "session_id": context.session_id
    }


if __name__ == "__main__":
    app.run()
