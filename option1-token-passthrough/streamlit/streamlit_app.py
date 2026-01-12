"""
Option 1: Token Passthrough - Streamlit Frontend
=================================================
This Streamlit app runs on EKS and:
1. Gets user's Okta token (simulated here, real app uses Okta SDK)
2. Calls AgentCore Runtime with the token as a custom header
3. Displays the agent's response

The custom header prefix X-Amzn-Bedrock-AgentCore-Runtime-Custom-* is
documented at:
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html
"""

import streamlit as st
import boto3
import json
import os
import base64
from datetime import datetime, timedelta

# Configuration
AGENT_RUNTIME_ARN = os.environ.get(
    "AGENT_RUNTIME_ARN",
    "arn:aws:bedrock-agentcore:us-west-2:123456789012:agent-runtime/your-agent-id"
)
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

# Custom header name (must start with X-Amzn-Bedrock-AgentCore-Runtime-Custom-)
CUSTOM_TOKEN_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken"

st.set_page_config(
    page_title="AgentCore Demo - Option 1",
    page_icon="🤖",
    layout="wide"
)

st.title("🤖 AgentCore Gateway Demo")
st.subheader("Option 1: Token Passthrough")


def generate_mock_okta_token(user_email: str, user_name: str) -> str:
    """
    Generate a mock Okta JWT token for demo purposes.
    In production, this would come from Okta SDK authentication.
    """
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "sub": f"okta-{user_email.split('@')[0]}-{hash(user_email) % 10000}",
        "email": user_email,
        "name": user_name,
        "groups": ["employees", "app-users"],
        "iat": int(datetime.now().timestamp()),
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),
        "iss": "https://company.okta.com",
        "aud": "agentcore-demo"
    }
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = "mock_signature_for_demo"
    
    return f"{header_b64}.{payload_b64}.{signature}"


def invoke_agent_with_token(prompt: str, user_token: str, session_id: str = None) -> dict:
    """
    Invoke AgentCore Runtime with user's token as custom header.
    
    Uses boto3 event system to inject the custom header before signing.
    This is the AWS-documented approach from:
    https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html
    """
    client = boto3.client("bedrock-agentcore", region_name=AWS_REGION)
    event_system = client.meta.events
    
    # Event handler to add custom header
    def add_custom_header(request, **kwargs):
        request.headers.add_header(CUSTOM_TOKEN_HEADER, user_token)
    
    # Register the handler
    EVENT_NAME = "before-sign.bedrock-agentcore.InvokeAgentRuntime"
    handler = event_system.register_first(EVENT_NAME, add_custom_header)
    
    try:
        payload = json.dumps({"prompt": prompt}).encode()
        
        invoke_params = {
            "agentRuntimeArn": AGENT_RUNTIME_ARN,
            "payload": payload
        }
        
        if session_id:
            invoke_params["runtimeSessionId"] = session_id
        
        response = client.invoke_agent_runtime(**invoke_params)
        
        # Read streaming response
        content_chunks = []
        for chunk in response.get("response", []):
            content_chunks.append(chunk.decode("utf-8"))
        
        result = json.loads("".join(content_chunks)) if content_chunks else {}
        
        return {
            "success": True,
            "response": result.get("response", str(result)),
            "session_id": response.get("runtimeSessionId"),
            "user": result.get("user")
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    finally:
        event_system.unregister(EVENT_NAME, handler)


# Sidebar - User Configuration
with st.sidebar:
    st.header("👤 User Settings")
    
    user_email = st.text_input("Email", value="john.doe@company.com")
    user_name = st.text_input("Name", value="John Doe")
    
    if st.button("🔐 Generate Token"):
        token = generate_mock_okta_token(user_email, user_name)
        st.session_state["user_token"] = token
        st.session_state["user_email"] = user_email
        st.session_state["user_name"] = user_name
        st.success("Token generated!")
    
    if "user_token" in st.session_state:
        st.success(f"✅ Logged in as: {st.session_state.get('user_name')}")
        with st.expander("View Token"):
            st.code(st.session_state["user_token"][:100] + "...", language="text")
    
    st.divider()
    st.header("⚙️ Configuration")
    st.text_input("Agent ARN", value=AGENT_RUNTIME_ARN, disabled=True)
    st.text_input("Region", value=AWS_REGION, disabled=True)

# Main Chat Interface
if "messages" not in st.session_state:
    st.session_state["messages"] = []

if "session_id" not in st.session_state:
    st.session_state["session_id"] = None

# Display chat history
for message in st.session_state["messages"]:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask me anything..."):
    if "user_token" not in st.session_state:
        st.error("Please generate a token first (sidebar)")
    else:
        # Add user message
        st.session_state["messages"].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                result = invoke_agent_with_token(
                    prompt=prompt,
                    user_token=st.session_state["user_token"],
                    session_id=st.session_state.get("session_id")
                )
                
                if result["success"]:
                    response = result["response"]
                    st.markdown(response)
                    st.session_state["messages"].append({"role": "assistant", "content": response})
                    
                    if result.get("session_id"):
                        st.session_state["session_id"] = result["session_id"]
                else:
                    error_msg = f"Error: {result['error']}"
                    st.error(error_msg)
                    st.session_state["messages"].append({"role": "assistant", "content": error_msg})

# Footer
st.divider()
col1, col2 = st.columns(2)
with col1:
    st.caption("Option 1: Token Passthrough Pattern")
with col2:
    if st.button("🗑️ Clear Chat"):
        st.session_state["messages"] = []
        st.session_state["session_id"] = None
        st.rerun()
