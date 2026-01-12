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

    ⚠️ DEMO ONLY: In production, replace this with real Okta authentication:
        1. Use Okta SDK to authenticate user (okta-auth-js or similar)
        2. Receive signed JWT from Okta
        3. Pass that token to invoke_agent_with_token()

    This function creates an unsigned JWT with realistic structure:
        - Header: Contains algorithm and type
        - Payload: User claims (email, name, groups, expiration)
        - Signature: Mock signature (NOT CRYPTOGRAPHICALLY VALID)

    Args:
        user_email: User's email address
        user_name: User's full name

    Returns:
        String in JWT format: base64(header).base64(payload).signature
    """
    # JWT header - declares this is an RS256-signed token
    header = {"alg": "RS256", "typ": "JWT"}

    # JWT payload - user identity and claims
    payload = {
        "sub": f"okta-{user_email.split('@')[0]}-{hash(user_email) % 10000}",  # Subject (user ID)
        "email": user_email,
        "name": user_name,
        "groups": ["employees", "app-users"],  # User's groups/roles
        "iat": int(datetime.now().timestamp()),  # Issued at
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),  # Expires in 1 hour
        "iss": "https://company.okta.com",  # Issuer (your Okta domain)
        "aud": "agentcore-demo"  # Audience (your application)
    }

    # Encode to base64url (JWT standard)
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = "mock_signature_for_demo"  # NOT CRYPTOGRAPHICALLY VALID

    return f"{header_b64}.{payload_b64}.{signature}"


def invoke_agent_with_token(prompt: str, user_token: str, session_id: str = None) -> dict:
    """
    Invoke AgentCore Runtime with user's token as custom header.

    Uses boto3 event system to inject the custom header before signing.
    This is the AWS-documented approach from:
    https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-header-allowlist.html

    Args:
        prompt: User's question/request
        user_token: JWT token from Okta (or other IdP)
        session_id: Optional session ID for conversation continuity

    Returns:
        dict with:
            - success: bool indicating if call succeeded
            - response: Agent's response text
            - session_id: Session ID for follow-up calls
            - user: User email extracted from token

    Flow:
        1. Create boto3 client for bedrock-agentcore service
        2. Register event handler to inject custom header BEFORE request is signed
        3. Call InvokeAgentRuntime API
        4. Unregister handler (cleanup)

    Why boto3 event system?
        - Custom headers must be added BEFORE AWS SigV4 signing
        - Direct header addition won't work (signature mismatch)
        - Event system hooks into request lifecycle at correct point
    """
    client = boto3.client("bedrock-agentcore", region_name=AWS_REGION)
    event_system = client.meta.events

    # Event handler to add custom header
    # This runs BEFORE the request is signed with AWS credentials
    def add_custom_header(request, **kwargs):
        # Add our custom header with the user's JWT token
        # Header name MUST start with "X-Amzn-Bedrock-AgentCore-Runtime-Custom-"
        request.headers.add_header(CUSTOM_TOKEN_HEADER, user_token)

    # Register the handler for the "before-sign" event
    # "register_first" ensures this runs before any other handlers
    EVENT_NAME = "before-sign.bedrock-agentcore.InvokeAgentRuntime"
    handler = event_system.register_first(EVENT_NAME, add_custom_header)
    
    try:
        # Prepare the payload as JSON bytes
        payload = json.dumps({"prompt": prompt}).encode()

        # Build invoke parameters
        invoke_params = {
            "agentRuntimeArn": AGENT_RUNTIME_ARN,
            "payload": payload
        }

        # Include session ID for conversation continuity if provided
        if session_id:
            invoke_params["runtimeSessionId"] = session_id

        # Call the AgentCore Runtime API
        # Our custom header is automatically included via the event handler above
        response = client.invoke_agent_runtime(**invoke_params)

        # Read streaming response
        # AgentCore returns response as an iterator of chunks
        content_chunks = []
        for chunk in response.get("response", []):
            content_chunks.append(chunk.decode("utf-8"))

        # Parse the complete response
        result = json.loads("".join(content_chunks)) if content_chunks else {}

        return {
            "success": True,
            "response": result.get("response", str(result)),
            "session_id": response.get("runtimeSessionId"),
            "user": result.get("user")  # User email from agent's response
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    finally:
        # CRITICAL: Always unregister the handler to prevent memory leaks
        # and avoid affecting subsequent API calls
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
