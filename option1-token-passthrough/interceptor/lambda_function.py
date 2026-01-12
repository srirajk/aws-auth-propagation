"""
Option 1: Token Passthrough - Gateway Interceptor Lambda
=========================================================
VERIFIED AGAINST AWS DOCUMENTATION (January 2026):
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html

Gateway Configuration Required:
- interceptionPoints: ["REQUEST"]
- inputConfiguration.passRequestHeaders: true  <-- CRITICAL

Key AWS Documented Behaviors:
1. Headers in gatewayRequest ONLY appear if passRequestHeaders=true
2. Authorization header CAN be injected by interceptor (bypasses restriction)
3. Response must include interceptorOutputVersion: "1.0"
4. Headers go in transformedGatewayRequest.headers
"""

import json
import logging
import base64
from typing import Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Header name we expect from the agent's MCP client call
INCOMING_TOKEN_HEADER = "X-Custom-UserToken"


def lambda_handler(event: dict, context) -> dict:
    """
    Gateway REQUEST Interceptor Lambda Handler.
    
    AWS DOCUMENTED Event Structure (when passRequestHeaders=true):
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
                "Accept": "application/json",
                "Authorization": "<bearer_token>",
                "X-Custom-UserToken": "<user_jwt>",
                "Mcp-Session-Id": "<session_id>"
            },
            "body": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "get_tasks", "arguments": {}}
            }
        }
      }
    }
    
    AWS DOCUMENTED Response Structure:
    {
      "interceptorOutputVersion": "1.0",
      "mcp": {
        "transformedGatewayRequest": {
            "headers": {
                "Authorization": "Bearer <user-token>"
            },
            "body": { ... }
        }
      }
    }
    """
    
    logger.info("=" * 60)
    logger.info("INTERCEPTOR LAMBDA INVOKED (REQUEST)")
    logger.info("=" * 60)
    
    input_version = event.get("interceptorInputVersion", "unknown")
    logger.info(f"Interceptor input version: {input_version}")
    
    # Navigate to correct location per AWS docs
    mcp_data = event.get("mcp", {})
    gateway_request = mcp_data.get("gatewayRequest", {})
    request_headers = gateway_request.get("headers", {})
    request_body = gateway_request.get("body", {})
    
    logger.info(f"Gateway request path: {gateway_request.get('path', 'N/A')}")
    logger.info(f"Received headers: {list(request_headers.keys())}")
    
    # Log MCP method if present
    if isinstance(request_body, dict):
        mcp_method = request_body.get("method", "unknown")
        logger.info(f"MCP method: {mcp_method}")
        if mcp_method == "tools/call":
            tool_name = request_body.get("params", {}).get("name", "unknown")
            logger.info(f"Tool being called: {tool_name}")
    
    # Extract user token (try multiple case variations)
    user_token = (
        request_headers.get(INCOMING_TOKEN_HEADER) or
        request_headers.get(INCOMING_TOKEN_HEADER.lower()) or
        request_headers.get("x-custom-usertoken")
    )
    
    if not user_token:
        logger.warning(f"No user token found in header: {INCOMING_TOKEN_HEADER}")
        logger.warning(f"Available headers: {list(request_headers.keys())}")
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayRequest": {
                    "body": request_body
                }
            }
        }
    
    logger.info(f"Found user token (first 50 chars): {user_token[:50]}...")
    
    # Optional: decode token for logging
    user_info = decode_jwt_payload_safe(user_token)
    if user_info:
        logger.info(f"User email: {user_info.get('email', 'unknown')}")
    
    # Build response with Authorization header
    # Per AWS docs: "Authorization header from interceptor lambda response 
    # is automatically propagated to the target"
    transformed_headers = {
        "Authorization": f"Bearer {user_token}"
    }
    
    logger.info("Injecting Authorization header for target")
    logger.info("=" * 60)
    
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "headers": transformed_headers,
                "body": request_body
            }
        }
    }


def decode_jwt_payload_safe(token: str) -> Optional[dict]:
    """Safely decode JWT payload (without verification) for logging."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as e:
        logger.warning(f"Could not decode JWT: {e}")
        return None


if __name__ == "__main__":
    # Test with AWS-documented event format
    test_event = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "rawGatewayRequest": {
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/call"}'
            },
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Bearer gateway-cognito-token",
                    "X-Custom-UserToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJva3RhLXVzZXItMTIzIiwiZW1haWwiOiJ1c2VyQGNvbXBhbnkuY29tIn0.sig",
                    "Mcp-Session-Id": "session-123"
                },
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "get_tasks", "arguments": {}}
                }
            }
        }
    }
    
    result = lambda_handler(test_event, None)
    print("\n" + "=" * 60)
    print("INTERCEPTOR RESULT:")
    print("=" * 60)
    print(json.dumps(result, indent=2))
    
    # Verify structure
    assert result["interceptorOutputVersion"] == "1.0"
    assert "mcp" in result
    assert "transformedGatewayRequest" in result["mcp"]
    print("\n✅ Output matches AWS documentation!")
