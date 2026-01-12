"""
Option 1: Token Passthrough - Deployment Script
=================================================
Deploys all components for the Option 1 demo.

Usage:
    python deploy.py --action deploy-all --region us-west-2
    python deploy.py --action deploy-interceptor --region us-west-2
    python deploy.py --action deploy-gateway --region us-west-2
    python deploy.py --action cleanup --region us-west-2
"""

import argparse
import boto3
import json
import os
import time
import zipfile
from pathlib import Path

# Configuration
class Config:
    REGION = "us-west-2"
    ACCOUNT_ID = None
    PROJECT_NAME = "option1-token-passthrough"
    INTERCEPTOR_LAMBDA_NAME = f"{PROJECT_NAME}-interceptor"
    GATEWAY_NAME = f"{PROJECT_NAME}-gateway"
    INTERCEPTOR_ROLE_NAME = f"{PROJECT_NAME}-interceptor-role"
    GATEWAY_ROLE_NAME = f"{PROJECT_NAME}-gateway-role"


def get_account_id():
    return boto3.client("sts").get_caller_identity()["Account"]


def create_interceptor_role(iam_client, config: Config) -> str:
    """Create IAM role for interceptor Lambda."""
    print("\n" + "=" * 60)
    print("Creating Interceptor Lambda Role")
    print("=" * 60)
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    try:
        response = iam_client.create_role(
            RoleName=config.INTERCEPTOR_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Option 1 Gateway Interceptor Lambda"
        )
        role_arn = response["Role"]["Arn"]
        print(f"✓ Created role: {config.INTERCEPTOR_ROLE_NAME}")
        
        iam_client.attach_role_policy(
            RoleName=config.INTERCEPTOR_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        print("✓ Attached Lambda execution policy")
        print("  Waiting for role to propagate...")
        time.sleep(10)
        return role_arn
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"  Role already exists: {config.INTERCEPTOR_ROLE_NAME}")
        return iam_client.get_role(RoleName=config.INTERCEPTOR_ROLE_NAME)["Role"]["Arn"]


def create_gateway_role(iam_client, config: Config) -> str:
    """Create IAM role for Gateway."""
    print("\n" + "=" * 60)
    print("Creating Gateway Service Role")
    print("=" * 60)
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": config.ACCOUNT_ID},
                "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{config.REGION}:{config.ACCOUNT_ID}:*"}
            }
        }]
    }
    
    try:
        response = iam_client.create_role(
            RoleName=config.GATEWAY_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for Option 1 Gateway"
        )
        role_arn = response["Role"]["Arn"]
        print(f"✓ Created role: {config.GATEWAY_ROLE_NAME}")
        
        # Add Lambda invoke permission
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": f"arn:aws:lambda:{config.REGION}:{config.ACCOUNT_ID}:function:{config.INTERCEPTOR_LAMBDA_NAME}"
            }]
        }
        
        iam_client.put_role_policy(
            RoleName=config.GATEWAY_ROLE_NAME,
            PolicyName="InvokeInterceptor",
            PolicyDocument=json.dumps(policy)
        )
        print("✓ Added Lambda invoke permission")
        time.sleep(10)
        return role_arn
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"  Role already exists: {config.GATEWAY_ROLE_NAME}")
        return iam_client.get_role(RoleName=config.GATEWAY_ROLE_NAME)["Role"]["Arn"]


def deploy_interceptor(lambda_client, config: Config, role_arn: str) -> str:
    """Deploy the interceptor Lambda."""
    print("\n" + "=" * 60)
    print("Deploying Interceptor Lambda")
    print("=" * 60)
    
    # Create deployment package
    zip_path = "/tmp/interceptor.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write("interceptor/lambda_function.py", "lambda_function.py")
    
    with open(zip_path, "rb") as f:
        zip_content = f.read()
    
    try:
        response = lambda_client.create_function(
            FunctionName=config.INTERCEPTOR_LAMBDA_NAME,
            Runtime="python3.11",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_content},
            Timeout=30,
            MemorySize=256,
            Description="Option 1 Gateway Interceptor - Token Passthrough"
        )
        lambda_arn = response["FunctionArn"]
        print(f"✓ Created Lambda: {config.INTERCEPTOR_LAMBDA_NAME}")
        print(f"  ARN: {lambda_arn}")
        
        # Wait for function to be active
        waiter = lambda_client.get_waiter("function_active")
        waiter.wait(FunctionName=config.INTERCEPTOR_LAMBDA_NAME)
        print("✓ Lambda is active")
        
        return lambda_arn
        
    except lambda_client.exceptions.ResourceConflictException:
        print(f"  Lambda exists, updating code...")
        lambda_client.update_function_code(
            FunctionName=config.INTERCEPTOR_LAMBDA_NAME,
            ZipFile=zip_content
        )
        response = lambda_client.get_function(FunctionName=config.INTERCEPTOR_LAMBDA_NAME)
        return response["Configuration"]["FunctionArn"]


def deploy_gateway(agentcore_client, config: Config, role_arn: str, 
                   interceptor_arn: str, cognito_config: dict, target_url: str) -> dict:
    """Deploy Gateway with CORRECT interceptor configuration."""
    print("\n" + "=" * 60)
    print("Deploying AgentCore Gateway")
    print("=" * 60)
    
    try:
        # CORRECT interceptor configuration per AWS docs
        response = agentcore_client.create_gateway(
            name=config.GATEWAY_NAME,
            roleArn=role_arn,
            protocolType="MCP",
            authorizerType="CUSTOM_JWT",
            authorizerConfiguration={
                "customJWTAuthorizer": {
                    "discoveryUrl": cognito_config["discovery_url"],
                    "allowedClients": [cognito_config["client_id"]]
                }
            },
            interceptorConfigurations=[
                {
                    "interceptor": {
                        "lambda": {
                            "arn": interceptor_arn
                        }
                    },
                    "interceptionPoints": ["REQUEST"],
                    "inputConfiguration": {
                        "passRequestHeaders": True  # CRITICAL for Option 1
                    }
                }
            ]
        )
        
        gateway_id = response["gatewayId"]
        gateway_url = response["gatewayUrl"]
        print(f"✓ Created Gateway: {gateway_id}")
        print(f"  URL: {gateway_url}")
        
        # Create target with header allowlist
        print("\nCreating Gateway Target...")
        agentcore_client.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=f"{config.PROJECT_NAME}-target",
            description="Target API for Option 1 demo",
            targetConfiguration={
                "openApi": {
                    "endpoint": target_url,
                    "specificationUri": f"{target_url}/openapi.json"
                }
            },
            metadataConfiguration={
                "allowedRequestHeaders": ["X-Custom-UserToken"]
            }
        )
        print("✓ Created Target")
        
        return {"gateway_id": gateway_id, "gateway_url": gateway_url}
        
    except Exception as e:
        print(f"  Error: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Deploy Option 1 Token Passthrough")
    parser.add_argument("--action", required=True, 
                       choices=["deploy-all", "deploy-interceptor", "deploy-gateway", "cleanup"])
    parser.add_argument("--region", default="us-west-2")
    args = parser.parse_args()
    
    config = Config()
    config.REGION = args.region
    config.ACCOUNT_ID = get_account_id()
    
    print(f"Account: {config.ACCOUNT_ID}")
    print(f"Region: {config.REGION}")
    
    iam_client = boto3.client("iam")
    lambda_client = boto3.client("lambda", region_name=config.REGION)
    
    if args.action == "deploy-interceptor":
        role_arn = create_interceptor_role(iam_client, config)
        deploy_interceptor(lambda_client, config, role_arn)
        
    elif args.action == "deploy-all":
        print("\n🚀 Starting full deployment...")
        interceptor_role = create_interceptor_role(iam_client, config)
        interceptor_arn = deploy_interceptor(lambda_client, config, interceptor_role)
        gateway_role = create_gateway_role(iam_client, config)
        print("\n✅ Deployment complete!")
        print(f"   Interceptor ARN: {interceptor_arn}")
        
    elif args.action == "cleanup":
        print("\n🧹 Cleanup not implemented - use AWS Console")


if __name__ == "__main__":
    main()
