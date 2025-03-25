# Multi-Tenant Custom Domain Architecture

## Project Overview

This project implements a multi-tenant architecture using AWS services where different custom domains (e.g., `gallery.devopsify.shop`, `photos.devopsify.shop`) map to different tenant workspaces. The system uses a Lambda authorizer to extract the domain from the Host header, look up the associated workspace ID in DynamoDB, and pass it to an Amplify app via a custom header.

## Component Architecture

### System Flow Diagram

```
┌─────────────┐           ┌───────────────┐           ┌─────────────────┐           ┌───────────────┐
│  User       │           │  API Gateway  │           │  Lambda         │           │  DynamoDB     │
│  Request    │─────────▶│  HTTP API     │─────────▶│  Authorizer     │─────────▶│  Table        │
│  (Custom    │           │  (6h8u9qeur2) │           │  Function       │           │               │
│   Domain)   │           └───────────────┘           └─────────────────┘           └───────────────┘
└─────────────┘                  │                            │                            │
                                │                            │                            │
                                │                            │                            │
                                │                            │                            │
                                ▼                            │                            │
                        ┌───────────────┐                    │                            │
                        │  Proxy        │                    │                            │
                        │  Integration  │◀───────────────────┘                            │
                        │  to Amplify   │◀───────────────────────────────────────────────┘
                        └───────────────┘
                                │
                                │
                                ▼
                        ┌───────────────┐
                        │  Amplify App  │
                        │  Response     │
                        └───────────────┘
```

## Resource Details

### API Gateway HTTP API

- **API ID**: `6h8u9qeur2`
- **API Name**: `DomainBasedRoutingHTTPAPI`
- **Endpoint**: `https://6h8u9qeur2.execute-api.us-east-1.amazonaws.com`
- **API Key Source**: Header (`x-api-key`)
- **API ARN**: `arn:aws:apigateway:us-east-1::/apis/6h8u9qeur2`

#### CORS Configuration
```json
{
  "AllowOrigins": "*",
  "AllowHeaders": ["x-workspace-id", "content-type", "authorization"],
  "AllowMethods": "*",
  "AllowCredentials": true,
  "MaxAge": 0
}
```
Note: MaxAge of 0 is ideal for development. For production, 86400 (24 hours) is recommended.

#### Routes

- **Route Key**: `ANY /{proxy+}`
- **Route ID**: `l4xvqz3`
- **Integration ID**: `8g8twjk`
- **Authorizer ID**: `rqn8ic`

### Lambda Authorizer

- **Function Name**: `HttpDomainAuthorizerPython`
- **Function ARN**: `arn:aws:lambda:us-east-1:590183815265:function:HttpDomainAuthorizerPython`
- **Runtime**: Python 3.13
- **Handler**: `http_domain_authorizer.lambda_handler`
- **Timeout**: 3 seconds
- **Memory**: 128 MB
- **IAM Role**: `DomainAuthorizerPython-role-vmxqf86k`
- **IAM Role ARN**: `arn:aws:iam::590183815265:role/service-role/DomainAuthorizerPython-role-vmxqf86k`

#### Lambda Source Code (`http_domain_authorizer.py`)

```python
import json
import boto3
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('domain-workspace-mappings')

def lambda_handler(event, context):
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Extract domain from Host header
    headers = event.get('headers', {})
    
    # First try to get from the custom Host header
    domain = None
    if headers:
        # Try the Host header first (case sensitive)
        if 'Host' in headers:
            domain = headers['Host']
        # Then try host (case insensitive)
        elif 'host' in headers:
            domain = headers['host']
            
        # For testing in API Gateway console, check if we're using a custom header
        if 'Host' in headers and headers['Host'] != event.get('requestContext', {}).get('domainName'):
            domain = headers['Host']
            logger.info(f"Using custom Host header: {domain}")
    
    # If no domain found in headers, try the request context
    if not domain:
        domain = event.get('requestContext', {}).get('domainName')
        logger.info(f"Using domain from request context: {domain}")
    
    try:
        # Extract domain from Host header
        domain = event.get('headers', {}).get('host')
        logger.info(f"Domain from request: {domain}")
        
        # Add detailed logging for troubleshooting
        logger.info(f"Full event: {json.dumps(event)}")
        
        # If no domain found, deny access
        if not domain:
            logger.error("No domain found in request")
            return {
                "isAuthorized": False,
                "context": {
                    "error": "No domain found in request"
                }
            }
        
        # Look up the domain in DynamoDB
        logger.info(f"Looking up domain in DynamoDB: {domain}")
        response = table.get_item(
            Key={
                'domain': domain
            }
        )
        logger.info(f"DynamoDB response: {json.dumps(response)}")
        
        # Check if the domain exists in the table
        if 'Item' in response:
            workspace_id = response['Item']['workspaceId']
            logger.info(f"Found workspace ID: {workspace_id} for domain: {domain}")
            
            # For HTTP API, return a simple response with isAuthorized and context
            return {
                "isAuthorized": True,
                "context": {
                    "workspaceId": workspace_id
                }
            }
        else:
            logger.error(f"Domain not found in table: {domain}")
            return {
                "isAuthorized": False,
                "context": {
                    "error": f"Domain not found: {domain}"
                }
            }
    
    except Exception as e:
        logger.error(f"Error looking up domain: {str(e)}")
        return {
            "isAuthorized": False,
            "context": {
                "error": f"Error: {str(e)}"
            }
        }
```

### Amplify Application

- **App Directory**: `ve_domain_test`
- **Deployment Method**: Continuous deployment (auto-deploys on git push)
- **App URL**: `https://main.d2jo2hz8i0qz1a.amplifyapp.com`

The application deployed to Amplify is contained in the `ve_domain_test` directory. This application is configured for automatic deployment whenever changes are pushed to the connected Git repository.

### API Integrations

- **Integration ID**: `8g8twjk`
- **Integration Type**: HTTP_PROXY
- **Integration URI**: `https://main.d2jo2hz8i0qz1a.amplifyapp.com/{proxy}`
- **Integration Method**: ANY
- **Timeout**: 30000 ms (30 seconds)

#### Parameter Mappings
```
Parameter: header.x-Workspace-Id
Value: $context.authorizer.workspaceId
```

### IAM Role and Policies

#### Role Details
- **Role Name**: `DomainAuthorizerPython-role-vmxqf86k`
- **Role ARN**: `arn:aws:iam::590183815265:role/service-role/DomainAuthorizerPython-role-vmxqf86k`
- **Path**: `/service-role/`

#### Attached Policies
1. **CloudWatchLogsFullAccess**
   - **Policy ARN**: `arn:aws:iam::aws:policy/CloudWatchLogsFullAccess`

2. **AmazonDynamoDBReadOnlyAccess**
   - **Policy ARN**: `arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess`

3. **AWSLambdaBasicExecutionRole**
   - **Policy ARN**: `arn:aws:iam::590183815265:policy/service-role/AWSLambdaBasicExecutionRole-77bcfe3a-5dfd-4b43-868e-f36868d25c13`

### DynamoDB Table

- **Table Name**: `domain-workspace-mappings`
- **Table ARN**: `arn:aws:dynamodb:us-east-1:590183815265:table/domain-workspace-mappings`
- **Billing Mode**: PAY_PER_REQUEST
- **Primary Key**: `domain` (String)

#### Sample Items

```json
[
  {
    "domain": "gallery.devopsify.shop",
    "workspaceId": "workspace-1",
    "status": "active",
    "createdAt": "2025-03-14T12:00:00Z"
  },
  {
    "domain": "photos.devopsify.shop",
    "workspaceId": "workspace-2",
    "status": "active",
    "createdAt": "2025-03-14T12:00:00Z"
  },
  {
    "domain": "studio.devopsify.shop",
    "workspaceId": "workspace-3",
    "status": "active",
    "createdAt": "2025-03-14T12:00:00Z"
  }
]
```

### Custom Domains

#### Gallery Domain
- **Domain Name**: `gallery.devopsify.shop`
- **Domain Type**: REGIONAL
- **Certificate ARN**: `arn:aws:acm:us-east-1:590183815265:certificate/52bba28a-b4b8-4df4-bb34-bb6f33e743dd`
- **API Mapping ID**: `biqish`
- **API ID**: `6h8u9qeur2`
- **Stage**: `$default`

#### Photos Domain
- **Domain Name**: `photos.devopsify.shop`
- **Domain Type**: REGIONAL
- **Certificate ARN**: `arn:aws:acm:us-east-1:590183815265:certificate/52bba28a-b4b8-4df4-bb34-bb6f33e743dd`
- **API Mapping ID**: `5mu77k`
- **API ID**: `6h8u9qeur2`
- **Stage**: `$default`

## System Flow Explanation

### 1. Request Initiation
A user makes a request to a custom domain (e.g., `gallery.devopsify.shop/home`). The request includes a `Host` header with the domain name.

### 2. Authorization Flow
1. The API Gateway receives the request and invokes the Lambda authorizer
2. The Lambda extracts the domain from the `Host` header
3. The Lambda queries the DynamoDB table to find the workspace ID
4. If found, it returns `isAuthorized: true` with the workspace ID in the context
5. If not found, it returns `isAuthorized: false` with an error message

### 3. Integration and Request Forwarding
1. For authorized requests, API Gateway adds the workspace ID as `x-Workspace-Id` header
2. The entire request (with the added header) is forwarded to the Amplify app
3. The path from the original request is preserved in the proxy integration

### 4. CORS Handling
1. For cross-origin requests, the browser first sends a preflight OPTIONS request
2. API Gateway automatically responds with the configured CORS headers
3. The actual request is then sent and processed as described above

### 5. Response Flow
1. The Amplify app processes the request using the workspace ID for tenant isolation
2. The response is sent back through API Gateway to the original requester

## Key Implementation Decisions

1. **HTTP API vs REST API**: HTTP API was chosen for better performance and simpler CORS handling
2. **Lambda Authorizer**: Provides flexibility to lookup domain-to-workspace mappings in DynamoDB
3. **DynamoDB**: Simple key-value store for efficient domain lookups
4. **Custom Headers**: Using `x-Workspace-Id` allows the Amplify app to maintain tenant isolation
5. **Proxy Integration**: Simplifies routing by passing all request paths directly to the backend

## Troubleshooting Guidelines

### Common Issues and Solutions

1. **Authorization Failures**:
   - Check CloudWatch logs for the Lambda authorizer
   - Verify the domain exists in the DynamoDB table
   - Ensure the Host header is being correctly parsed

2. **CORS Issues**:
   - Check that all required headers are included in the CORS configuration
   - For development, set MaxAge to 0 to prevent caching of preflight responses
   - Verify the browser's network tab for preflight responses

3. **Routing Problems**:
   - Check the API Gateway access logs
   - Verify the proxy integration is correctly configured
   - Test direct access to the Amplify app endpoint

## AWS CLI Commands for Management

### Check API Configuration
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="json"; aws.exe apigatewayv2 get-api --api-id 6h8u9qeur2
```

### View CORS Configuration
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="json"; aws.exe apigatewayv2 get-api --api-id 6h8u9qeur2 | ConvertFrom-Json | Select-Object -ExpandProperty CorsConfiguration
```

### View Routes
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe apigatewayv2 get-routes --api-id 6h8u9qeur2
```

### View Authorizers
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe apigatewayv2 get-authorizers --api-id 6h8u9qeur2
```

### View Domain Mappings
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe apigatewayv2 get-api-mappings --domain-name gallery.devopsify.shop
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe apigatewayv2 get-api-mappings --domain-name photos.devopsify.shop
```

### View Lambda Role Policies
```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="json"; aws.exe iam list-attached-role-policies --role-name DomainAuthorizerPython-role-vmxqf86k
```

## Replication Instructions

To recreate this setup in another AWS account, follow the steps in the `total-setup.md` document, which provides detailed AWS CLI commands for each component.

---

_This document serves as a complete knowledge base for the Multi-Tenant Custom Domain Architecture implementation._

## Important Implementation Files

- **Lambda Authorizer Code**: `http_domain_authorizer.py` - This is the actual Lambda function code deployed as the HTTP API authorizer
- **Documentation**: `total-setup.md` - Contains detailed AWS CLI commands for recreating the setup
