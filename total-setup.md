# AWS HTTP API with Lambda Authorizer - Complete Setup Guide

This document outlines the complete setup for an HTTP API with a Lambda authorizer that uses the Host header to map domains to workspace IDs.

## Table of Contents
1. [Lambda Authorizer](#lambda-authorizer)
2. [IAM Role Configuration](#iam-role-configuration)
3. [DynamoDB Table](#dynamodb-table)
4. [HTTP API Configuration](#http-api-configuration)
5. [API Routes and Authorizers](#api-routes-and-authorizers)
6. [Integration Configuration](#integration-configuration)
7. [Custom Domain Configuration](#custom-domain-configuration)
8. [API Mappings](#api-mappings)

## Lambda Authorizer
The Lambda authorizer (`HttpDomainAuthorizerPython`) extracts the domain from the Host header, looks it up in a DynamoDB table, and returns the workspace ID in the context.

### Function Configuration

```json
{
    "FunctionName": "HttpDomainAuthorizerPython",
    "Runtime": "python3.13",
    "Role": "arn:aws:iam::590183815265:role/service-role/DomainAuthorizerPython-role-vmxqf86k",
    "Handler": "http_domain_authorizer.lambda_handler",
    "Timeout": 3,
    "MemorySize": 128
}
```

### Function Code (http_domain_authorizer.py)

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
        response = table.get_item(
            Key={
                'domain': domain
            }
        )
        
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

## IAM Role Configuration

### Role Details
```
Role Name: DomainAuthorizerPython-role-vmxqf86k
Role ARN: arn:aws:iam::590183815265:role/service-role/DomainAuthorizerPython-role-vmxqf86k
Path: /service-role/
```

### Assume Role Policy Document
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### Attached Policies
1. CloudWatchLogsFullAccess (`arn:aws:iam::aws:policy/CloudWatchLogsFullAccess`)
2. AmazonDynamoDBReadOnlyAccess (`arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess`)
3. AWSLambdaBasicExecutionRole (`arn:aws:iam::590183815265:policy/service-role/AWSLambdaBasicExecutionRole-77bcfe3a-5dfd-4b43-868e-f36868d25c13`)

## DynamoDB Table

### Table Configuration
```
Table Name: domain-workspace-mappings
Table ARN: arn:aws:dynamodb:us-east-1:590183815265:table/domain-workspace-mappings
Billing Mode: PAY_PER_REQUEST
```

### Primary Key
- Partition Key: `domain` (String)

### Sample Items
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

## HTTP API Configuration

### API Details
```
API ID: 6h8u9qeur2
API Name: DomainBasedRoutingHTTPAPI
API Endpoint: https://6h8u9qeur2.execute-api.us-east-1.amazonaws.com
API Key Source: HEADER (x-api-key)
Protocol Type: HTTP
```

### CORS Configuration
```
Allowed Origins: *
Allowed Headers:
  - x-workspace-id
  - content-type
  - authorization
Allowed Methods: *
Allow Credentials: true
Max Age: 0 seconds  # Note: 0 is best for development, 86400 (24 hours) is recommended for production environments
```

## API Routes and Authorizers

### Route Configuration
```
Route Key: ANY /{proxy+}
Route ID: l4xvqz3
Integration: 8g8twjk
Authorizer: rqn8ic (Custom)
```

### Authorizer Configuration
```
Authorizer ID: rqn8ic
Authorizer Name: HttpDomainAuthorizer
Authorizer Type: REQUEST
Identity Source: $request.header.host
Authorizer URI: arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:590183815265:function:HttpDomainAuthorizerPython/invocations
Enable Simple Responses: true
```

## Integration Configuration

### Integration Details
```
Integration ID: 8g8twjk
Integration Type: HTTP_PROXY
Integration Method: ANY
Integration URI: https://main.d2jo2hz8i0qz1a.amplifyapp.com/{proxy}
Timeout: 30000 ms
```

### Parameter Mappings
```
Parameter: header.x-Workspace-Id
Value: $context.authorizer.workspaceId
```

## Custom Domain Configuration

### Domain Names
1. Gallery Domain:
   ```
   Domain Name: gallery.devopsify.shop
   Domain Type: REGIONAL
   Certificate ARN: arn:aws:acm:us-east-1:590183815265:certificate/52bba28a-b4b8-4df4-bb34-bb6f33e743dd
   Endpoint: d-npmdc0a2vf.execute-api.us-east-1.amazonaws.com
   ```

2. Photos Domain:
   ```
   Domain Name: photos.devopsify.shop
   Domain Type: REGIONAL
   Certificate ARN: arn:aws:acm:us-east-1:590183815265:certificate/52bba28a-b4b8-4df4-bb34-bb6f33e743dd
   ```

## API Mappings

### Gallery Domain API Mapping
```
Domain Name: gallery.devopsify.shop
API ID: 6h8u9qeur2
API Mapping ID: biqish
Stage: $default
```

### Photos Domain API Mapping
```
Domain Name: photos.devopsify.shop
API ID: 6h8u9qeur2
API Mapping ID: 5mu77k
Stage: $default
```

## Recreating the Setup in Another AWS Account

### Step 1: Create the DynamoDB Table
```bash
aws dynamodb create-table \
    --table-name domain-workspace-mappings \
    --attribute-definitions AttributeName=domain,AttributeType=S \
    --key-schema AttributeName=domain,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

### Step 2: Add Items to the DynamoDB Table
```bash
aws dynamodb put-item \
    --table-name domain-workspace-mappings \
    --item '{"domain": {"S": "gallery.yourdomain.com"}, "workspaceId": {"S": "workspace-1"}, "status": {"S": "active"}, "createdAt": {"S": "2025-03-14T12:00:00Z"}}'

aws dynamodb put-item \
    --table-name domain-workspace-mappings \
    --item '{"domain": {"S": "photos.yourdomain.com"}, "workspaceId": {"S": "workspace-2"}, "status": {"S": "active"}, "createdAt": {"S": "2025-03-14T12:00:00Z"}}'
```

### Step 3: Create IAM Role for Lambda
```bash
aws iam create-role \
    --role-name DomainAuthorizerRole \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }'

aws iam attach-role-policy \
    --role-name DomainAuthorizerRole \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess

aws iam attach-role-policy \
    --role-name DomainAuthorizerRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess

aws iam attach-role-policy \
    --role-name DomainAuthorizerRole \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

### Step 4: Create Lambda Function
1. Save the Lambda function code to `http_domain_authorizer.py`
2. Create a ZIP file:
```bash
zip http_domain_authorizer.zip http_domain_authorizer.py
```
3. Create the Lambda function:
```bash
aws lambda create-function \
    --function-name HttpDomainAuthorizerPython \
    --runtime python3.13 \
    --role YOUR_ROLE_ARN \
    --handler http_domain_authorizer.lambda_handler \
    --zip-file fileb://http_domain_authorizer.zip \
    --timeout 3 \
    --memory-size 128
```

### Step 5: Create HTTP API
```bash
aws apigatewayv2 create-api \
    --name DomainBasedRoutingHTTPAPI \
    --protocol-type HTTP \
    --cors-configuration AllowOrigins='*',AllowHeaders='x-workspace-id,content-type,authorization',AllowMethods='*',AllowCredentials=true
```

### Step 6: Create Lambda Authorizer
```bash
aws apigatewayv2 create-authorizer \
    --api-id YOUR_API_ID \
    --authorizer-type REQUEST \
    --identity-source '$request.header.host' \
    --name HttpDomainAuthorizer \
    --authorizer-uri YOUR_LAMBDA_INVOKE_ARN \
    --enable-simple-responses true
```

### Step 7: Create Integration with Amplify App
```bash
aws apigatewayv2 create-integration \
    --api-id YOUR_API_ID \
    --integration-type HTTP_PROXY \
    --integration-method ANY \
    --integration-uri YOUR_AMPLIFY_APP_URL/{proxy} \
    --payload-format-version 1.0 \
    --timeout-in-millis 30000 \
    --request-parameters 'header.x-Workspace-Id=$context.authorizer.workspaceId'
```

### Step 8: Create Route
```bash
aws apigatewayv2 create-route \
    --api-id YOUR_API_ID \
    --route-key 'ANY /{proxy+}' \
    --target "integrations/YOUR_INTEGRATION_ID" \
    --authorizer-id YOUR_AUTHORIZER_ID
```

### Step 9: Create Custom Domain Names
```bash
aws apigatewayv2 create-domain-name \
    --domain-name gallery.yourdomain.com \
    --domain-name-configurations CertificateArn=YOUR_CERTIFICATE_ARN

aws apigatewayv2 create-domain-name \
    --domain-name photos.yourdomain.com \
    --domain-name-configurations CertificateArn=YOUR_CERTIFICATE_ARN
```

### Step 10: Create API Mappings
```bash
aws apigatewayv2 create-api-mapping \
    --domain-name gallery.yourdomain.com \
    --api-id YOUR_API_ID \
    --stage $default

aws apigatewayv2 create-api-mapping \
    --domain-name photos.yourdomain.com \
    --api-id YOUR_API_ID \
    --stage $default
```

### Step 11: Set Up DNS Records
Create CNAME records in your DNS provider:
- `gallery.yourdomain.com` → `[API Gateway domain endpoint]`
- `photos.yourdomain.com` → `[API Gateway domain endpoint]`

## Testing the Setup

### Test Lambda Authorizer Directly
```json
{
  "version": "2.0",
  "type": "REQUEST",
  "routeArn": "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/*/ANY/{proxy+}",
  "identitySource": [
    "yourdomain.com"
  ],
  "routeKey": "ANY /{proxy+}",
  "rawPath": "/home",
  "headers": {
    "host": "gallery.yourdomain.com"
  },
  "requestContext": {
    "domainName": "gallery.yourdomain.com"
  }
}
```

### Test API Endpoint
```bash
curl -H "Host: gallery.yourdomain.com" https://gallery.yourdomain.com/home
```
