# Deploying the Custom Domain API as AWS Lambda

This guide provides step-by-step instructions for deploying the FastAPI application as an AWS Lambda function with API Gateway.

## Prerequisites

- AWS CLI installed and configured with appropriate permissions
- Python 3.8 or later
- Access to AWS services: Lambda, API Gateway, ACM, and DynamoDB

## Packaging the Application

Create a deployment package for Lambda:

### PowerShell (Windows)

```powershell
# Create a directory for the deployment package
New-Item -ItemType Directory -Force -Path "package"

# Copy the application code
Copy-Item app.py package/

# Install dependencies in the package directory
pip install -r requirements.txt -t package

# Create the zip file
cd package
Compress-Archive -Path * -DestinationPath ../function.zip -Force
cd ..
```

### Bash (Linux/macOS)

```bash
# Create a directory for the deployment package
mkdir -p package

# Copy the application code
cp app.py package/

# Install dependencies in the package directory
pip install -r requirements.txt -t package

# Create the zip file
cd package
zip -r ../function.zip .
cd ..
```

## IAM Role Setup

Create an IAM role with necessary permissions:

### PowerShell (Windows)

```powershell
# Create IAM role for Lambda function
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe iam create-role --role-name lambda-custom-domain-reg-role --assume-role-policy-document '{
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
}' | Out-String

# Attach required policies
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess | Out-String
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess | Out-String
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator | Out-String
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole | Out-String

# Wait for the role to propagate
Start-Sleep -Seconds 10
```

### Bash (Linux/macOS)

```bash
# Create IAM role for Lambda function
aws iam create-role --role-name lambda-custom-domain-reg-role --assume-role-policy-document '{
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

# Attach required policies
aws iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
aws iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess
aws iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator
aws iam attach-role-policy --role-name lambda-custom-domain-reg-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Wait for the role to propagate
sleep 10
```

## Lambda Function Deployment

Create the Lambda function:

### PowerShell (Windows)

```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe lambda create-function --function-name CustomDomainRegistrationAPI --zip-file fileb://function.zip --handler app.handler --runtime python3.9 --role arn:aws:iam::<ACCOUNT_ID>:role/lambda-custom-domain-reg-role --timeout 30 --memory-size 256 --environment "Variables={DYNAMODB_TABLE=domain-workspace-mappings,API_GATEWAY_ID=<YOUR_API_GATEWAY_ID>}" | Out-String
```

### Bash (Linux/macOS)

```bash
aws lambda create-function --function-name CustomDomainRegistrationAPI --zip-file fileb://function.zip --handler app.handler --runtime python3.9 --role arn:aws:iam::<ACCOUNT_ID>:role/lambda-custom-domain-reg-role --timeout 30 --memory-size 256 --environment "Variables={DYNAMODB_TABLE=domain-workspace-mappings,API_GATEWAY_ID=<YOUR_API_GATEWAY_ID>}"
```

Replace `<ACCOUNT_ID>` with your AWS account ID and `<YOUR_API_GATEWAY_ID>` with your API Gateway ID.

## API Gateway HTTP API Setup

Create an HTTP API:

### PowerShell (Windows)

```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe apigatewayv2 create-api --name CustomDomainAPI --protocol-type HTTP --target arn:aws:lambda:<REGION>:<ACCOUNT_ID>:function:CustomDomainRegistrationAPI | Out-String
```

### Bash (Linux/macOS)

```bash
aws apigatewayv2 create-api --name CustomDomainAPI --protocol-type HTTP --target arn:aws:lambda:<REGION>:<ACCOUNT_ID>:function:CustomDomainRegistrationAPI
```

Note the API ID from the response (you'll need it for the Lambda environment variables).

Grant API Gateway permission to invoke your Lambda function:

### PowerShell (Windows)

```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe lambda add-permission --function-name CustomDomainRegistrationAPI --statement-id apigateway --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:<REGION>:<ACCOUNT_ID>:<API_ID>/*/*/*" | Out-String
```

### Bash (Linux/macOS)

```bash
aws lambda add-permission --function-name CustomDomainRegistrationAPI --statement-id apigateway --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:<REGION>:<ACCOUNT_ID>:<API_ID>/*/*/*"
```

Replace `<REGION>`, `<ACCOUNT_ID>`, and `<API_ID>` with your values.

## DynamoDB Table Setup

Create the DynamoDB table for domain mappings:

### PowerShell (Windows)

```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe dynamodb create-table --table-name domain-workspace-mappings --attribute-definitions AttributeName=domain,AttributeType=S --key-schema AttributeName=domain,KeyType=HASH --billing-mode PAY_PER_REQUEST | Out-String
```

### Bash (Linux/macOS)

```bash
aws dynamodb create-table --table-name domain-workspace-mappings --attribute-definitions AttributeName=domain,AttributeType=S --key-schema AttributeName=domain,KeyType=HASH --billing-mode PAY_PER_REQUEST
```

## Testing the Deployment

Test the API endpoints using curl or other HTTP client tools:

### PowerShell (Windows)

```powershell
# Request a new domain with DNS validation
$headers = @{
    "Content-Type" = "application/json"
}

$body = @{
    domain = "test.example.com"
    workspace_id = "workspace-test"
    validation_method = "DNS"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://<API_ID>.execute-api.<REGION>.amazonaws.com/domains/request" -Method POST -Headers $headers -Body $body
```

### Bash (Linux/macOS)

```bash
# Request a new domain with DNS validation
curl -X POST "https://<API_ID>.execute-api.<REGION>.amazonaws.com/domains/request" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "test.example.com",
    "workspace_id": "workspace-test",
    "validation_method": "DNS"
  }'
```

Check the status:

### PowerShell (Windows)

```powershell
Invoke-RestMethod -Uri "https://<API_ID>.execute-api.<REGION>.amazonaws.com/domains/status?domain=test.example.com&workspace_id=workspace-test" -Method GET
```

### Bash (Linux/macOS)

```bash
curl -X GET "https://<API_ID>.execute-api.<REGION>.amazonaws.com/domains/status?domain=test.example.com&workspace_id=workspace-test"
```

## Updating the Lambda Function

When you need to update the function code:

### PowerShell (Windows)

```powershell
# Repackage the application
# [follow packaging steps again]

# Update the Lambda function
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe lambda update-function-code --function-name CustomDomainRegistrationAPI --zip-file fileb://function.zip | Out-String
```

### Bash (Linux/macOS)

```bash
# Repackage the application
# [follow packaging steps again]

# Update the Lambda function
aws lambda update-function-code --function-name CustomDomainRegistrationAPI --zip-file fileb://function.zip
```

## Monitoring and Logs

View CloudWatch logs:

### PowerShell (Windows)

```powershell
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe logs describe-log-groups --log-group-name-prefix /aws/lambda/CustomDomainRegistrationAPI | Out-String

# Get the most recent log stream
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="json";
$logStreams = aws.exe logs describe-log-streams --log-group-name /aws/lambda/CustomDomainRegistrationAPI --order-by LastEventTime --descending --limit 1 | ConvertFrom-Json
$latestStream = $logStreams.logStreams[0].logStreamName

# View log events
$env:AWS_PAGER=""; $env:AWS_DEFAULT_OUTPUT="text"; aws.exe logs get-log-events --log-group-name /aws/lambda/CustomDomainRegistrationAPI --log-stream-name $latestStream | Out-String
```

### Bash (Linux/macOS)

```bash
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/CustomDomainRegistrationAPI

# Get the most recent log stream
logStream=$(aws logs describe-log-streams --log-group-name /aws/lambda/CustomDomainRegistrationAPI --order-by LastEventTime --descending --limit 1 --query 'logStreams[0].logStreamName' --output text)

# View log events
aws logs get-log-events --log-group-name /aws/lambda/CustomDomainRegistrationAPI --log-stream-name $logStream
```

## Security Considerations

- Restrict IAM permissions to the minimum required
- Consider adding authentication to your API Gateway endpoints
- Review ACM certificate validation methods for security implications
- Implement API key requirements or other authorization mechanisms
