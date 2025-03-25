# Deploying the Custom Domain API as AWS Lambda

This guide provides step-by-step instructions for deploying the FastAPI application as an AWS Lambda function with API Gateway using the AWS Console.

## Preparation

1. Run the packaging PowerShell script to create the Lambda deployment package:
   ```
   .\package-lambda.ps1
   ```
   This script will create a `deployment\function.zip` file with all the necessary code and dependencies.

## Lambda Deployment (AWS Console)

### 1. Create IAM Role

1. Open the AWS Console and navigate to **IAM** service
2. Click on **Roles** in the left sidebar
3. Click **Create role**
4. Select **AWS service** as the trusted entity type
5. Select **Lambda** as the use case
6. Click **Next**
7. Search for and add the following policies:
   - `AmazonDynamoDBReadWriteAccess`
   - `AWSCertificateManagerFullAccess`
   - `AmazonAPIGatewayAdministrator`
   - `AWSLambdaBasicExecutionRole` (for CloudWatch Logs)
8. Click **Next**
9. Name the role `lambda-custom-domain-reg-role`
10. Click **Create role**

### 2. Create Lambda Function

1. Navigate to the **Lambda** service in AWS Console
2. Click **Create function**
3. Select **Author from scratch**
4. Enter the following details:
   - **Function name**: `CustomDomainRegistrationAPI`
   - **Runtime**: Python 3.13
   - **Architecture**: x86_64
   - **Permissions**: Use an existing role
   - **Existing role**: `lambda-custom-domain-reg-role` (created in previous step)
5. Click **Create function**

### 3. Upload Code

1. In the Lambda function page, scroll to the **Code source** section
2. Click on the **Upload from** dropdown and select **.zip file**
3. Click **Upload** and select the `deployment/function.zip` file
4. Click **Save**

### 4. Configure Function Settings

1. Scroll to **Configuration** tab
2. Click on **General configuration** and then **Edit**
   - Set **Timeout** to `30` seconds
   - Set **Memory** to `256` MB
   - Click **Save**
3. Click on **Environment variables** and then **Edit**
   - Add the following key-value pairs:
     - Key: `API_GATEWAY_ID` Value: `[Leave blank for now]` (Will add after creating API Gateway)
     - Key: `DYNAMODB_TABLE` Value: `domain-workspace-mappings`
   - Click **Save**
   - Note: `AWS_REGION` is automatically set by AWS Lambda and should not be added as a custom environment variable

### 5. Configure Handler and Test

1. In the **Runtime settings** section, click **Edit**
2. Change the **Handler** to `app.handler`
3. Click **Save**
4. At this point, your Lambda function is configured and ready to be invoked (no additional deployment steps needed)

## API Gateway Setup (AWS Console)

### 1. Create HTTP API

1. Navigate to **API Gateway** service in AWS Console
2. Click **Create API**
3. Under HTTP API, click **Build**
4. Enter the following details:
   - **API name**: `CustomDomainProvisioningAPI`
   - In **Integrations**, select **Add integration**
   - Choose **Lambda**
   - Select the `CustomDomainRegistrationAPI` Lambda function
   - Keep **API key required** as `No`
5. Click **Next**
6. Configure routes:
   - Click **Add route**
   - Method: `POST`
   - Resource path: `/domains/request`
   - Integration target: `CustomDomainRegistrationAPI`
   - Click **Add route** again
   - Method: `GET`
   - Resource path: `/domains/status`
   - Integration target: `CustomDomainRegistrationAPI`
7. Click **Next**
8. Configure stages:
   - Keep default stage name as `$default`
   - Enable **Auto-deploy**
9. Click **Next**
10. Review and click **Create**

### 2. Configure CORS

1. In the API Gateway console, select your API
2. Select the **CORS** tab
3. Click **Configure**
4. Add the following settings:
   - **Access-Control-Allow-Origins**: `*` (or your specific domains)
   - **Access-Control-Allow-Headers**: `content-type,x-api-key,authorization,x-workspace-id`
   - **Access-Control-Allow-Methods**: `*`
   - **Access-Control-Allow-Credentials**: `Yes`
5. Click **Save**

## API Usage

### 1. Request Certificate

To request a certificate for a custom domain, call the request endpoint with the domain and workspace_id:

```powershell
$response = Invoke-RestMethod -Uri "https://abc123def.execute-api.us-east-1.amazonaws.com/domains/request" -Method Post -Body '{"domain": "test.devopsify.shop", "workspace_id": "workspace-test"}' -ContentType "application/json"

# Display the response including validation records
$response | ConvertTo-Json -Depth 5
```

The response will include validation records that need to be added to DNS.

### 2. Check Certificate Status

After adding the CNAME records to DNS, check the status using the domain and workspace_id:

```powershell
Invoke-RestMethod -Uri "https://abc123def.execute-api.us-east-1.amazonaws.com/domains/status?domain=test.devopsify.shop&workspace_id=workspace-test" -Method Get
```

## Lambda CloudWatch Logs

To view logs for debugging:

1. Navigate to **CloudWatch** service in AWS Console
2. Click on **Log groups** in the left sidebar
3. Find and click on the log group named `/aws/lambda/CustomDomainRegistrationAPI`
4. View the latest log stream to see execution details

## Updating the Lambda Function

When you make changes to your code:

1. Update your local code files
2. Recreate the deployment package following the preparation steps
3. In the Lambda console:
   - Select your Lambda function
   - Go to the **Code** tab
   - Click **Upload from** and choose **.zip file**
   - Select your updated zip file
   - Click **Save**

## Conclusion

Your FastAPI application is now deployed as a Lambda function with API Gateway integration. This serverless architecture provides a cost-effective solution for your custom domain provisioning API, perfectly suited for the limited usage by premium customers.
