# Custom Domain Provisioning API

A FastAPI application for managing custom domain provisioning with AWS Certificate Manager and API Gateway, deployed as an AWS Lambda function.

## Overview

This API provides endpoints for provisioning custom domains for workspace tenants. It manages the process of:

1. Creating SSL certificates in AWS Certificate Manager (ACM) with either DNS or EMAIL validation
2. Obtaining domain validation records for DNS validation or sending email for EMAIL validation
3. Checking certificate status
4. Configuring API Gateway custom domains
5. Mapping domains to the existing HTTP API
6. Updating DynamoDB with domain-to-workspace mappings

## API Endpoints

### 1. Request Domain

**Endpoint:** `POST /domains/request`

Creates a certificate request for a custom domain.

**Request Body:**
```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "validation_method": "DNS",
  "validation_domain": null
}
```

OR for EMAIL validation:

```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "validation_method": "EMAIL",
  "validation_domain": "example.com"
}
```

**Parameters:**
- `domain`: The custom domain to provision
- `workspace_id`: ID of the workspace to associate with this domain
- `validation_method`: Either "DNS" or "EMAIL" for certificate validation
- `validation_domain`: (Optional) The domain to receive validation emails for EMAIL validation method

**Response:**
```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "status": "PENDING_VALIDATION",
  "validation_method": "DNS",
  "validation_records": [
    {
      "name": "_12345abcde.client.example.com.",
      "value": "_6789fghijk.acm-validations.aws.",
      "type": "CNAME"
    }
  ],
  "message": "Certificate request initiated. Please add the following DNS validation records to verify domain ownership."
}
```

OR for EMAIL validation:

```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "status": "PENDING_VALIDATION",
  "validation_method": "EMAIL",
  "validation_records": null,
  "message": "Certificate request initiated. Please check your email to admin@example.com for domain validation instructions."
}
```

### 2. Check Domain Status

**Endpoint:** `GET /domains/status?domain={domain}&workspace_id={workspace_id}`

Checks the status of a domain request and proceeds with setup if the certificate is issued.

**Query Parameters:**
- `domain`: The custom domain to check
- `workspace_id`: ID of the workspace associated with this domain

**Response (Pending):**
```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "status": "PENDING",
  "validation_method": "DNS",
  "certificate_status": "PENDING_VALIDATION",
  "api_gateway_domain": null,
  "validation_records": [
    {
      "name": "_12345abcde.client.example.com.",
      "value": "_6789fghijk.acm-validations.aws.",
      "type": "CNAME"
    }
  ],
  "validation_domain": null,
  "message": "Certificate is still pending validation. Please add these CNAME records to your DNS."
}
```

**Response (Configured):**
```json
{
  "domain": "client.example.com",
  "workspace_id": "workspace-123",
  "status": "CONFIGURED",
  "validation_method": "DNS",
  "certificate_status": "ISSUED",
  "api_gateway_domain": "d-abc123.execute-api.us-east-1.amazonaws.com",
  "validation_records": null,
  "validation_domain": null,
  "message": "Custom domain is fully configured. Create a CNAME record from your domain to the API Gateway domain."
}
```

## Workflow

1. Tenant submits domain request through your web interface
2. Your backend calls the `/domains/request` endpoint with the chosen validation method
3. For DNS validation: Present the validation records to the tenant for DNS configuration
   For EMAIL validation: Instruct the tenant to check validation emails
4. Periodically poll the `/domains/status` endpoint to check certificate status
5. Once status is "CONFIGURED", present the API Gateway domain to the tenant for final DNS configuration

## Environment Configuration

For production deployment, set the following environment variables:

- `API_GATEWAY_ID` - The ID of your HTTP API (required)
- `DYNAMODB_TABLE` - The DynamoDB table name (required)

## Security Considerations

- Ensure proper IAM permissions are configured
- Consider adding authentication to these API endpoints
- In production, protect API with appropriate authorization
