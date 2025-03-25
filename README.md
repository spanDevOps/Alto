# Custom Domain Provisioning API

A FastAPI application for managing custom domain provisioning in the multi-tenant Alto architecture.

## Overview

This API provides endpoints for provisioning custom domains for tenants in a multi-tenant application. It manages the process of:

1. Creating SSL certificates in AWS Certificate Manager (ACM)
2. Obtaining domain validation records
3. Checking certificate status
4. Configuring API Gateway custom domains
5. Mapping domains to the existing HTTP API
6. Updating DynamoDB with domain-to-workspace mappings

## Getting Started

### Prerequisites

- Python 3.8+
- AWS credentials configured (via environment variables or AWS CLI)
- Permissions to access ACM, API Gateway, and DynamoDB

### Installation

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   uvicorn app:app --reload
   ```

The API will be available at http://localhost:8000

## API Documentation

Once running, you can access the Swagger UI documentation at:
- http://localhost:8000/docs
- http://localhost:8000/redoc (alternative interface)

### Endpoints

#### 1. Request Custom Domain

**Endpoint:** `POST /domains/request`

Creates an SSL certificate for a custom domain and returns validation records for DNS configuration.

**Request Body:**
```json
{
  "domain": "client.devopsify.shop",
  "workspace_id": "workspace-123"
}
```

**Response:**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "client.devopsify.shop",
  "status": "PENDING_VALIDATION",
  "validation_records": [
    {
      "name": "_a79865eb4cd1a6ab43.client.devopsify.shop",
      "value": "_c3c69a8dfa23e234b1.acm-validations.aws",
      "type": "CNAME"
    }
  ],
  "message": "Certificate created. Please add the CNAME validation records to your DNS configuration."
}
```

#### 2. Check Domain Status

**Endpoint:** `GET /domains/status/{request_id}?domain=client.devopsify.shop`

Checks the status of a domain request. If the certificate is issued, it completes the domain setup.

**Response (Pending):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "client.devopsify.shop",
  "status": "PENDING",
  "certificate_status": "PENDING_VALIDATION",
  "message": "Certificate is still pending validation. Please add the CNAME records to your DNS."
}
```

**Response (Configured):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "client.devopsify.shop",
  "status": "CONFIGURED",
  "certificate_status": "ISSUED",
  "api_gateway_domain": "d-abc123.execute-api.us-east-1.amazonaws.com",
  "message": "Custom domain is fully configured. Create a CNAME record from your domain to the API Gateway domain."
}
```

## Workflow

1. Tenant submits domain request through your web interface
2. Your backend calls the `/domains/request` endpoint
3. Present the validation records to the tenant for DNS configuration
4. Periodically poll the `/domains/status/{request_id}` endpoint to check certificate status
5. Once status is "CONFIGURED", present the API Gateway domain to the tenant for final DNS configuration

## Environment Configuration

For production deployment, consider setting the following environment variables:

- `AWS_REGION` - AWS region for services
- `API_GATEWAY_ID` - The ID of your HTTP API (currently hardcoded as "6h8u9qeur2")
- `DYNAMODB_TABLE` - The DynamoDB table name (currently hardcoded as "domain-workspace-mappings")

## Security Considerations

- Ensure proper IAM permissions are configured
- Consider adding authentication to these API endpoints
- In production, serve API over HTTPS
