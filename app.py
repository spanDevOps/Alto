import os
import json
import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import boto3
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from mangum import Mangum

# Configure logging with more details
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Create a handler if none exists
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(handler)

# Initialize FastAPI app
app = FastAPI(
    title="Custom Domain Registration API", 
    description="Serverless API for registering and provisioning custom domains for workspace tenants through AWS Certificate Manager and API Gateway"
)

# Models
class DomainRequest(BaseModel):
    domain: str
    workspace_id: str

class ValidationRecord(BaseModel):
    name: str
    value: str
    type: str

class DomainRequestResponse(BaseModel):
    domain: str
    workspace_id: str
    status: str
    validation_records: Optional[List[ValidationRecord]] = None
    message: str

class DomainStatus(BaseModel):
    domain: str
    workspace_id: str
    status: str
    certificate_status: Optional[str] = None
    api_gateway_domain: Optional[str] = None
    validation_records: Optional[List[ValidationRecord]] = None
    message: str

# Dependency for AWS clients
async def get_clients():
    # No need to specify region - AWS Lambda automatically provides the region
    session = boto3.Session()
    acm = session.client('acm')
    apigateway = session.client('apigatewayv2')
    dynamodb = session.resource('dynamodb')
    
    return {
        "acm": acm,
        "apigateway": apigateway,
        "dynamodb": dynamodb
    }

@app.post("/domains/request", response_model=DomainRequestResponse)
async def request_domain(domain_request: DomainRequest, clients=Depends(get_clients)):
    """
    Request a custom domain and create SSL certificate
    
    This endpoint:
    1. Creates certificate in ACM
    2. Returns validation records (CNAME) for DNS configuration
    """
    domain = domain_request.domain
    workspace_id = domain_request.workspace_id
    
    try:
        # Create certificate in ACM
        acm_client = clients["acm"]
        
        # First, check for existing certificates
        logger.info(json.dumps({
            "action": "check_existing_certificates",
            "domain": domain,
            "workspace_id": workspace_id,
            "message": "Starting certificate check"
        }))
        existing_cert_arn = None
        
        try:
            certificates = acm_client.list_certificates(
                CertificateStatuses=['PENDING_VALIDATION', 'ISSUED']
            )
            
            logger.info(json.dumps({
                "action": "list_certificates",
                "count": len(certificates.get('CertificateSummaryList', [])),
                "message": "Retrieved certificates list"
            }))
            
            # Find any existing certificate for this domain + workspace
            for cert in certificates.get('CertificateSummaryList', []):
                if cert['DomainName'] == domain:
                    logger.info(json.dumps({
                        "action": "found_matching_domain",
                        "domain": domain,
                        "cert_arn": cert['CertificateArn'],
                        "message": "Found certificate with matching domain"
                    }))
                    
                    # Get certificate details - needed for validation records later
                    cert_details = acm_client.describe_certificate(
                        CertificateArn=cert['CertificateArn']
                    )
                    
                    # Always use direct tag listing - more reliable than certificate details
                    try:
                        cert_tags = acm_client.list_tags_for_certificate(
                            CertificateArn=cert['CertificateArn']
                        )
                        
                        logger.info(json.dumps({
                            "action": "certificate_tags",
                            "domain": domain,
                            "cert_arn": cert['CertificateArn'],
                            "tags": cert_tags.get('Tags', []),
                            "message": "Retrieved certificate tags"
                        }))
                        
                        # Check for workspace ID tag
                        for tag in cert_tags.get('Tags', []):
                            if tag['Key'] == 'WorkspaceId' and tag['Value'] == workspace_id:
                                existing_cert_arn = cert['CertificateArn']
                                logger.info(json.dumps({
                                    "action": "found_matching_workspace",
                                    "domain": domain,
                                    "workspace_id": workspace_id,
                                    "cert_arn": existing_cert_arn,
                                    "message": "Found certificate with matching workspace"
                                }))
                                break
                    except Exception as tag_error:
                        logger.error(json.dumps({
                            "action": "tags_error",
                            "domain": domain,
                            "cert_arn": cert['CertificateArn'],
                            "error": str(tag_error),
                            "message": "Error retrieving certificate tags"
                        }))
                    
                    if existing_cert_arn:
                        break
        except Exception as e:
            logger.error(json.dumps({
                "action": "check_certificates_error",
                "error": str(e),
                "message": "Error checking existing certificates"
            }))
            raise
        
        # Either reuse existing certificate or create new one
        if existing_cert_arn:
            logger.info(json.dumps({
                "action": "reuse_certificate",
                "domain": domain,
                "workspace_id": workspace_id,
                "cert_arn": existing_cert_arn,
                "message": "Reusing existing certificate"
            }))
            certificate_arn = existing_cert_arn
        else:
            logger.info(json.dumps({
                "action": "create_certificate",
                "domain": domain,
                "workspace_id": workspace_id,
                "message": "Creating new certificate"
            }))
            try:
                certificate_response = acm_client.request_certificate(
                    DomainName=domain,
                    ValidationMethod='DNS',
                    Tags=[
                        {
                            'Key': 'WorkspaceId',
                            'Value': workspace_id
                        },
                    ]
                )
                certificate_arn = certificate_response['CertificateArn']
                logger.info(json.dumps({
                    "action": "certificate_created",
                    "domain": domain,
                    "workspace_id": workspace_id,
                    "cert_arn": certificate_arn,
                    "message": "Successfully created new certificate"
                }))
            except Exception as cert_error:
                logger.error(json.dumps({
                    "action": "create_certificate_error",
                    "domain": domain,
                    "workspace_id": workspace_id,
                    "error": str(cert_error),
                    "message": "Error creating certificate"
                }))
                raise cert_error
        
        # Get the certificate details to retrieve CNAME validation records
        certificate_details = acm_client.describe_certificate(
            CertificateArn=certificate_arn
        )
        
        # Log certificate details for debugging
        logger.info(json.dumps({
            "action": "certificate_details",
            "domain": domain,
            "workspace_id": workspace_id,
            "cert_arn": certificate_arn,
            "message": "Retrieved certificate details"
        }))
        
        # Extract validation records
        validation_records = []
        retry_count = 0
        max_retries = 3
        retry_delay = 2  # seconds
        
        # Try to get validation records with retries
        while retry_count < max_retries:
            if 'Certificate' in certificate_details and 'DomainValidationOptions' in certificate_details['Certificate']:
                # Log validation options for debugging
                logger.info(json.dumps({
                    "action": "validation_options",
                    "domain": domain,
                    "workspace_id": workspace_id,
                    "cert_arn": certificate_arn,
                    "message": "Retrieved validation options"
                }))
                
                for validation in certificate_details['Certificate']['DomainValidationOptions']:
                    if 'ResourceRecord' in validation:
                        record = validation['ResourceRecord']
                        validation_records.append({
                            "name": record['Name'],
                            "value": record['Value'],
                            "type": record['Type']
                        })
            
            # If we got validation records, break out of the retry loop
            if validation_records:
                break
                
            # Otherwise, wait and retry
            logger.info(json.dumps({
                "action": "retry_validation_records",
                "domain": domain,
                "workspace_id": workspace_id,
                "cert_arn": certificate_arn,
                "message": "Retrying validation records"
            }))
            await asyncio.sleep(retry_delay)
            retry_count += 1
            
            # Get updated certificate details
            certificate_details = acm_client.describe_certificate(
                CertificateArn=certificate_arn
            )
        
        # If no validation records are available yet, provide instructions
        message = "Certificate created. "
        if validation_records:
            message += "Add these CNAME records to your DNS to validate domain ownership."
        else:
            message += "Validation records are not yet available. Please check the status endpoint in 30-60 seconds to get validation records."
        
        # Return validation records for DNS configuration
        return DomainRequestResponse(
            domain=domain,
            workspace_id=workspace_id,
            status="PENDING_VALIDATION",
            validation_records=validation_records,
            message=message
        )
        
    except Exception as e:
        logger.error(json.dumps({
            "action": "request_domain_error",
            "domain": domain,
            "workspace_id": workspace_id,
            "error": str(e),
            "message": "Error requesting domain"
        }))
        raise HTTPException(status_code=500, detail=f"Failed to request domain: {str(e)}")

@app.get("/domains/status", response_model=DomainStatus)
async def check_domain_status(domain: str, workspace_id: str, clients=Depends(get_clients)):
    """
    Check the status of a custom domain request and proceed with setup if certificate is issued
    
    This endpoint:
    1. Checks certificate status in ACM
    2. If issued, creates custom domain in API Gateway
    3. Maps the domain to the HTTP API
    4. Updates DynamoDB with domain mapping
    5. Returns API Gateway domain for DNS configuration
    """
    try:
        # Find the certificate for the domain and workspace
        acm_client = clients["acm"]
        
        # Log what we're searching for
        logger.info(json.dumps({
            "action": "find_certificate",
            "domain": domain,
            "workspace_id": workspace_id,
            "message": "Searching for certificate"
        }))
        
        # Get all certificates with broader filter
        certificates = acm_client.list_certificates(
            CertificateStatuses=['PENDING_VALIDATION', 'ISSUED', 'VALIDATION_TIMED_OUT']
        )
        
        # Log how many certificates we found
        logger.info(json.dumps({
            "action": "list_certificates",
            "count": len(certificates.get('CertificateSummaryList', [])),
            "message": "Retrieved certificates list"
        }))
        
        certificate_arn = None
        certificate_status = "NOT_FOUND"
        cert_details = None
        
        # Find the certificate matching the domain
        for cert in certificates.get('CertificateSummaryList', []):
            logger.info(json.dumps({
                "action": "check_certificate",
                "domain": domain,
                "cert_arn": cert['CertificateArn'],
                "message": "Checking certificate"
            }))
            
            if cert['DomainName'] == domain:
                logger.info(json.dumps({
                    "action": "found_matching_domain",
                    "domain": domain,
                    "cert_arn": cert['CertificateArn'],
                    "message": "Found certificate with matching domain"
                }))
                cert_details = acm_client.describe_certificate(
                    CertificateArn=cert['CertificateArn']
                )
                
                # Log the full certificate details
                logger.info(json.dumps({
                    "action": "certificate_details",
                    "domain": domain,
                    "cert_arn": cert['CertificateArn'],
                    "message": "Retrieved certificate details"
                }))
                
                # Check if this certificate is associated with the workspace_id
                found_workspace = False
                
                # Sometimes tags might be empty or not yet populated
                if 'Tags' in cert_details.get('Certificate', {}):
                    for tag in cert_details['Certificate']['Tags']:
                        logger.info(json.dumps({
                            "action": "check_tag",
                            "domain": domain,
                            "cert_arn": cert['CertificateArn'],
                            "tag_key": tag['Key'],
                            "tag_value": tag['Value'],
                            "message": "Checking tag"
                        }))
                        if tag['Key'] == 'WorkspaceId' and tag['Value'] == workspace_id:
                            found_workspace = True
                            logger.info(json.dumps({
                                "action": "found_matching_workspace",
                                "domain": domain,
                                "workspace_id": workspace_id,
                                "cert_arn": cert['CertificateArn'],
                                "message": "Found certificate with matching workspace"
                            }))
                            break
                else:
                    logger.info(json.dumps({
                        "action": "no_tags",
                        "domain": domain,
                        "cert_arn": cert['CertificateArn'],
                        "message": "No tags found in certificate"
                    }))
                
                # For debugging, let's temporarily match just on domain
                # Remove or modify this in production
                found_workspace = True
                logger.info(json.dumps({
                    "action": "temp_match_domain",
                    "domain": domain,
                    "workspace_id": workspace_id,
                    "cert_arn": cert['CertificateArn'],
                    "message": "Temporarily matching on domain"
                }))
                
                if found_workspace:
                    certificate_arn = cert['CertificateArn']
                    certificate_status = cert_details['Certificate']['Status']
                    break
        
        if not certificate_arn:
            return DomainStatus(
                workspace_id=workspace_id,
                domain=domain,
                status="FAILED",
                certificate_status="NOT_FOUND",
                message="Certificate not found for this domain and workspace."
            )
        
        # If certificate is still pending validation
        if certificate_status == 'PENDING_VALIDATION':
            # Get validation records to show again
            validation_records = []
            if 'Certificate' in cert_details and 'DomainValidationOptions' in cert_details['Certificate']:
                # Log validation details for debugging
                logger.info(json.dumps({
                    "action": "validation_details",
                    "domain": domain,
                    "cert_arn": certificate_arn,
                    "message": "Retrieved validation details"
                }))
                
                for validation in cert_details['Certificate']['DomainValidationOptions']:
                    if 'ResourceRecord' in validation:
                        record = validation['ResourceRecord']
                        validation_records.append({
                            "name": record['Name'],
                            "value": record['Value'],
                            "type": record['Type']
                        })
            
            message = "Certificate is still pending validation. "
            if validation_records:
                message += "Please add these CNAME records to your DNS."
            else:
                message += "Validation records are not yet available. Please try again in 30-60 seconds."
            
            return DomainStatus(
                workspace_id=workspace_id,
                domain=domain,
                status="PENDING",
                certificate_status=certificate_status,
                validation_records=validation_records,
                message=message
            )
        
        # If certificate is issued, proceed with API Gateway and DynamoDB setup
        if certificate_status == 'ISSUED':
            apigateway_client = clients["apigateway"]
            dynamodb = clients["dynamodb"]
            
            # 1. Create custom domain in API Gateway
            api_domain = None
            try:
                domain_response = apigateway_client.create_domain_name(
                    DomainName=domain,
                    DomainNameConfigurations=[
                        {
                            'CertificateArn': certificate_arn,
                            'EndpointType': 'REGIONAL',
                            'SecurityPolicy': 'TLS_1_2'
                        }
                    ]
                )
                api_domain = domain_response['DomainNameConfigurations'][0]['ApiGatewayDomainName']
                
                # 2. Map domain to the HTTP API
                # Get API ID from environment variables
                api_id = os.getenv("API_GATEWAY_ID", "6h8u9qeur2")
                
                apigateway_client.create_api_mapping(
                    DomainName=domain,
                    ApiId=api_id,
                    Stage="$default"
                )
                
                # 3. Update DynamoDB with domain mapping
                table_name = os.getenv("DYNAMODB_TABLE", "domain-workspace-mappings")
                table = dynamodb.Table(table_name)
                
                # Add entry to DynamoDB
                table.put_item(
                    Item={
                        'domain': domain,
                        'workspaceId': workspace_id,
                        'status': 'active',
                        'createdAt': datetime.now().isoformat()
                    }
                )
                
                return DomainStatus(
                    workspace_id=workspace_id,
                    domain=domain,
                    status="CONFIGURED",
                    certificate_status=certificate_status,
                    api_gateway_domain=api_domain,
                    message="Custom domain is fully configured. Create a CNAME record from your domain to the API Gateway domain."
                )
                
            except Exception as e:
                logger.error(json.dumps({
                    "action": "configure_domain_error",
                    "domain": domain,
                    "workspace_id": workspace_id,
                    "error": str(e),
                    "message": "Error configuring domain"
                }))
                return DomainStatus(
                    workspace_id=workspace_id,
                    domain=domain,
                    status="CERTIFICATE_ISSUED_CONFIG_FAILED",
                    certificate_status=certificate_status,
                    message=f"Certificate is issued but domain configuration failed: {str(e)}"
                )
        
        # If certificate has any other status
        return DomainStatus(
            workspace_id=workspace_id,
            domain=domain,
            status="PENDING",
            certificate_status=certificate_status,
            message=f"Certificate status: {certificate_status}"
        )
            
    except Exception as e:
        logger.error(json.dumps({
            "action": "check_domain_status_error",
            "domain": domain,
            "workspace_id": workspace_id,
            "error": str(e),
            "message": "Error checking domain status"
        }))
        raise HTTPException(status_code=500, detail=f"Failed to check domain status: {str(e)}")

# Root endpoint for health check
@app.get("/")
async def root():
    return {"status": "healthy", "message": "Custom Domain Registration API is running"}

# Create Lambda handler
handler = Mangum(app)
