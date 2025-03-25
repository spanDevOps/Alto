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
