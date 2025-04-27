from fastapi import Request
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def logging_middleware(request: Request, call_next):
    """
    Middleware to log request details for debugging
    """
    # Log the request method and URL
    logger.info(f"Request: {request.method} {request.url}")
    
    # Log headers
    headers = dict(request.headers)
    logger.info(f"Headers: {json.dumps(headers, indent=2)}")
    
    # Try to log the request body
    try:
        body = await request.body()
        if body:
            # Clone the request with the body we've already read
            # Store the body so it can be read again by route handlers
            request._body = body
            body_str = body.decode()
            if body_str:
                try:
                    # Try to parse as JSON for prettier logging
                    body_json = json.loads(body_str)
                    logger.info(f"Request Body: {json.dumps(body_json, indent=2)}")
                except json.JSONDecodeError:
                    # If not JSON, log as string
                    logger.info(f"Request Body: {body_str}")
    except Exception as e:
        logger.error(f"Error reading request body: {str(e)}")
    
    # Process the request
    response = await call_next(request)
    
    # Log the response status code
    logger.info(f"Response Status: {response.status_code}")
    
    return response