#!/usr/bin/env python3
"""
Custom proxy server for bridging Open WebUI to Composio MCP API.

This server:
1. Accepts requests with Bearer token authentication (Open WebUI format)
2. Transforms Bearer tokens to x-api-key headers (Composio format)
3. Forwards requests to Composio MCP API
4. Streams responses back to the client
5. Handles CORS for web browser requests
"""

import os
import logging
import time
from flask import Flask, request, Response, jsonify, stream_with_context
from flask_cors import CORS
import requests
from werkzeug.exceptions import BadRequest, InternalServerError

# Configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for all routes (needed for Open WebUI)
CORS(app, origins="*", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])

# Configuration
COMPOSIO_BASE_URL = "https://mcp.composio.dev"
DEFAULT_API_KEY = os.getenv('X_API_KEY', '')
PORT = int(os.getenv('PORT', 8000))

# Request timeout settings
REQUEST_TIMEOUT = 120
CONNECTION_TIMEOUT = 30

# Add performance headers to all responses
@app.after_request
def add_performance_headers(response):
    """Add performance and security headers to all responses."""
    # Add connection keep-alive for better performance
    response.headers['Connection'] = 'keep-alive'
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Add caching for static/health endpoints
    if request.endpoint in ['health_check', 'detailed_health']:
        response.headers['Cache-Control'] = 'public, max-age=30'
    elif request.path == '/openapi.json':
        response.headers['Cache-Control'] = 'public, max-age=300'  # 5 minutes
    
    return response

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint for Railway."""
    response = jsonify({
        "status": "healthy",
        "service": "composio-proxy",
        "timestamp": int(time.time())
    })
    # Add cache headers for faster subsequent requests
    response.headers['Cache-Control'] = 'public, max-age=30'
    response.headers['Connection'] = 'keep-alive'
    return response, 200

@app.route('/health', methods=['GET'])
def detailed_health():
    """Detailed health check endpoint."""
    try:
        # Test connection to Composio API
        test_response = requests.get(
            f"{COMPOSIO_BASE_URL}/",
            timeout=CONNECTION_TIMEOUT,
            headers={"x-api-key": DEFAULT_API_KEY or "test"}
        )
        composio_status = "reachable" if test_response.status_code != 500 else "unreachable"
    except Exception as e:
        composio_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "service": "composio-proxy",
        "composio_api": composio_status,
        "port": PORT,
        "timestamp": int(time.time())
    }), 200

def extract_api_key_from_request():
    """Extract API key from Authorization header or use default."""
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header.startswith('Bearer '):
        # Extract Bearer token and use as API key
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        logger.debug(f"Extracted API key from Bearer token (length: {len(api_key)})")
        return api_key
    elif DEFAULT_API_KEY:
        logger.debug("Using default API key")
        return DEFAULT_API_KEY
    else:
        logger.warning("No API key found in Authorization header and no default configured")
        return None

def sanitize_headers_for_logging(headers):
    """Sanitize headers for logging by removing sensitive information."""
    sanitized = dict(headers)
    sensitive_headers = ['authorization', 'x-api-key', 'cookie', 'set-cookie']
    
    for header in sensitive_headers:
        if header in sanitized:
            sanitized[header] = '[REDACTED]'
        # Also check lowercase versions
        header_lower = header.lower()
        if header_lower in sanitized:
            sanitized[header_lower] = '[REDACTED]'
    
    return sanitized

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_request(path=''):
    """Proxy all requests to Composio API with authentication transformation."""
    
    # Handle preflight OPTIONS requests
    if request.method == 'OPTIONS':
        return '', 200
    
    start_time = time.time()
    
    try:
        # Allow unauthenticated access to openapi.json for Open WebUI integration
        if path == 'openapi.json' and request.method == 'GET':
            api_key = DEFAULT_API_KEY or 'anonymous'
            logger.info(f"Allowing unauthenticated access to /openapi.json")
        else:
            # Extract API key from request for other endpoints
            api_key = extract_api_key_from_request()
            if not api_key:
                logger.error("No API key provided in request")
                return jsonify({
                    "error": "Authentication required",
                    "message": "Provide API key in Authorization: Bearer <key> header"
                }), 401
        
        # Build target URL
        target_url = f"{COMPOSIO_BASE_URL}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string.decode('utf-8')}"
        
        # Prepare headers for Composio API
        headers = {}
        for key, value in request.headers.items():
            # Skip hop-by-hop headers and host
            if key.lower() not in ['host', 'authorization', 'connection', 'upgrade', 
                                  'proxy-authenticate', 'proxy-authorization', 'te', 
                                  'trailers', 'transfer-encoding']:
                headers[key] = value
        
        # Add Composio authentication
        headers['x-api-key'] = api_key
        
        # Log request details (with sanitized headers)
        logger.info(f"Proxying {request.method} {target_url}")
        logger.debug(f"Request headers: {sanitize_headers_for_logging(headers)}")
        
        # Get request data
        request_data = None
        if request.method in ['POST', 'PUT', 'PATCH'] and request.data:
            request_data = request.data
            logger.debug(f"Request body length: {len(request_data)} bytes")
        
        # Make request to Composio API with streaming
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request_data,
            params=None,  # Already included in target_url
            timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT),
            stream=True,
            allow_redirects=True
        )
        
        # Log response details
        duration = time.time() - start_time
        logger.info(f"Response from Composio: {response.status_code} ({duration:.2f}s)")
        logger.debug(f"Response headers: {sanitize_headers_for_logging(dict(response.headers))}")
        
        # Prepare response headers
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [
            (key, value) for key, value in response.headers.items()
            if key.lower() not in excluded_headers
        ]
        
        # Stream the response back
        def generate():
            try:
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                    if chunk:
                        yield chunk
            except Exception as e:
                logger.error(f"Error streaming response: {str(e)}")
                yield b""
        
        return Response(
            stream_with_context(generate()),
            status=response.status_code,
            headers=response_headers,
            direct_passthrough=True
        )
        
    except requests.exceptions.Timeout:
        logger.error(f"Timeout connecting to Composio API: {target_url}")
        return jsonify({
            "error": "Gateway timeout",
            "message": "Request to Composio API timed out"
        }), 504
        
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error to Composio API: {str(e)}")
        return jsonify({
            "error": "Bad gateway",
            "message": "Could not connect to Composio API"
        }), 502
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        return jsonify({
            "error": "Proxy error",
            "message": f"Error forwarding request: {str(e)}"
        }), 500
        
    except Exception as e:
        logger.error(f"Unexpected error in proxy_request: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred"
        }), 500

if __name__ == '__main__':
    logger.info(f"Starting Composio proxy server on port {PORT}")
    logger.info(f"Proxying requests to: {COMPOSIO_BASE_URL}")
    logger.info(f"Default API key configured: {'Yes' if DEFAULT_API_KEY else 'No'}")
    
    # Run Flask development server (Gunicorn will be used in production)
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
