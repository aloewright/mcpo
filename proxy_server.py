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
from typing import Any, Dict, List, Optional, Tuple
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

# Simple in-memory cache for expensive aggregations (e.g., tools listing)
_TOOLS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
TOOLS_CACHE_TTL_SECONDS = int(os.getenv('TOOLS_CACHE_TTL_SECONDS', '120'))  # 2 minutes default
# Limit initial aggregation size to reduce cold connect latency (tunable)
TOOLS_MAX_APPS = int(os.getenv('TOOLS_MAX_APPS', '25'))

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


def _get_with_auth(path: str, api_key: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    """Helper to GET from Composio with x-api-key and standard timeouts."""
    url = f"{COMPOSIO_BASE_URL}{path if path.startswith('/') else '/' + path}"
    headers = {
        'x-api-key': api_key,
        # propagate a minimal set of client hints for troubleshooting
        'X-Client': 'composio-proxy',
    }
    return requests.get(url, headers=headers, params=params, timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT))


def _fetch_all_tools(api_key: str, max_apps: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate tools across all apps into a single list compatible with older clients.
    Returns a dict like {"items": [...]}.
    Uses a short-lived in-memory cache keyed by api_key.
    """
    now = time.time()
    cache_key = f"tools::{api_key[:6]}::{TOOLS_CACHE_TTL_SECONDS}::{max_apps or 'all'}"
    cached = _TOOLS_CACHE.get(cache_key)
    if cached and (now - cached[0]) < TOOLS_CACHE_TTL_SECONDS:
        return cached[1]

    # 1) fetch apps
    apps_resp = _get_with_auth('/api/apps', api_key)
    if apps_resp.status_code != 200:
        raise InternalServerError(f"Upstream /api/apps returned {apps_resp.status_code}")
    apps = apps_resp.json()
    if isinstance(apps, dict) and 'items' in apps:
        apps_list = apps['items']
    else:
        # Some deployments return a plain array
        apps_list = apps if isinstance(apps, list) else []

    aggregated: List[Dict[str, Any]] = []
    if max_apps is not None and isinstance(max_apps, int) and max_apps > 0:
        apps_list = apps_list[:max_apps]

    for app in apps_list:
        app_key = app.get('key') or app.get('slug') or app.get('id')
        if not app_key:
            continue
        try:
            tools_resp = _get_with_auth(f"/api/apps/{app_key}/tools/list", api_key)
            if tools_resp.status_code != 200:
                logger.warning(f"Skipping tools for {app_key}: {tools_resp.status_code}")
                continue
            tools_json = tools_resp.json()
            items = tools_json.get('items', []) if isinstance(tools_json, dict) else []
            # Ensure toolkit slug/name present; inject if missing from app
            for t in items:
                tk = t.get('toolkit') or {}
                if not tk:
                    t['toolkit'] = {
                        'slug': app.get('key') or app.get('slug') or 'unknown',
                        'name': app.get('name') or (app.get('key') or 'unknown')
                    }
            aggregated.extend(items)
        except Exception as e:
            logger.warning(f"Error fetching tools for app {app_key}: {e}")
            continue

    result = {"items": aggregated}
    _TOOLS_CACHE[cache_key] = (now, result)
    return result

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

@app.route('/api/tools', methods=['GET', 'OPTIONS'])
def legacy_tools_endpoint():
    """Compatibility endpoint for clients expecting /api/tools.
    Aggregates tools across all apps and returns a single items list.
    """
    if request.method == 'OPTIONS':
        return '', 200

    api_key = extract_api_key_from_request()
    if not api_key:
        return jsonify({
            "error": "Authentication required",
            "message": "Provide API key in Authorization: Bearer <key> header"
        }), 401

    try:
        start = time.time()
        # limit initial aggregation to speed up connect; clients can request more later
        data = _fetch_all_tools(api_key, max_apps=TOOLS_MAX_APPS)
        duration = time.time() - start
        logger.info(f"/api/tools aggregated {len(data.get('items', []))} tools in {duration:.2f}s")
        # Cache-friendly headers
        resp = jsonify(data)
        resp.headers['Cache-Control'] = f"public, max-age={TOOLS_CACHE_TTL_SECONDS}"
        return resp, 200
    except Exception as e:
        logger.error(f"Failed to aggregate tools: {e}")
        return jsonify({
            "error": "Upstream error",
            "message": str(e)
        }), 502


@app.route('/models', methods=['GET', 'OPTIONS'])
def models_endpoint():
    """MCP models endpoint - returns available models for Open WebUI.
    Since Composio is a tools/actions provider, we return a placeholder model list.
    No authentication required for model discovery.
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    # Return a basic model response that Open WebUI expects
    # This doesn't require authentication as it's just metadata
    response = jsonify({
        "data": [
            {
                "id": "composio-tools",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "composio",
                "permission": [],
                "root": "composio-tools",
                "parent": None
            }
        ],
        "object": "list"
    })
    response.headers['Cache-Control'] = 'public, max-age=300'  # Cache for 5 minutes
    return response, 200


@app.route('/v1/models', methods=['GET', 'OPTIONS'])
def v1_models_endpoint():
    """OpenAI-compatible models endpoint for broader client compatibility."""
    if request.method == 'OPTIONS':
        return '', 200
    response = jsonify({
        "data": [
            {
                "id": "composio-tools",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "composio",
                "permission": [],
                "root": "composio-tools",
                "parent": None
            }
        ],
        "object": "list"
    })
    response.headers['Cache-Control'] = 'public, max-age=300'
    return response, 200


@app.route('/mcp/ws', methods=['GET', 'OPTIONS'])
def legacy_sse_notice():
    """Provide a helpful message for clients trying to use deprecated SSE routes."""
    if request.method == 'OPTIONS':
        return '', 200
    return jsonify({
        "error": "SSE is obsolete. Please upgrade your client to latest version or use /api/tools for listing tools.",
        "hint": "This proxy exposes a compatibility /api/tools endpoint for older clients."
    }), 410  # Gone status for obsolete endpoints


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_request(path=''):
    """Proxy all requests to Composio API with authentication transformation."""
    
    # Handle preflight OPTIONS requests
    if request.method == 'OPTIONS':
        return '', 200
    
    # Don't proxy specific endpoints we handle locally
    if path in ['api/tools', 'mcp/ws', 'models', 'v1/models']:
        return jsonify({
            "error": "Route handling error",
            "message": "This endpoint should be handled by a specific route, not the proxy"
        }), 500
    
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
