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
from flask import Flask, request, Response, jsonify, stream_with_context, make_response
from flask_cors import CORS
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.exceptions import BadRequest, InternalServerError
from functools import lru_cache
import threading

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
CORS(
    app,
    origins="*",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "x-api-key"],
    expose_headers=["Content-Type"],
)

# Configuration
COMPOSIO_BASE_URL = "https://mcp.composio.dev"
COMPOSIO_BACKEND_BASE = os.getenv('COMPOSIO_BACKEND_BASE', 'https://backend.composio.dev')
DEFAULT_API_KEY = os.getenv('X_API_KEY', '')
PORT = int(os.getenv('PORT', 8000))

# Request timeout settings
REQUEST_TIMEOUT = 60
CONNECTION_TIMEOUT = 10

# Connection pooling session for better performance
_session = None
_session_lock = threading.Lock()

def get_requests_session():
    """Get a shared requests session with connection pooling and retry logic."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                _session = requests.Session()
                
                # Configure retry strategy
                retry_strategy = Retry(
                    total=2,
                    backoff_factor=0.1,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                
                # Mount adapters with connection pooling
                adapter = HTTPAdapter(
                    max_retries=retry_strategy,
                    pool_connections=20,
                    pool_maxsize=100
                )
                _session.mount("http://", adapter)
                _session.mount("https://", adapter)
                
    return _session

# Enhanced in-memory cache for expensive aggregations
_TOOLS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_SERVERS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
TOOLS_CACHE_TTL_SECONDS = int(os.getenv('TOOLS_CACHE_TTL_SECONDS', '300'))
SERVERS_CACHE_TTL_SECONDS = int(os.getenv('SERVERS_CACHE_TTL_SECONDS', '600'))
# CRITICAL: Limit tools to prevent 49MB response
TOOLS_MAX_APPS = int(os.getenv('TOOLS_MAX_APPS', '10'))  # Reduced from 15
OPENAPI_MAX_TOOLS = int(os.getenv('OPENAPI_MAX_TOOLS', '50'))  # NEW: Hard limit for OpenAPI

# In-memory allowlist of apps the user wants enabled
_ALLOWED_APPS: set[str] = set()
# Allowlist by MCP server id (from backend API v3 mcp servers)
_ALLOWED_SERVERS: set[str] = set()
_ENABLED_TOOLKITS: set[str] = set()

# Add performance headers to all responses
@app.after_request
def add_performance_headers(response):
    """Add performance and security headers to all responses."""
    response.headers['Connection'] = 'keep-alive'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    
    if request.endpoint in ['health_check', 'detailed_health']:
        response.headers['Cache-Control'] = 'public, max-age=30'
    elif request.path == '/openapi.json':
        response.headers['Cache-Control'] = 'public, max-age=300'
    
    return response

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint for Railway."""
    response = jsonify({
        "status": "healthy",
        "service": "composio-proxy",
        "timestamp": int(time.time())
    })
    response.headers['Cache-Control'] = 'public, max-age=30'
    response.headers['Connection'] = 'keep-alive'
    return response, 200

@app.route('/health', methods=['GET'])
def detailed_health():
    """Detailed health check endpoint."""
    try:
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
        api_key = auth_header[7:]
        logger.debug(f"Extracted API key from Bearer token (length: {len(api_key)})")
        return api_key
    elif DEFAULT_API_KEY:
        logger.debug("Using default API key")
        return DEFAULT_API_KEY
    else:
        logger.warning("No API key found in Authorization header and no default configured")
        return None

def _get_with_auth(path: str, api_key: str, params: Optional[Dict[str, Any]] = None, *, base: Optional[str] = None) -> requests.Response:
    """Helper to GET from Composio with x-api-key and standard timeouts."""
    root = base or COMPOSIO_BASE_URL
    url = f"{root}{path if path.startswith('/') else '/' + path}"
    headers = {
        'x-api-key': api_key,
        'X-Client': 'composio-proxy',
        'Connection': 'keep-alive',
    }
    session = get_requests_session()
    return session.get(url, headers=headers, params=params, timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT))

@lru_cache(maxsize=32)
def _get_cached_servers(api_key_hash: str, base_url: str) -> Dict[str, Any]:
    """Cache MCP servers list with LRU cache."""
    try:
        resp = _get_with_auth('/api/v3/mcp/servers', api_key_hash, base=base_url)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch servers: {e}")
    return {"items": []}

def _apply_server_and_toolkit_filters(tools: List[Dict[str, Any]], api_key: str) -> List[Dict[str, Any]]:
    """Apply server and toolkit filtering to tools list."""
    if not _ALLOWED_SERVERS and not _ENABLED_TOOLKITS:
        return tools
    
    # Apply server allowlist by toolkit membership
    if _ALLOWED_SERVERS:
        api_key_hash = api_key[:16]
        servers_data = _get_cached_servers(api_key_hash, COMPOSIO_BACKEND_BASE)
        allowed_toolkits_by_server = set()
        for s in servers_data.get('items', []):
            if str(s.get('id')).lower() in _ALLOWED_SERVERS:
                for tk in (s.get('toolkits') or []):
                    allowed_toolkits_by_server.add(str(tk).lower())
        tools = [t for t in tools if ((t.get('toolkit') or {}).get('slug') or '').lower() in allowed_toolkits_by_server]
    
    # Apply direct toolkit filtering
    if _ENABLED_TOOLKITS:
        tools = [t for t in tools if ((t.get('toolkit') or {}).get('slug') or '').lower() in _ENABLED_TOOLKITS]
    
    return tools

def _fetch_all_tools(api_key: str, max_apps: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate tools across all apps into a single list."""
    now = time.time()
    cache_key = f"tools::{api_key[:8]}::{max_apps or 'all'}::{hash(tuple(sorted(_ALLOWED_APPS)))}"
    cached = _TOOLS_CACHE.get(cache_key)
    if cached and (now - cached[0]) < TOOLS_CACHE_TTL_SECONDS:
        logger.debug(f"Using cached tools (age: {now - cached[0]:.1f}s)")
        return cached[1]

    start_time = time.time()
    
    # Fetch apps with connection pooling
    apps_resp = _get_with_auth('/api/apps', api_key)
    if apps_resp.status_code != 200:
        raise InternalServerError(f"Upstream /api/apps returned {apps_resp.status_code}")
    apps = apps_resp.json()
    if isinstance(apps, dict) and 'items' in apps:
        apps_list = apps['items']
    else:
        apps_list = apps if isinstance(apps, list) else []

    # Apply limits early to reduce processing
    if max_apps is not None and isinstance(max_apps, int) and max_apps > 0:
        apps_list = apps_list[:max_apps]
        
    # Pre-filter by allowed apps if set
    if _ALLOWED_APPS:
        apps_list = [app for app in apps_list 
                    if (app.get('key') or app.get('slug') or '').lower() in _ALLOWED_APPS]

    aggregated: List[Dict[str, Any]] = []
    session = get_requests_session()
    
    for app in apps_list:
        app_key = app.get('key') or app.get('slug') or app.get('id')
        if not app_key:
            continue
        try:
            tools_resp = _get_with_auth(f"/api/apps/{app_key}/tools/list", api_key)
            if tools_resp.status_code != 200:
                logger.debug(f"Skipping tools for {app_key}: {tools_resp.status_code}")
                continue
            tools_json = tools_resp.json()
            items = tools_json.get('items', []) if isinstance(tools_json, dict) else []
            for t in items:
                tk = t.get('toolkit') or {}
                if not tk:
                    t['toolkit'] = {
                        'slug': app.get('key') or app.get('slug') or 'unknown',
                        'name': app.get('name') or (app.get('key') or 'unknown')
                    }
            aggregated.extend(items)
        except Exception as e:
            logger.debug(f"Error fetching tools for app {app_key}: {e}")
            continue

    result = {"items": aggregated}
    _TOOLS_CACHE[cache_key] = (now, result)
    
    fetch_duration = time.time() - start_time
    logger.info(f"Fetched {len(aggregated)} tools from {len(apps_list)} apps in {fetch_duration:.2f}s")
    
    return result

def sanitize_headers_for_logging(headers):
    """Sanitize headers for logging by removing sensitive information."""
    sanitized = dict(headers)
    sensitive_headers = ['authorization', 'x-api-key', 'cookie', 'set-cookie']
    
    for header in sensitive_headers:
        if header in sanitized:
            sanitized[header] = '[REDACTED]'
        header_lower = header.lower()
        if header_lower in sanitized:
            sanitized[header_lower] = '[REDACTED]'
    
    return sanitized

@app.route('/openapi.json', methods=['GET', 'OPTIONS'])
def openapi_endpoint():
    """Serve OpenAPI schema with server URL rewritten to this proxy's absolute URL."""
    if request.method == 'OPTIONS':
        return '', 200

    try:
        # Fetch upstream openapi
        upstream = requests.get(
            f"{COMPOSIO_BASE_URL}/openapi.json",
            headers={"x-api-key": DEFAULT_API_KEY} if DEFAULT_API_KEY else None,
            timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT),
        )
        upstream.raise_for_status()
        data = upstream.json()

        # Rewrite servers to absolute URL of this proxy
        base_url = request.url_root.rstrip('/')
        data['servers'] = [
            {"url": base_url, "description": "Proxy base"},
            {"url": "/", "description": "Relative (upstream default)"},
        ]

        resp = jsonify(data)
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp, 200
    except Exception as e:
        logger.error(f"Failed to serve openapi.json: {e}")
        return jsonify({"error": "OpenAPI fetch failed", "message": str(e)}), 502

def _format_tools_manifest(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a manifest that matches common tool formats (OpenAI, generic)."""
    tools_as_functions = []
    tools_simple = []
    for t in items:
        slug = t.get('slug') or t.get('name')
        title = t.get('name') or slug
        desc = t.get('description') or ''
        params = t.get('input_parameters') or {"type": "object", "properties": {}}
        tools_as_functions.append({
            "type": "function",
            "function": {
                "name": slug,
                "description": desc or title,
                "parameters": params
            }
        })
        tools_simple.append({
            "name": slug,
            "title": title,
            "description": desc,
            "parameters": params
        })
    return {
        "items": items,
        "tools": tools_simple,
        "openai_tools": tools_as_functions,
        "count": len(items)
    }

@app.route('/api/tools', methods=['GET', 'OPTIONS'])
def legacy_tools_endpoint():
    """Compatibility endpoint for clients expecting /api/tools."""
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
        data = _fetch_all_tools(api_key, max_apps=TOOLS_MAX_APPS)
        duration = time.time() - start
        logger.info(f"/api/tools aggregated {len(data.get('items', []))} tools in {duration:.2f}s")
        manifest = _format_tools_manifest(data.get('items', []))
        resp = jsonify(manifest)
        resp.headers['Cache-Control'] = f"public, max-age={TOOLS_CACHE_TTL_SECONDS}"
        return resp, 200
    except Exception as e:
        logger.error(f"Failed to aggregate tools: {e}")
        return jsonify({
            "error": "Upstream error",
            "message": str(e)
        }), 502

@app.route('/tools', methods=['GET', 'OPTIONS'])
@app.route('/api/tools/manifest', methods=['GET', 'OPTIONS'])
@app.route('/tools/manifest', methods=['GET', 'OPTIONS'])
def tools_manifest_endpoint():
    """Expose tools with multiple shapes."""
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
        data = _fetch_all_tools(api_key, max_apps=TOOLS_MAX_APPS)
        duration = time.time() - start
        logger.info(f"{request.path} aggregated {len(data.get('items', []))} tools in {duration:.2f}s")
        manifest = _format_tools_manifest(data.get('items', []))
        resp = jsonify(manifest)
        resp.headers['Cache-Control'] = f"public, max-age={TOOLS_CACHE_TTL_SECONDS}"
        return resp, 200
    except Exception as e:
        logger.error(f"Failed to aggregate tools (manifest): {e}")
        return jsonify({
            "error": "Upstream error",
            "message": str(e)
        }), 502

@app.route('/models', methods=['GET', 'OPTIONS'])
def models_endpoint():
    """MCP models endpoint - returns available models for Open WebUI."""
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

@app.route('/openapi.tools.json', methods=['GET', 'OPTIONS'])
def dynamic_tools_openapi():
    """Dynamically generate an OpenAPI spec exposing Composio tools - FIXED for size issues."""
    if request.method == 'OPTIONS':
        return '', 200

    api_key = extract_api_key_from_request() or DEFAULT_API_KEY
    if not api_key:
        return jsonify({"error": "Authentication required"}), 401

    try:
        # Parse filters
        apps_param = request.args.get('apps', '').strip()
        apps_filter = [a.strip().lower() for a in apps_param.split(',') if a.strip()] if apps_param else []
        q = (request.args.get('q') or '').strip().lower()
        try:
            max_tools = min(int(request.args.get('max', '50')), OPENAPI_MAX_TOOLS)  # HARD LIMIT
        except Exception:
            max_tools = OPENAPI_MAX_TOOLS
        mode = (request.args.get('mode') or 'generic').lower()  # Default to generic

        tools = _fetch_all_tools(api_key, max_apps=TOOLS_MAX_APPS).get('items', [])
        
        # Apply server and toolkit filtering
        tools = _apply_server_and_toolkit_filters(tools, api_key)
        
        # Apply legacy apps allowlist if set
        if _ALLOWED_APPS:
            tools = [t for t in tools if ((t.get('toolkit') or {}).get('slug') or '').lower() in _ALLOWED_APPS]

        def tool_matches(t: Dict[str, Any]) -> bool:
            tk = (t.get('toolkit') or {}).get('slug') or (t.get('toolkit') or {}).get('name') or ''
            if apps_filter and (tk or '').lower() not in apps_filter:
                return False
            if not q:
                return True
            text = ' '.join([
                str(t.get('slug') or ''),
                str(t.get('name') or ''),
                str(t.get('description') or ''),
                str(tk or '')
            ]).lower()
            return q in text

        filtered = [t for t in tools if tool_matches(t)]
        # CRITICAL: Apply hard limit to prevent massive responses
        if max_tools > 0:
            filtered = filtered[:max_tools]

        base_url = request.url_root.rstrip('/')
        paths: Dict[str, Any] = {}

        # Always use generic mode to reduce response size
        paths['/openapi/tools/invoke'] = {
            "post": {
                "operationId": "invoke_tool",
                "summary": "Invoke a Composio tool by name",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Tool slug"},
                                    "args": {"type": "object", "additionalProperties": True}
                                },
                                "required": ["name", "args"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Invocation result", "content": {"application/json": {"schema": {"type": "object"}}}},
                    "default": {"description": "Error", "content": {"application/json": {"schema": {"type": "object"}}}}
                }
            }
        }

        # Management endpoints
        paths['/openapi/mcp/servers'] = {
            "get": {
                "operationId": "list_mcp_servers",
                "summary": "List user's MCP servers",
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            }
        }
        paths['/openapi/mcp/servers/allowed'] = {
            "get": {
                "operationId": "get_allowed_servers",
                "summary": "Get enabled MCP servers",
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            },
            "post": {
                "operationId": "set_allowed_servers",
                "summary": "Enable specific MCP servers",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"servers": {"type": "array", "items": {"type": "string"}}}, "required": ["servers"]}}}},
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            }
        }
        paths['/openapi/toolkits'] = {
            "get": {
                "operationId": "list_toolkits",
                "summary": "List available toolkits",
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            }
        }
        paths['/openapi/toolkits/allowed'] = {
            "get": {
                "operationId": "get_allowed_toolkits",
                "summary": "Get enabled toolkits",
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            },
            "post": {
                "operationId": "set_allowed_toolkits",
                "summary": "Enable specific toolkits",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"toolkits": {"type": "array", "items": {"type": "string"}}}, "required": ["toolkits"]}}}},
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}
            }
        }

        spec = {
            "openapi": "3.1.0",
            "info": {"title": "Composio Tools via Proxy", "version": "1.0.0"},
            "servers": [{"url": base_url, "description": "Proxy base"}],
            "paths": paths,
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearerAuth": []}]
        }
        
        # Log response size for monitoring
        import json
        spec_size = len(json.dumps(spec, separators=(',', ':')))
        logger.info(f"Generated OpenAPI spec: {len(filtered)} tools, {spec_size} bytes")
        
        resp = jsonify(spec)
        resp.headers['Cache-Control'] = 'public, max-age=120'
        return resp, 200
    except Exception as e:
        logger.error(f"Failed to generate tools OpenAPI: {e}")
        return jsonify({"error": "Failed to generate OpenAPI", "message": str(e)}), 500

@app.route('/openapi/tools/invoke', methods=['POST', 'OPTIONS'])
def openapi_tool_invoke_generic():
    """Generic invoke endpoint used for all tool invocations."""
    if request.method == 'OPTIONS':
        return '', 200

    api_key = extract_api_key_from_request() or DEFAULT_API_KEY
    if not api_key:
        return jsonify({"error": "Authentication required"}), 401

    payload = request.get_json(silent=True) or {}
    name = (payload.get('name') or '').strip()
    args = payload.get('args') or {}
    if not name:
        return jsonify({"error": "Invalid request", "message": "Missing tool 'name'"}), 400

    try:
        tools = _fetch_all_tools(api_key, max_apps=None).get('items', [])
        # Apply server and toolkit filtering
        tools = _apply_server_and_toolkit_filters(tools, api_key)
        
        # Apply legacy apps allowlist if set
        if _ALLOWED_APPS:
            tools = [t for t in tools if ((t.get('toolkit') or {}).get('slug') or '').lower() in _ALLOWED_APPS]
        tool = next((t for t in tools if (t.get('slug') or '').lower() == name.lower()), None)
        if not tool:
            return jsonify({"error": "Not found", "message": f"Tool '{name}' not found"}), 404
        toolkit = tool.get('toolkit') or {}
        app_key = toolkit.get('slug') or toolkit.get('name')
        if not app_key:
            return jsonify({"error": "Unknown app", "message": f"No app/toolkit info for tool '{name}'"}), 400

        target = f"{COMPOSIO_BASE_URL}/api/apps/{app_key}/tools/{name}/execute"
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        upstream = requests.post(target, headers=headers, json=args, timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT))
        try:
            body = upstream.json()
        except Exception:
            body = {"raw": upstream.text}
        return make_response(jsonify(body), upstream.status_code)
    except Exception as e:
        logger.error(f"Generic tool invoke failed: {e}")
        return jsonify({"error": "Invoke failed", "message": str(e)}), 500

@app.route('/openapi/apps', methods=['GET'])
def openapi_list_apps():
    api_key = extract_api_key_from_request() or DEFAULT_API_KEY
    if not api_key:
        return jsonify({"error": "Authentication required"}), 401
    try:
        resp = _get_with_auth('/api/apps', api_key)
        return make_response(resp.json(), resp.status_code)
    except Exception as e:
        logger.error(f"List apps failed: {e}")
        return jsonify({"error": "Failed", "message": str(e)}), 500

@app.route('/openapi/mcp/servers', methods=['GET'])
def openapi_list_mcp_servers():
    api_key = extract_api_key_from_request() or DEFAULT_API_KEY
    if not api_key:
        return jsonify({"error": "Authentication required"}), 401
    try:
        resp = _get_with_auth('/api/v3/mcp/servers', api_key, base=COMPOSIO_BACKEND_BASE)
        return make_response(resp.json(), resp.status_code)
    except Exception as e:
        logger.error(f"List MCP servers failed: {e}")
        return jsonify({"error": "Failed", "message": str(e)}), 500

@app.route('/openapi/mcp/servers/allowed', methods=['GET', 'POST', 'OPTIONS'])
def openapi_allowed_mcp_servers():
    """Manage allowed MCP servers for tool filtering."""
    if request.method == 'OPTIONS':
        return '', 200
    if request.method == 'GET':
        return jsonify({"servers": sorted(list(_ALLOWED_SERVERS))})
    payload = request.get_json(silent=True) or {}
    servers = payload.get('servers') or []
    if not isinstance(servers, list):
        return jsonify({"error": "Invalid body", "message": "servers must be an array"}), 400
    global _ALLOWED_SERVERS
    _ALLOWED_SERVERS = set([str(s).lower() for s in servers if str(s).strip()])
    logger.info(f"Updated allowed servers: {sorted(list(_ALLOWED_SERVERS))}")
    return jsonify({"ok": True, "servers": sorted(list(_ALLOWED_SERVERS))})

@app.route('/openapi/toolkits', methods=['GET'])
def openapi_list_toolkits():
    """List all available toolkits from user's MCP servers."""
    api_key = extract_api_key_from_request() or DEFAULT_API_KEY
    if not api_key:
        return jsonify({"error": "Authentication required"}), 401
    try:
        servers_resp = _get_with_auth('/api/v3/mcp/servers', api_key, base=COMPOSIO_BACKEND_BASE)
        if servers_resp.status_code != 200:
            return jsonify({"error": "Failed to fetch servers"}), servers_resp.status_code
        
        servers_data = servers_resp.json()
        toolkits = set()
        server_toolkit_map = {}
        
        for server in servers_data.get('items', []):
            server_id = str(server.get('id', ''))
            server_name = server.get('name', f"Server {server_id}")
            server_toolkits = server.get('toolkits', [])
            
            for toolkit in server_toolkits:
                toolkit_name = str(toolkit).lower()
                toolkits.add(toolkit_name)
                if toolkit_name not in server_toolkit_map:
                    server_toolkit_map[toolkit_name] = []
                server_toolkit_map[toolkit_name].append({
                    'id': server_id,
                    'name': server_name
                })
        
        return jsonify({
            "toolkits": sorted(list(toolkits)),
            "server_toolkit_map": server_toolkit_map
        })
    except Exception as e:
        logger.error(f"List toolkits failed: {e}")
        return jsonify({"error": "Failed", "message": str(e)}), 500

@app.route('/openapi/toolkits/allowed', methods=['GET', 'POST', 'OPTIONS'])
def openapi_allowed_toolkits():
    """Manage allowed toolkits for tool filtering."""
    if request.method == 'OPTIONS':
        return '', 200
    if request.method == 'GET':
        return jsonify({"toolkits": sorted(list(_ENABLED_TOOLKITS))})
    payload = request.get_json(silent=True) or {}
    toolkits = payload.get('toolkits') or []
    if not isinstance(toolkits, list):
        return jsonify({"error": "Invalid body", "message": "toolkits must be an array"}), 400
    global _ENABLED_TOOLKITS
    _ENABLED_TOOLKITS = set([str(t).lower() for t in toolkits if str(t).strip()])
    logger.info(f"Updated enabled toolkits: {sorted(list(_ENABLED_TOOLKITS))}")
    return jsonify({"ok": True, "toolkits": sorted(list(_ENABLED_TOOLKITS))})

@app.route('/openapi/apps/allowed', methods=['GET', 'POST', 'OPTIONS'])
def openapi_allowed_apps():
    if request.method == 'OPTIONS':
        return '', 200
    if request.method == 'GET':
        return jsonify({"apps": sorted(list(_ALLOWED_APPS))})
    payload = request.get_json(silent=True) or {}
    apps = payload.get('apps') or []
    if not isinstance(apps, list):
        return jsonify({"error": "Invalid body", "message": "apps must be an array"}), 400
    global _ALLOWED_APPS
    _ALLOWED_APPS = set([str(a).lower() for a in apps if str(a).strip()])
    return jsonify({"ok": True, "apps": sorted(list(_ALLOWED_APPS))})

@app.route('/mcp/ws', methods=['GET', 'OPTIONS'])
def legacy_sse_notice():
    """Provide a helpful message for clients trying to use deprecated SSE routes."""
    if request.method == 'OPTIONS':
        return '', 200
    return jsonify({
        "error": "SSE is obsolete. Please upgrade your client to latest version or use /api/tools for listing tools.",
        "hint": "This proxy exposes a compatibility /api/tools endpoint for older clients."
    }), 410

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_request(path=''):
    """Proxy all requests to Composio API with authentication transformation."""
    
    # Handle preflight OPTIONS requests
    if request.method == 'OPTIONS':
        return '', 200
    
    # Don't proxy specific endpoints we handle locally
    if path in ['api/tools', 'mcp/ws', 'models', 'v1/models', 'openapi.json', 'tools', 'api/tools/manifest', 'tools/manifest', 'openapi.tools.json'] or path.startswith('openapi/'):
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
            if key.lower() not in ['host', 'authorization', 'connection', 'upgrade', 
                                  'proxy-authenticate', 'proxy-authorization', 'te', 
                                  'trailers', 'transfer-encoding']:
                headers[key] = value
        
        headers['x-api-key'] = api_key
        
        logger.info(f"Proxying {request.method} {target_url}")
        logger.debug(f"Request headers: {sanitize_headers_for_logging(headers)}")
        
        request_data = None
        if request.method in ['POST', 'PUT', 'PATCH'] and request.data:
            request_data = request.data
            logger.debug(f"Request body length: {len(request_data)} bytes")
        
        # Make request to Composio API with streaming and connection pooling
        session = get_requests_session()
        response = session.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request_data,
            params=None,
            timeout=(CONNECTION_TIMEOUT, REQUEST_TIMEOUT),
            stream=True,
            allow_redirects=True
        )
        
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
