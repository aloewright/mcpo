#!/usr/bin/env python3
"""
Minimal working proxy server for Railway deployment testing.
"""

import os
import logging
import time
from flask import Flask, jsonify

# Configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
PORT = int(os.getenv('PORT', 8000))

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint for Railway."""
    logger.info("Health check requested")
    return jsonify({
        "status": "healthy",
        "service": "composio-proxy",
        "timestamp": int(time.time()),
        "message": "Minimal version deployed successfully"
    }), 200

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Test endpoint."""
    return jsonify({
        "message": "Test endpoint working",
        "mcp_toggles": "Coming soon"
    }), 200

if __name__ == '__main__':
    logger.info(f"Starting minimal Composio proxy server on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
