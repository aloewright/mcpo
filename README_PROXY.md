# Composio Proxy for Open WebUI

A reliable Flask-based proxy server that bridges Open WebUI to Composio's Model Context Protocol (MCP) API, solving authentication and compatibility issues.

## 🚀 Quick Start

### Deploy to Railway

1. **Fork/Clone this repository** to your GitHub account

2. **Deploy to Railway:**
   - Go to [Railway.app](https://railway.app) and connect your GitHub account
   - Create new project from your forked repository
   - Railway will automatically detect the `railway.config` file and deploy

3. **Set Environment Variables in Railway Dashboard:**
   ```bash
   COMPOSIO_API_KEY=your_composio_api_key_here  # Optional
   LOG_LEVEL=INFO                               # Optional
   ```

4. **Configure Open WebUI:**
   - Set API Base URL to: `https://your-railway-app.railway.app`
   - Set Bearer Token to your Composio API key
   - The proxy will transform the Bearer token to the required `x-api-key` header

## 🔧 How It Works

### The Problem
- **Open WebUI** expects OpenAPI-compatible servers with `Authorization: Bearer <token>` authentication
- **Composio MCP** uses `x-api-key: <key>` authentication headers
- Direct connection results in 502 Bad Gateway errors due to authentication mismatch

### The Solution
This proxy server:

1. **Listens** on Railway's assigned port (`$PORT`)
2. **Accepts** requests with `Authorization: Bearer <token>` headers (Open WebUI format)
3. **Transforms** Bearer tokens to `x-api-key: <token>` headers (Composio format)  
4. **Forwards** all requests to `https://mcp.composio.dev/`
5. **Streams** responses back to Open WebUI with proper CORS headers
6. **Handles** errors gracefully with detailed logging

### Authentication Flow
```
Open WebUI → Proxy Server → Composio MCP API
    ↓             ↓              ↓
Bearer Token → x-api-key → Composio Tools
```

## 📁 Project Structure

```
mcpo/
├── proxy_server.py      # Main Flask application
├── requirements.txt     # Python dependencies
├── railway.config       # Railway deployment configuration
├── test_proxy.py       # Comprehensive test suite
├── .env.example        # Environment variables template
└── README_PROXY.md     # This documentation
```

## 🧪 Local Development & Testing

### Prerequisites
```bash
python3 -m pip install flask flask-cors requests gunicorn
```

### Run Locally
```bash
# Set environment variables
export PORT=8000
export COMPOSIO_API_KEY=your_composio_api_key_here
export LOG_LEVEL=DEBUG

# Start the proxy server
python3 proxy_server.py
```

### Test the Proxy
```bash
# Run comprehensive tests
python3 test_proxy.py

# Test against production deployment
python3 test_proxy.py --url https://your-railway-app.railway.app --api-key your_real_api_key
```

### Manual Testing
```bash
# Health check
curl https://your-railway-app.railway.app/

# Test with Bearer token authentication
curl -H "Authorization: Bearer your_composio_api_key" \
     https://your-railway-app.railway.app/some-endpoint
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port (provided by Railway) | 8000 | Yes |
| `COMPOSIO_API_KEY` | Default API key if not in Bearer token | - | No |
| `LOG_LEVEL` | Logging verbosity (DEBUG/INFO/WARNING/ERROR) | INFO | No |

### Railway Configuration (`railway.config`)

```json
{
  "$schema": "https://railway.com/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "runtime": "V2",
    "numReplicas": 1,
    "startCommand": "gunicorn proxy_server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120 --access-logfile - --error-logfile -",
    "healthcheckPath": "/",
    "sleepApplication": false,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

## 🔍 API Endpoints

### Health Checks
- `GET /` - Basic health check
- `GET /health` - Detailed health check with Composio API connectivity test

### Proxy Endpoints
- `*` (all paths) - Forwards to `https://mcp.composio.dev/<path>` with authentication transformation

### Example Requests

#### Health Check
```bash
curl https://your-railway-app.railway.app/
```
```json
{
  "status": "healthy",
  "service": "composio-proxy",
  "timestamp": 1703123456
}
```

#### Forwarded Request
```bash
curl -H "Authorization: Bearer your_composio_api_key" \
     -H "Content-Type: application/json" \
     https://your-railway-app.railway.app/tools
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. 502 Bad Gateway
**Symptoms:** Open WebUI shows connection errors
**Solutions:**
- Check Railway deployment logs: `railway logs`
- Verify environment variables are set correctly
- Test health endpoints: `curl https://your-app.railway.app/`

#### 2. Authentication Errors  
**Symptoms:** 401 Unauthorized responses
**Solutions:**
- Verify Composio API key is valid
- Check Bearer token format in Open WebUI
- Enable DEBUG logging: `LOG_LEVEL=DEBUG`

#### 3. CORS Issues
**Symptoms:** Browser console shows CORS errors
**Solutions:**
- Verify flask-cors is installed
- Check browser developer tools for specific CORS errors
- The proxy already handles CORS with `origins="*"`

### Debugging Steps

1. **Check Railway Logs:**
   ```bash
   railway logs --follow
   ```

2. **Test Health Endpoints:**
   ```bash
   curl https://your-app.railway.app/health
   ```

3. **Enable Debug Logging:**
   ```bash
   # In Railway dashboard, set:
   LOG_LEVEL=DEBUG
   ```

4. **Run Local Tests:**
   ```bash
   python3 test_proxy.py --url https://your-app.railway.app
   ```

### Log Analysis

The proxy provides structured logging:
```
2024-01-01 12:00:00 - proxy_server - INFO - Proxying GET https://mcp.composio.dev/tools
2024-01-01 12:00:01 - proxy_server - INFO - Response from Composio: 200 (0.45s)
```

## 🚀 Production Deployment

### Railway Deployment (Recommended)

1. **Automatic deployment** via GitHub integration
2. **Environment variables** managed through Railway dashboard  
3. **Automatic SSL** and custom domains supported
4. **Scaling** handled automatically

### Alternative Deployment Options

#### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY proxy_server.py .
EXPOSE 8000
CMD ["gunicorn", "proxy_server:app", "--bind", "0.0.0.0:8000", "--workers", "2"]
```

#### Heroku
```bash
echo "web: gunicorn proxy_server:app --bind 0.0.0.0:$PORT" > Procfile
git push heroku main
```

## 🔒 Security Considerations

- **API keys** are never logged (sanitized in debug output)
- **HTTPS** enforced in production (Railway provides SSL)
- **Input validation** on all forwarded requests
- **Error handling** prevents information leakage
- **CORS** configured securely for web browser access

## 📈 Performance & Monitoring

### Metrics to Monitor
- Response times to Composio API
- Error rates (4xx/5xx responses)  
- Request volume and patterns
- Memory and CPU usage

### Railway Monitoring
Railway provides built-in metrics for:
- Response times
- Error rates
- Resource usage
- Request volume

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `python3 test_proxy.py`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter issues:

1. **Check this README** for troubleshooting steps
2. **Review Railway logs** for error details
3. **Run the test suite** to identify specific problems
4. **Create an issue** with logs and configuration details

---

**Success Indicator:** When properly configured, Open WebUI should successfully connect to Composio tools without 502 errors, and you should see successful request logs in the Railway dashboard.
