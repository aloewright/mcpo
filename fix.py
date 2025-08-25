#!/usr/bin/env python3
import re

# Read the file
with open('proxy_server.py', 'r') as f:
    content = f.read()

# 1. Remove duplicate route (lines 903-938 approximately)
lines = content.split('\n')
new_lines = []
skip_duplicate = False
for i, line in enumerate(lines):
    if '@app.route(\'/openapi/tools/<slug>\', methods=[\'POST\', \'OPTIONS\'])' in line and i > 700:
        # This is the duplicate route, skip until next @app.route
        skip_duplicate = True
        continue
    elif skip_duplicate and line.startswith('@app.route'):
        skip_duplicate = False
    
    if not skip_duplicate:
        new_lines.append(line)

content = '\n'.join(new_lines)

# 2. Add size limits
content = content.replace(
    'TOOLS_MAX_APPS = int(os.getenv(\'TOOLS_MAX_APPS\', \'15\'))',
    'TOOLS_MAX_APPS = int(os.getenv(\'TOOLS_MAX_APPS\', \'8\'))  # Reduced to prevent 49MB responses'
)

# 3. Add OpenAPI tool limit right after TOOLS_MAX_APPS
content = content.replace(
    'TOOLS_MAX_APPS = int(os.getenv(\'TOOLS_MAX_APPS\', \'8\'))  # Reduced to prevent 49MB responses',
    'TOOLS_MAX_APPS = int(os.getenv(\'TOOLS_MAX_APPS\', \'8\'))  # Reduced to prevent 49MB responses\nOPENAPI_MAX_TOOLS = int(os.getenv(\'OPENAPI_MAX_TOOLS\', \'30\'))  # Hard limit for OpenAPI spec'
)

# 4. Fix max_tools calculation to use the limit
content = re.sub(
    r'max_tools = int\(request\.args\.get\([^)]+\)\)',
    'max_tools = min(int(request.args.get("max", "30")), OPENAPI_MAX_TOOLS)',
    content
)

# 5. Apply the hard limit to filtered tools
content = content.replace(
    'filtered = filtered[:max_tools]',
    'filtered = filtered[:min(max_tools, OPENAPI_MAX_TOOLS)]'
)

# Write the fixed file
with open('proxy_server.py', 'w') as f:
    f.write(content)

print("Fixed proxy_server.py - removed duplicate route and added size limits")
