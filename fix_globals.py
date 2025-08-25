#!/usr/bin/env python3

with open('proxy_server.py', 'r') as f:
    content = f.read()

# Fix global declarations by moving them to function start
lines = content.split('\n')
new_lines = []

i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is a function that needs global declaration fixes
    if line.startswith('def openapi_allowed_mcp_servers'):
        new_lines.append(line)  # function def
        i += 1
        new_lines.append(lines[i])  # docstring
        i += 1
        new_lines.append('    global _ALLOWED_SERVERS')  # add global at start
        # Continue with rest of function, removing duplicate globals
        while i < len(lines) and not lines[i].startswith('def ') and not lines[i].startswith('@app.route'):
            if 'global _ALLOWED_SERVERS' not in lines[i]:
                new_lines.append(lines[i])
            i += 1
        continue
    elif line.startswith('def openapi_allowed_toolkits'):
        new_lines.append(line)  # function def
        i += 1
        new_lines.append(lines[i])  # docstring
        i += 1
        new_lines.append('    global _ENABLED_TOOLKITS')  # add global at start
        while i < len(lines) and not lines[i].startswith('def ') and not lines[i].startswith('@app.route'):
            if 'global _ENABLED_TOOLKITS' not in lines[i]:
                new_lines.append(lines[i])
            i += 1
        continue
    elif line.startswith('def openapi_allowed_apps'):
        new_lines.append(line)  # function def
        i += 1
        if i < len(lines) and '"""' in lines[i]:
            new_lines.append(lines[i])  # docstring if present
            i += 1
        new_lines.append('    global _ALLOWED_APPS')  # add global at start
        while i < len(lines) and not lines[i].startswith('def ') and not lines[i].startswith('@app.route'):
            if 'global _ALLOWED_APPS' not in lines[i]:
                new_lines.append(lines[i])
            i += 1
        continue
    else:
        new_lines.append(line)
        i += 1

with open('proxy_server.py', 'w') as f:
    f.write('\n'.join(new_lines))

print("Fixed global declarations")
