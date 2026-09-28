# Trojan-HAILAMDEV API Documentation

## Base URL
```
http://localhost:8443/api/v1
```

## Authentication
Currently no authentication required. For production, implement JWT or API key authentication.

## Endpoints

### Health Check
```
GET /health
```
Response:
```json
{
  "status": "ok",
  "timestamp": 1699999999,
  "version": "1.0.0"
}
```

### Agent Management

#### List Agents
```
GET /agents?status=active
```
Query Parameters:
- `status` (optional): Filter by agent status (active, inactive, disconnected)

Response:
```json
{
  "agents": [
    {
      "id": "uuid",
      "hostname": "target-host",
      "os": "linux",
      "arch": "amd64",
      "username": "user",
      "ip": "192.168.1.100",
      "first_seen": 1699999999,
      "last_seen": 1699999999,
      "status": "active",
      "modules": ["shell", "file", "process"],
      "uptime": 3600.5
    }
  ],
  "total": 1
}
```

#### Get Agent Details
```
GET /agents/:id
```

#### Remove Agent
```
DELETE /agents/:id
```

### Command Management

#### Send Command
```
POST /commands
```
Body:
```json
{
  "agent_id": "uuid",
  "type": "shell",
  "payload": {"command": "whoami"}
}
```

Command Types:
- `shell` - Execute shell command
- `module` - Execute module
- `heartbeat` - Request heartbeat

#### List Commands
```
GET /commands?status=pending&agent_id=uuid
```

#### Get Command Result
```
GET /commands/:id
```

#### Cancel Command
```
DELETE /commands/:id
```

### Module Execution

#### Execute Module
```
POST /modules/execute
```
Body:
```json
{
  "agent_id": "uuid",
  "module": "file",
  "args": {"action": "list", "path": "/home/user"}
}
```

Available Modules:
- `shell` - Shell command execution
- `file` - File operations (read, write, list, delete, upload, download)
- `process` - Process management (list, kill, terminate)
- `network` - Network operations (scan, connections, interfaces, dns)
- `system` - System info (info, users, temperature, cpu)
- `persistence` - Persistence management (install, remove, list)
- `keylogger` - Keystroke logging (start, stop, get, clear)
- `screenshot` - Desktop capture
- `audio` - Microphone recording
- `clipboard` - Clipboard monitoring

#### List Modules
```
GET /modules
```

#### Get Module Info
```
GET /modules/:name
```

### Interactive Shell

#### Initialize Shell Session
```
POST /agents/:id/interact
```

#### Get Shell Status
```
GET /agents/:id/shell
```

#### Send Shell Command
```
POST /agents/:id/shell
```
Body:
```json
{
  "command": "ls -la",
  "timeout": 30
}
```

### Statistics

#### General Stats
```
GET /stats
```

#### Agent Stats
```
GET /stats/agents
```

#### Command Stats
```
GET /stats/commands
```

### WebSocket Endpoints

#### Agent WebSocket
```
GET /ws/agents/:id
```
Real-time agent interaction.

#### Events WebSocket
```
GET /ws/events
```
Real-time server events and statistics.

Message Types:
```json
{
  "type": "stats_update",
  "agent_count": 5,
  "timestamp": 1699999999
}
```

## Error Responses
```json
{
  "error": "description of error"
}
```

Status Codes:
- 200 - Success
- 400 - Bad Request
- 404 - Not Found
- 500 - Internal Server Error