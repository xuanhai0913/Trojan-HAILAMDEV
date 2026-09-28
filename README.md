# Trojan-HAILAMDEV

Remote Access Trojan implementation for authorized security testing and research purposes.

> **Disclaimer:** Authorized lab/research only. Use this project only on systems you own or have explicit written permission to test. Do not use it for unauthorized access, persistence, surveillance, data collection, or deployment against third parties.

## Architecture

- `src/` — Core implementation modules
- `config/` — Configuration files and templates
- `tests/` — Unit and integration tests
- `docs/` — Documentation and usage guides

## Components

1. **Agent** — Lightweight implant with persistence
2. **C2 Server** — Command and control infrastructure
3. **Communication** — Encrypted channel with protocol obfuscation
4. **Modules** — Extensible capability plugins

## Build

```bash
# Build agent
go build -o bin/agent src/agent/main.go

# Build C2 server
go build -o bin/c2 src/c2/main.go
```

## Configuration

Copy `config/example.yaml` to `config/production.yaml` and adjust:

```yaml
c2:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "certs/server.pem"
  tls_key: "certs/server.key"

agent:
  beacon_interval: 30
  jitter: 0.3
  max_retries: 3
```

## Security Notice

This software is for authorized lab/research only. Unauthorized deployment violates computer fraud and abuse laws. Use only on systems you own or have explicit written permission to test.

## Author

**Author:** Nguyen Xuan Hai

- LinkedIn: [linkedin.com/in/xuanhai0913](https://www.linkedin.com/in/xuanhai0913/)
- Facebook: [facebook.com/nguyenhai0913](https://www.facebook.com/nguyenhai0913)
