package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"fei/control-plane/internal/storage"

	"github.com/nats-io/nats.go"
)

type AgentState int

const (
	AgentOnline  AgentState = 1
	AgentOffline AgentState = 0
)

type Agent struct {
	ID        string     `json:"id"`
	State     AgentState `json:"state"`
	LastSeen  time.Time  `json:"last_seen"`
	FirstSeen time.Time  `json:"first_seen"`
	Hostname  string     `json:"hostname"`
	OSInfo    string     `json:"os_info"`
	IPAddress string     `json:"ip_address"`
}

type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskSent      TaskStatus = "sent"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskTimeout   TaskStatus = "timeout"
)

type Task struct {
	ID        string     `json:"id"`
	AgentID   string     `json:"agent_id"`
	Type      uint16     `json:"type"`
	Payload   []byte     `json:"payload"`
	Status    TaskStatus `json:"status"`
	Created   time.Time  `json:"created"`
	Updated   time.Time  `json:"updated"`
	Result    []byte     `json:"result,omitempty"`
	ErrReason string     `json:"error,omitempty"`
}

type ControlPlane struct {
	natsURL    string
	grpcAddr   string
	httpAddr   string
	dataDir    string
	nc         *nats.Conn
	store      *storage.FileStore
	agents     sync.Map
	tasks      sync.Map
	taskSeq    uint64
	taskMu     sync.Mutex
	dirtyMu    sync.Mutex
	dirty      bool
	grpcServer *GRPCServer
}

func (cp *ControlPlane) markDirty() {
	cp.dirtyMu.Lock()
	cp.dirty = true
	cp.dirtyMu.Unlock()
}

func (cp *ControlPlane) snapshot() {
	snap := &storage.Snapshot{Version: 1, TaskSeq: cp.taskSeq}
	cp.agents.Range(func(_, v interface{}) bool {
		a := v.(*Agent)
		snap.Agents = append(snap.Agents, storage.AgentRecord{
			ID: a.ID, State: int(a.State), LastSeen: a.LastSeen, FirstSeen: a.FirstSeen,
			Hostname: a.Hostname, OSInfo: a.OSInfo, IPAddress: a.IPAddress,
		})
		return true
	})
	cp.tasks.Range(func(_, v interface{}) bool {
		t := v.(*Task)
		snap.Tasks = append(snap.Tasks, storage.TaskRecord{
			ID: t.ID, AgentID: t.AgentID, Type: t.Type, Payload: t.Payload,
			Status: string(t.Status), Created: t.Created, Updated: t.Updated,
			Result: t.Result, ErrReason: t.ErrReason,
		})
		return true
	})
	if err := cp.store.Save(snap); err != nil {
		log.Printf("snapshot save: %v", err)
		return
	}
	cp.dirtyMu.Lock()
	cp.dirty = false
	cp.dirtyMu.Unlock()
}

func (cp *ControlPlane) restore() {
	snap, err := cp.store.Load()
	if err != nil {
		log.Printf("snapshot load: %v", err)
		return
	}
	cp.taskSeq = snap.TaskSeq
	for _, a := range snap.Agents {
		cp.agents.Store(a.ID, &Agent{
			ID: a.ID, State: AgentState(a.State), LastSeen: a.LastSeen, FirstSeen: a.FirstSeen,
			Hostname: a.Hostname, OSInfo: a.OSInfo, IPAddress: a.IPAddress,
		})
	}
	for _, t := range snap.Tasks {
		cp.tasks.Store(t.ID, &Task{
			ID: t.ID, AgentID: t.AgentID, Type: t.Type, Payload: t.Payload,
			Status: TaskStatus(t.Status), Created: t.Created, Updated: t.Updated,
			Result: t.Result, ErrReason: t.ErrReason,
		})
	}
	log.Printf("restored %d agents, %d tasks", len(snap.Agents), len(snap.Tasks))
}

func (cp *ControlPlane) snapshotLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cp.dirtyMu.Lock()
		d := cp.dirty
		cp.dirtyMu.Unlock()
		if d {
			cp.snapshot()
		}
	}
}

func main() {
	cp := &ControlPlane{}
	flag.StringVar(&cp.natsURL, "nats", nats.DefaultURL, "NATS server URL")
	flag.StringVar(&cp.grpcAddr, "grpc", ":50051", "gRPC server listen address")
	flag.StringVar(&cp.httpAddr, "http", ":8080", "HTTP REST API listen address")
	flag.StringVar(&cp.dataDir, "data", "./data", "persistent state directory")
	flag.Parse()

	store, err := storage.NewFileStore(cp.dataDir)
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}
	cp.store = store
	cp.restore()

	nc, err := nats.Connect(cp.natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("NATS disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Println("NATS reconnected")
		}),
	)
	if err != nil {
		log.Fatalf("connect to NATS: %v", err)
	}
	cp.nc = nc
	defer nc.Close()
	log.Printf("connected to NATS at %s", cp.natsURL)

	if err := cp.subscribeEvents(); err != nil {
		log.Fatalf("subscribe events: %v", err)
	}

	if err := cp.subscribeAPI(); err != nil {
		log.Fatalf("subscribe API: %v", err)
	}

	grpcServer := NewGRPCServer(cp, cp.grpcAddr)
	if err := grpcServer.Start(); err != nil {
		log.Fatalf("start gRPC server: %v", err)
	}
	cp.grpcServer = grpcServer

	go cp.startHTTPServer()
	go cp.taskTimeoutChecker()
	go cp.snapshotLoop()

	log.Println("control plane ready")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down, final snapshot...")
	grpcServer.Stop()
	cp.snapshot()
}

func (cp *ControlPlane) subscribeEvents() error {
	_, err := cp.nc.Subscribe("fei.event.>", func(msg *nats.Msg) {
		cp.handleEvent(msg)
	})
	return err
}

func (cp *ControlPlane) subscribeAPI() error {
	_, err := cp.nc.Subscribe("fei.api.>", func(msg *nats.Msg) {
		cp.handleAPIRequest(msg)
	})
	return err
}

func (cp *ControlPlane) handleEvent(msg *nats.Msg) {
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		log.Printf("malformed event subject: %s", msg.Subject)
		return
	}
	agentID := parts[2]
	eventType := parts[3]

	var evt map[string]interface{}
	if err := json.Unmarshal(msg.Data, &evt); err != nil {
		log.Printf("unmarshal event: %v", err)
		return
	}

	switch eventType {
	case "agent_online":
		hostname, _ := evt["hostname"].(string)
		ipAddress, _ := evt["ip_address"].(string)
		osInfo, _ := evt["os_info"].(string)
		if hostname == "" {
			hostname = "unknown"
		}
		if ipAddress == "" {
			ipAddress = "unknown"
		}
		if osInfo == "" {
			osInfo = "unknown"
		}

		now := time.Now()
		var agent *Agent
		if existing, ok := cp.agents.Load(agentID); ok {
			agent = existing.(*Agent)
			agent.State = AgentOnline
			agent.LastSeen = now
		} else {
			agent = &Agent{
				ID:        agentID,
				State:     AgentOnline,
				LastSeen:  now,
				FirstSeen: now,
			}
		}
		agent.Hostname = hostname
		agent.IPAddress = ipAddress
		agent.OSInfo = osInfo
		cp.agents.Store(agentID, agent)
		cp.markDirty()
		log.Printf("agent online: %s (hostname=%s, ip=%s, os=%s)", agentID, hostname, ipAddress, osInfo)

	case "agent_offline", "agent_timeout":
		if val, ok := cp.agents.Load(agentID); ok {
			agent := val.(*Agent)
			agent.State = AgentOffline
			agent.LastSeen = time.Now()
			cp.markDirty()
		}
		log.Printf("agent %s: %s", eventType, agentID)

	case "heartbeat":
		if val, ok := cp.agents.Load(agentID); ok {
			agent := val.(*Agent)
			agent.LastSeen = time.Now()
			agent.State = AgentOnline
		}

	case "exec_return":
		if cp.handleExecReturn(agentID, evt) {
			cp.markDirty()
		}

	case "exception":
		log.Printf("agent exception: %s - %v", agentID, evt["payload"])

	case "plugin_load":
		log.Printf("plugin load ack: %s", agentID)

	case "destroy":
		log.Printf("destroy ack: %s", agentID)

	default:
		log.Printf("unhandled event: %s from %s", eventType, agentID)
	}
}

func (cp *ControlPlane) handleExecReturn(agentID string, evt map[string]any) bool {
	payloadRaw, ok := evt["payload"]
	if !ok {
		return false
	}
	var payload []byte
	switch v := payloadRaw.(type) {
	case string:
		payload = []byte(v)
	case []byte:
		payload = v
	case []any:
		for _, item := range v {
			if n, ok := item.(float64); ok {
				payload = append(payload, byte(n))
			}
		}
	}

	// Prefer exact task_id correlation if gateway provided it.
	if taskIDRaw, ok := evt["task_id"]; ok {
		var taskID string
		switch v := taskIDRaw.(type) {
		case string:
			taskID = v
		case []byte:
			taskID = string(v)
		}
		if taskID != "" {
			if val, ok := cp.tasks.Load(taskID); ok {
				task := val.(*Task)
				if task.AgentID == agentID && task.Status == TaskSent {
					task.Result = payload
					task.Status = TaskCompleted
					task.Updated = time.Now()
					log.Printf("task %s completed for agent %s (matched by task_id)", taskID, agentID)
					return true
				}
			}
		}
	}

	// Fallback: match the most recently sent task for this agent.
	var matched *Task
	cp.tasks.Range(func(key, value any) bool {
		task := value.(*Task)
		if task.AgentID == agentID && task.Status == TaskSent {
			if matched == nil || task.Updated.After(matched.Updated) {
				matched = task
			}
		}
		return true
	})
	if matched != nil {
		matched.Result = payload
		matched.Status = TaskCompleted
		matched.Updated = time.Now()
		log.Printf("task %s completed for agent %s (fallback match)", matched.ID, agentID)
		return true
	}

	return false
}

func (cp *ControlPlane) handleAPIRequest(msg *nats.Msg) {
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 3 {
		cp.replyError(msg, "malformed API subject")
		return
	}
	action := parts[2]

	switch action {
	case "list_agents":
		cp.apiListAgents(msg)
	case "send_command":
		cp.apiSendCommand(msg)
	case "get_task":
		cp.apiGetTask(msg)
	case "list_tasks":
		cp.apiListTasks(msg)
	case "agent_info":
		if len(parts) >= 4 {
			cp.apiGetAgentInfo(msg, parts[3])
		} else {
			cp.replyError(msg, "agent_id required")
		}
	default:
		cp.replyError(msg, fmt.Sprintf("unknown action: %s", action))
	}
}

func (cp *ControlPlane) apiListAgents(msg *nats.Msg) {
	var agents []*Agent
	cp.agents.Range(func(_, value interface{}) bool {
		agent := value.(*Agent)
		agents = append(agents, agent)
		return true
	})

	resp := map[string]interface{}{
		"success": true,
		"agents":  agents,
		"count":   len(agents),
	}
	data, _ := json.Marshal(resp)
	msg.Respond(data)
}

func (cp *ControlPlane) apiSendCommand(msg *nats.Msg) {
	var req struct {
		AgentID string `json:"agent_id"`
		Type    uint16 `json:"type"`
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		cp.replyError(msg, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if _, ok := cp.agents.Load(req.AgentID); !ok {
		cp.replyError(msg, fmt.Sprintf("agent %s not found", req.AgentID))
		return
	}

	taskID := cp.nextTaskID()
	task := &Task{
		ID:      taskID,
		AgentID: req.AgentID,
		Type:    req.Type,
		Payload: req.Payload,
		Status:  TaskPending,
		Created: time.Now(),
		Updated: time.Now(),
	}
	cp.tasks.Store(taskID, task)
	cp.markDirty()

	cmd := map[string]interface{}{
		"type":    req.Type,
		"payload": req.Payload,
		"task_id": taskID,
	}
	cmdData, _ := json.Marshal(cmd)

	subj := fmt.Sprintf("fei.cmd.%s", req.AgentID)
	if err := cp.nc.Publish(subj, cmdData); err != nil {
		task.Status = TaskFailed
		task.ErrReason = err.Error()
		task.Updated = time.Now()
		cp.markDirty()
		cp.replyError(msg, fmt.Sprintf("publish to gateway failed: %v", err))
		return
	}

	task.Status = TaskSent
	task.Updated = time.Now()
	cp.markDirty()

	resp := map[string]interface{}{
		"success": true,
		"task_id": taskID,
	}
	data, _ := json.Marshal(resp)
	msg.Respond(data)
	log.Printf("task %s sent to agent %s (type=0x%04x)", taskID, req.AgentID, req.Type)
}

func (cp *ControlPlane) apiGetTask(msg *nats.Msg) {
	var req struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		cp.replyError(msg, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if val, ok := cp.tasks.Load(req.TaskID); ok {
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"task":    val.(*Task),
		})
		msg.Respond(data)
	} else {
		cp.replyError(msg, "task not found")
	}
}

func (cp *ControlPlane) apiListTasks(msg *nats.Msg) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(msg.Data, &req)

	var tasks []*Task
	cp.tasks.Range(func(_, value interface{}) bool {
		task := value.(*Task)
		if req.AgentID == "" || task.AgentID == req.AgentID {
			tasks = append(tasks, task)
		}
		return true
	})

	data, _ := json.Marshal(map[string]interface{}{
		"success": true,
		"tasks":   tasks,
		"count":   len(tasks),
	})
	msg.Respond(data)
}

func (cp *ControlPlane) apiGetAgentInfo(msg *nats.Msg, agentID string) {
	if val, ok := cp.agents.Load(agentID); ok {
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"agent":   val.(*Agent),
		})
		msg.Respond(data)
	} else {
		cp.replyError(msg, "agent not found")
	}
}

func (cp *ControlPlane) replyError(msg *nats.Msg, errMsg string) {
	data, _ := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   errMsg,
	})
	msg.Respond(data)
	log.Printf("API error: %s", errMsg)
}

func (cp *ControlPlane) nextTaskID() string {
	cp.taskMu.Lock()
	defer cp.taskMu.Unlock()
	cp.taskSeq++
	return fmt.Sprintf("task_%d_%s", cp.taskSeq, hex.EncodeToString([]byte(time.Now().Format("150405"))))
}

func (cp *ControlPlane) taskTimeoutChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		cp.tasks.Range(func(_, value interface{}) bool {
			task := value.(*Task)
			if task.Status == TaskSent && now.Sub(task.Updated) > 60*time.Second {
				task.Status = TaskTimeout
				task.Updated = now
				task.ErrReason = "response timeout (60s)"
				log.Printf("task %s timed out for agent %s", task.ID, task.AgentID)
			}
			return true
		})
	}
}

func (cp *ControlPlane) startHTTPServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var agents []*Agent
		cp.agents.Range(func(_, value interface{}) bool {
			agent := value.(*Agent)
			agents = append(agents, agent)
			return true
		})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"agents":  agents,
			"count":   len(agents),
		})
	})

	mux.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agentID := r.URL.Query().Get("agent_id")
		var tasks []*Task
		cp.tasks.Range(func(_, value interface{}) bool {
			task := value.(*Task)
			if agentID == "" || task.AgentID == agentID {
				tasks = append(tasks, task)
			}
			return true
		})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"tasks":   tasks,
			"count":   len(tasks),
		})
	})

	log.Printf("HTTP server listening on %s", cp.httpAddr)
	if err := http.ListenAndServe(cp.httpAddr, mux); err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}
