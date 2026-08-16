package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AgentRecord struct {
	ID        string    `json:"id"`
	State     int       `json:"state"`
	LastSeen  time.Time `json:"last_seen"`
	FirstSeen time.Time `json:"first_seen"`
	Hostname  string    `json:"hostname"`
	OSInfo    string    `json:"os_info"`
	IPAddress string    `json:"ip_address"`
}

type TaskRecord struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Type      uint16    `json:"type"`
	Payload   []byte    `json:"payload"`
	Status    string    `json:"status"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Result    []byte    `json:"result,omitempty"`
	ErrReason string    `json:"error,omitempty"`
}

type Snapshot struct {
	Version   int           `json:"version"`
	SavedAt   time.Time     `json:"saved_at"`
	Agents    []AgentRecord `json:"agents"`
	Tasks     []TaskRecord  `json:"tasks"`
	TaskSeq   uint64        `json:"task_seq"`
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return &FileStore{path: filepath.Join(dir, "fei_state.json")}, nil
}

func (s *FileStore) Load() (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Snapshot{Version: 1}, nil
		}
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	return &snap, nil
}

func (s *FileStore) Save(snap *Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap.SavedAt = time.Now()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileStore) Path() string {
	return s.path
}
