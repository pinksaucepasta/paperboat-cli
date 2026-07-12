package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type JSONFileSink struct {
	mu       sync.Mutex
	file     *os.File
	size     int64
	maxBytes int64
}

func NewJSONFileSink(path string) (*JSONFileSink, error) {
	return NewJSONFileSinkWithLimit(path, 5*1024*1024)
}

func NewJSONFileSinkWithLimit(path string, maxBytes int64) (*JSONFileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("telemetry event log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create telemetry directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open telemetry event log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure telemetry event log: %w", err)
	}
	if maxBytes <= 0 {
		_ = file.Close()
		return nil, fmt.Errorf("telemetry event log limit must be positive")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect telemetry event log: %w", err)
	}
	return &JSONFileSink{file: file, size: info.Size(), maxBytes: maxBytes}, nil
}

func (s *JSONFileSink) Record(event Event) {
	if s == nil || event.Validate() != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if int64(len(line)) > s.maxBytes {
		return
	}
	if s.size+int64(len(line)) > s.maxBytes {
		if err := s.file.Truncate(0); err != nil {
			s.disableLocked()
			return
		}
		s.size = 0
	}
	n, err := s.file.Write(line)
	s.size += int64(n)
	if err != nil || n != len(line) {
		s.disableLocked()
	}
}

func (s *JSONFileSink) disableLocked() {
	_ = s.file.Close()
	s.file = nil
}

func (s *JSONFileSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
