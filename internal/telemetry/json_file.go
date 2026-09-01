package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	defaultTelemetryFileMaxBytes = 5 * 1024 * 1024
	defaultTelemetryQueueSize    = 256
	defaultTelemetryMaxBackups   = 1
	maximumTelemetryQueueSize    = 4096
	maximumTelemetryBackups      = 4
)

var (
	// These errors intentionally contain no path, rejected value, or OS error
	// text. Telemetry errors may be surfaced to users and must not become a
	// side channel for local paths or event content.
	ErrJSONFileSinkClosed      = errors.New("telemetry event sink is closed")
	ErrJSONFileSinkWrite       = errors.New("telemetry event sink write failed")
	ErrJSONFileSinkSync        = errors.New("telemetry event sink sync failed")
	ErrJSONFileSinkOpen        = errors.New("telemetry event sink could not be opened")
	ErrJSONFileSinkRotate      = errors.New("telemetry event sink rotation failed")
	ErrJSONFileSinkInvalidSize = errors.New("telemetry event sink size is invalid")
	ErrJSONFileSinkEventLarge  = errors.New("telemetry event is too large")
)

// JSONFileSinkOptions controls the bounded local JSONL event sink.
//
// A zero options value selects the defaults. MaxBackups is bounded to four;
// setting it to zero in a non-zero options value disables backups while still
// rotating the active file in place.
type JSONFileSinkOptions struct {
	MaxBytes      int64
	QueueCapacity int
	MaxBackups    int
}

func defaultJSONFileSinkOptions() JSONFileSinkOptions {
	return JSONFileSinkOptions{
		MaxBytes:      defaultTelemetryFileMaxBytes,
		QueueCapacity: defaultTelemetryQueueSize,
		MaxBackups:    defaultTelemetryMaxBackups,
	}
}

func (o JSONFileSinkOptions) normalized() (JSONFileSinkOptions, error) {
	if o == (JSONFileSinkOptions{}) {
		return defaultJSONFileSinkOptions(), nil
	}
	if o.MaxBytes <= 0 {
		return JSONFileSinkOptions{}, ErrJSONFileSinkInvalidSize
	}
	if o.QueueCapacity <= 0 || o.QueueCapacity > maximumTelemetryQueueSize {
		return JSONFileSinkOptions{}, ErrJSONFileSinkInvalidSize
	}
	if o.MaxBackups < 0 || o.MaxBackups > maximumTelemetryBackups {
		return JSONFileSinkOptions{}, ErrJSONFileSinkInvalidSize
	}
	return o, nil
}

type telemetryFileItem struct {
	event   *Event
	barrier chan error
}

// JSONFileSink is a bounded, asynchronous metadata event sink. Record never
// waits for disk I/O. Events accepted into the queue are drained on Close,
// followed by fsync and close. Queue overflow is observable through
// DroppedEvents and does not expose event contents.
type JSONFileSink struct {
	path       string
	maxBytes   int64
	maxBackups int
	queue      chan telemetryFileItem
	stop       chan struct{}
	done       chan struct{}

	lifecycleMu sync.Mutex
	closed      bool

	stateMu  sync.RWMutex
	file     *os.File
	size     int64
	writeErr error
	closeErr error

	dropped atomic.Uint64
}

func NewJSONFileSink(path string) (*JSONFileSink, error) {
	return NewJSONFileSinkWithOptions(path, defaultJSONFileSinkOptions())
}

func NewJSONFileSinkWithLimit(path string, maxBytes int64) (*JSONFileSink, error) {
	options := defaultJSONFileSinkOptions()
	options.MaxBytes = maxBytes
	return NewJSONFileSinkWithOptions(path, options)
}

// NewJSONFileSinkWithQueueLimit is useful for callers that need a deliberately
// small producer queue while retaining the normal one-backup rotation policy.
func NewJSONFileSinkWithQueueLimit(path string, maxBytes int64, queueCapacity int) (*JSONFileSink, error) {
	options := defaultJSONFileSinkOptions()
	options.MaxBytes = maxBytes
	options.QueueCapacity = queueCapacity
	return NewJSONFileSinkWithOptions(path, options)
}

func NewJSONFileSinkWithOptions(path string, options JSONFileSinkOptions) (*JSONFileSink, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrJSONFileSinkOpen
	}
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, ErrJSONFileSinkOpen
	}

	file, err := openTelemetryFile(path)
	if err != nil {
		return nil, ErrJSONFileSinkOpen
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrJSONFileSinkOpen
	}
	if info.Size() > options.MaxBytes {
		// Do not begin with an already-unbounded active file. Keep the old
		// content in the same bounded backup scheme before accepting events.
		if err := rotateTelemetryFiles(path, file, options.MaxBackups); err != nil {
			_ = file.Close()
			return nil, ErrJSONFileSinkRotate
		}
		file, err = openTelemetryFile(path)
		if err != nil {
			return nil, ErrJSONFileSinkOpen
		}
		info, err = file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, ErrJSONFileSinkOpen
		}
	}

	sink := &JSONFileSink{
		path:       path,
		maxBytes:   options.MaxBytes,
		maxBackups: options.MaxBackups,
		queue:      make(chan telemetryFileItem, options.QueueCapacity),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		file:       file,
		size:       info.Size(),
	}
	go sink.run()
	return sink, nil
}

// Record implements Sink. Validation and queue overflow are intentionally
// silent for the legacy fire-and-forget interface; callers needing feedback
// can use RecordEvent and DroppedEvents.
func (s *JSONFileSink) Record(event Event) {
	if s == nil {
		return
	}
	_ = s.RecordEvent(event)
}

// RecordEvent validates and queues one event without waiting for disk I/O.
// A nil error means the event was valid; it may still have been dropped if the
// bounded queue was full. DroppedEvents reports those losses explicitly.
func (s *JSONFileSink) RecordEvent(event Event) error {
	if s == nil {
		return ErrJSONFileSinkClosed
	}
	if s.queue == nil {
		s.dropped.Add(1)
		return ErrJSONFileSinkClosed
	}
	if err := event.Validate(); err != nil {
		return err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return ErrJSONFileSinkWrite
	}
	line = append(line, '\n')
	if int64(len(line)) > s.maxBytes {
		return ErrJSONFileSinkEventLarge
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closed {
		s.dropped.Add(1)
		return ErrJSONFileSinkClosed
	}
	// The worker serializes all file state. The encoded line is checked above
	// so queueing cannot be rejected later for a caller-controlled size.
	select {
	case s.queue <- telemetryFileItem{event: &event}:
		return nil
	default:
		s.dropped.Add(1)
		return nil
	}
}

// Flush waits until all events accepted before the call have been written and
// fsynced. It is the explicit durability boundary used by shutdown and tests.
func (s *JSONFileSink) Flush(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.queue == nil || s.done == nil {
		return ErrJSONFileSinkClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	barrier := make(chan error, 1)
	s.lifecycleMu.Lock()
	if s.closed {
		done := s.done
		s.lifecycleMu.Unlock()
		<-done
		return s.lastError()
	}
	select {
	case s.queue <- telemetryFileItem{barrier: barrier}:
		s.lifecycleMu.Unlock()
	case <-ctx.Done():
		s.lifecycleMu.Unlock()
		return ctx.Err()
	}
	select {
	case err := <-barrier:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *JSONFileSink) run() {
	defer close(s.done)
	for {
		select {
		case item := <-s.queue:
			s.process(item)
		case <-s.stop:
			s.drain()
			s.finalize()
			return
		}
	}
}

func (s *JSONFileSink) drain() {
	for {
		select {
		case item := <-s.queue:
			s.process(item)
		default:
			return
		}
	}
}

func (s *JSONFileSink) process(item telemetryFileItem) {
	if item.event != nil {
		s.writeEvent(*item.event)
	}
	if item.barrier != nil {
		item.barrier <- s.sync()
	}
}

func (s *JSONFileSink) writeEvent(event Event) {
	line, err := json.Marshal(event)
	if err != nil {
		s.setError(ErrJSONFileSinkWrite)
		return
	}
	line = append(line, '\n')

	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.writeErr != nil || s.file == nil {
		return
	}
	if int64(len(line)) > s.maxBytes {
		s.setErrorLocked(ErrJSONFileSinkEventLarge)
		return
	}
	if s.size > 0 && s.size+int64(len(line)) > s.maxBytes {
		if err := s.rotateLocked(); err != nil {
			s.setErrorLocked(err)
			return
		}
	}
	n, err := s.file.Write(line)
	s.size += int64(n)
	if err != nil || n != len(line) {
		s.setErrorLocked(ErrJSONFileSinkWrite)
	}
}

func (s *JSONFileSink) rotateLocked() error {
	if s.file == nil {
		return ErrJSONFileSinkWrite
	}
	if err := s.file.Sync(); err != nil {
		return ErrJSONFileSinkSync
	}
	if err := s.file.Close(); err != nil {
		return ErrJSONFileSinkRotate
	}
	s.file = nil
	if err := rotateTelemetryFiles(s.path, nil, s.maxBackups); err != nil {
		return ErrJSONFileSinkRotate
	}
	file, err := openTelemetryFile(s.path)
	if err != nil {
		return ErrJSONFileSinkOpen
	}
	s.file = file
	s.size = 0
	return nil
}

func (s *JSONFileSink) sync() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.file == nil {
		return s.lastErrorLocked()
	}
	if err := s.file.Sync(); err != nil {
		s.setErrorLocked(ErrJSONFileSinkSync)
		return ErrJSONFileSinkSync
	}
	return nil
}

func (s *JSONFileSink) finalize() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.file == nil {
		return
	}
	if s.writeErr == nil {
		if err := s.file.Sync(); err != nil {
			s.setErrorLocked(ErrJSONFileSinkSync)
		}
	}
	if err := s.file.Close(); err != nil && s.closeErr == nil {
		s.closeErr = ErrJSONFileSinkWrite
	}
	s.file = nil
}

// DroppedEvents is the number of valid events discarded because the producer
// queue was full or the sink had already closed.
func (s *JSONFileSink) DroppedEvents() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func (s *JSONFileSink) DropCount() uint64 { return s.DroppedEvents() }

// LastError returns a stable, content-free error class for asynchronous write
// failures. It never returns an underlying filesystem error.
func (s *JSONFileSink) LastError() error {
	if s == nil {
		return nil
	}
	return s.lastError()
}

func (s *JSONFileSink) lastError() error {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.lastErrorLocked()
}

func (s *JSONFileSink) lastErrorLocked() error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.closeErr
}

func (s *JSONFileSink) setError(err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.setErrorLocked(err)
}

func (s *JSONFileSink) setErrorLocked(err error) {
	if s.writeErr == nil {
		s.writeErr = err
	}
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

func (s *JSONFileSink) Close() error {
	if s == nil {
		return nil
	}
	if s.done == nil || s.stop == nil {
		s.lifecycleMu.Lock()
		s.closed = true
		s.lifecycleMu.Unlock()
		return s.lastError()
	}
	s.lifecycleMu.Lock()
	if s.closed {
		done := s.done
		s.lifecycleMu.Unlock()
		<-done
		return s.lastError()
	}
	s.closed = true
	close(s.stop)
	done := s.done
	s.lifecycleMu.Unlock()
	<-done
	return s.lastError()
}

func openTelemetryFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureTelemetryFile(path); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// rotateTelemetryFiles rotates the active path while no descriptor for path
// is open. file may be supplied when the caller has already opened path (the
// constructor path); it is closed before renaming.
func rotateTelemetryFiles(path string, file *os.File, backups int) error {
	if file != nil {
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	for index := backups; index >= 1; index-- {
		target := path + "." + itoa(index)
		if index == backups {
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if index > 1 {
			source := path + "." + itoa(index-1)
			//paperboat:allow-source-policy atomic-replacement owner=telemetry reason=bounded-log-rotation
			if err := os.Rename(source, target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if backups > 0 {
		//paperboat:allow-source-policy atomic-replacement owner=telemetry reason=bounded-active-log-rotation
		if err := os.Rename(path, path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err := os.Truncate(path, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func itoa(value int) string {
	// The backup count is capped at four, so avoiding fmt keeps constructor and
	// error paths small and deterministic.
	if value < 0 {
		return "0"
	}
	return string([]byte{'0' + byte(value)})
}
