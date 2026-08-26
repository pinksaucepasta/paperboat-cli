package execprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
)

var (
	ErrInvalid           = errors.New("invalid exec request")
	ErrConflict          = errors.New("exec operation id conflict")
	ErrCapacity          = errors.New("exec capacity reached")
	ErrNotFound          = errors.New("exec operation not found")
	ErrReplayUnavailable = errors.New("exec event replay unavailable")
)

const (
	StateAuthorized State = "authorized"
	StateStarting   State = "starting"
	StateRunning    State = "running"
	StateExited     State = "exited"
	StateSignaled   State = "signaled"
	StateCanceled   State = "canceled"
	StateFailed     State = "failed"
)

type State string

type Request struct {
	OperationID string            `json:"operation_id"`
	Argv        []string          `json:"argv"`
	CWD         string            `json:"cwd"`
	Environment map[string]string `json:"environment,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	PTY         bool              `json:"pty"`
	Dimensions  pty.Dimensions    `json:"dimensions,omitempty"`
}

type Result struct {
	Code     int       `json:"code"`
	Signal   string    `json:"signal,omitempty"`
	ExitedAt time.Time `json:"exited_at"`
}

type Snapshot struct {
	OperationID  string     `json:"operation_id"`
	State        State      `json:"state"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	Result       *Result    `json:"result,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	NextSequence uint64     `json:"next_sequence"`
}

type Event struct {
	Sequence       uint64  `json:"sequence"`
	Stream         string  `json:"stream"`
	StreamSequence uint64  `json:"stream_sequence,omitempty"`
	Data           []byte  `json:"data,omitempty"`
	State          State   `json:"state,omitempty"`
	Result         *Result `json:"result,omitempty"`
	ErrorCode      string  `json:"error_code,omitempty"`
}

type Config struct {
	WorkspaceRoot     string
	BaseEnvironment   []string
	MaximumActive     int
	MaximumOperations int
	ReplayBytes       int
	ChunkBytes        int
	CancelGrace       time.Duration
	Clock             func() time.Time
	Store             *store.Store
	Retention         time.Duration
}

type Manager struct {
	config     Config
	mu         sync.Mutex
	operations map[string]*Execution
	order      []string
	active     int
}

type Execution struct {
	manager *Manager
	request Request
	hash    [sha256.Size]byte

	mu              sync.Mutex
	state           State
	startedAt       *time.Time
	result          *Result
	errorCode       string
	events          []Event
	streamSequences map[string]uint64
	eventBytes      int
	earliest        uint64
	next            uint64
	wake            chan struct{}
	done            chan struct{}
	doneOnce        sync.Once
	process         process
	cancelRequested bool
	waitErr         error
	readers         map[uint64]uint64
	nextReader      uint64
}

type Reader struct {
	execution *Execution
	id        uint64
	mu        sync.Mutex
	next      uint64
	closed    bool
}

type process interface {
	Start(context.Context) error
	Write([]byte) (int, error)
	CloseInput() error
	Signal(pty.Signal) error
	Resize(pty.Dimensions) error
	Wait(context.Context) (Result, error)
	Terminate(context.Context, time.Duration) (Result, error)
}

var environmentKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const persistencePrefix = "exec:"

func New(config Config) (*Manager, error) {
	return NewPersistent(context.Background(), config)
}

func NewPersistent(ctx context.Context, config Config) (*Manager, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if config.MaximumActive == 0 {
		config.MaximumActive = 32
	}
	if config.MaximumOperations == 0 {
		config.MaximumOperations = 1024
	}
	if config.ReplayBytes == 0 {
		config.ReplayBytes = 1 << 20
	}
	if config.ChunkBytes == 0 {
		config.ChunkBytes = 32 << 10
	}
	if config.CancelGrace == 0 {
		config.CancelGrace = 2 * time.Second
	}
	if config.Retention == 0 {
		config.Retention = time.Hour
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	root, err := filepath.EvalSymlinks(config.WorkspaceRoot)
	if err != nil || !filepath.IsAbs(root) || config.MaximumActive < 1 || config.MaximumActive > 1024 || config.MaximumOperations < config.MaximumActive || config.MaximumOperations > 1<<20 || config.ReplayBytes < 64<<10 || config.ReplayBytes > 64<<20 || config.ChunkBytes < 1024 || config.ChunkBytes > 1<<20 || config.CancelGrace < 0 || config.CancelGrace > time.Minute || config.Retention <= 0 || config.Retention > 7*24*time.Hour || !validBaseEnvironment(config.BaseEnvironment) {
		return nil, ErrInvalid
	}
	config.WorkspaceRoot = filepath.Clean(root)
	config.BaseEnvironment = append([]string(nil), config.BaseEnvironment...)
	manager := &Manager{config: config, operations: make(map[string]*Execution)}
	if config.Store != nil {
		if err := manager.load(ctx); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (m *Manager) Start(ctx context.Context, request Request) (*Execution, bool, error) {
	if ctx == nil {
		return nil, false, ErrInvalid
	}
	request, hash, err := m.validate(request)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	if existing := m.operations[request.OperationID]; existing != nil {
		if existing.hash != hash {
			m.mu.Unlock()
			return nil, false, ErrConflict
		}
		m.mu.Unlock()
		return existing, true, nil
	}
	if m.active >= m.config.MaximumActive {
		m.mu.Unlock()
		return nil, false, ErrCapacity
	}
	for len(m.operations) >= m.config.MaximumOperations && len(m.order) > 0 {
		oldest := m.order[0]
		m.order = m.order[1:]
		delete(m.operations, oldest)
	}
	if len(m.operations) >= m.config.MaximumOperations {
		m.mu.Unlock()
		return nil, false, ErrCapacity
	}
	if m.config.Store != nil {
		record, inserted, reserveErr := m.config.Store.ReserveOperation(ctx, persistencePrefix+request.OperationID, hash[:], m.config.Clock().Add(m.config.Retention))
		if reserveErr != nil {
			m.mu.Unlock()
			return nil, false, reserveErr
		}
		if !inserted {
			if !bytes.Equal(record.RequestHash, hash[:]) {
				m.mu.Unlock()
				return nil, false, ErrConflict
			}
			recovered, recoverErr := m.executionFromRecord(ctx, record)
			if recoverErr != nil {
				m.mu.Unlock()
				return nil, false, recoverErr
			}
			m.operations[request.OperationID] = recovered
			m.order = append(m.order, request.OperationID)
			m.mu.Unlock()
			return recovered, true, nil
		}
	}
	execution := &Execution{manager: m, request: request, hash: hash, state: StateAuthorized, earliest: 1, next: 1, wake: make(chan struct{}), done: make(chan struct{}), streamSequences: make(map[string]uint64), readers: make(map[uint64]uint64)}
	m.operations[request.OperationID] = execution
	m.active++
	m.mu.Unlock()
	go execution.run(context.WithoutCancel(ctx))
	return execution, false, nil
}

func (m *Manager) Get(operationID string) (*Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	execution := m.operations[operationID]
	if execution == nil {
		return nil, ErrNotFound
	}
	return execution, nil
}

func (m *Manager) validate(request Request) (Request, [sha256.Size]byte, error) {
	if !validID(request.OperationID) || len(request.Argv) == 0 || len(request.Argv) > 64 || request.Timeout < 0 || request.Timeout > 24*time.Hour || request.PTY && (request.Dimensions.Columns == 0 || request.Dimensions.Rows == 0) || !request.PTY && request.Dimensions != (pty.Dimensions{}) {
		return Request{}, [sha256.Size]byte{}, ErrInvalid
	}
	total := 0
	for _, arg := range request.Argv {
		total += len(arg)
		if len(arg) == 0 || len(arg) > 4096 || total > 64<<10 || strings.ContainsRune(arg, '\x00') {
			return Request{}, [sha256.Size]byte{}, ErrInvalid
		}
	}
	cwd, err := filepath.EvalSymlinks(request.CWD)
	if err != nil || !filepath.IsAbs(cwd) || !within(m.config.WorkspaceRoot, cwd) {
		return Request{}, [sha256.Size]byte{}, ErrInvalid
	}
	request.CWD = filepath.Clean(cwd)
	if len(request.Environment) > 128 {
		return Request{}, [sha256.Size]byte{}, ErrInvalid
	}
	envTotal := 0
	for key, value := range request.Environment {
		envTotal += len(key) + len(value)
		if !environmentKey.MatchString(key) || len(value) > 4096 || envTotal > 64<<10 || strings.ContainsRune(value, '\x00') {
			return Request{}, [sha256.Size]byte{}, ErrInvalid
		}
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return Request{}, [sha256.Size]byte{}, ErrInvalid
	}
	return request, sha256.Sum256(canonical), nil
}

func (e *Execution) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

func (e *Execution) snapshotLocked() Snapshot {
	value := Snapshot{OperationID: e.request.OperationID, State: e.state, StartedAt: e.startedAt, ErrorCode: e.errorCode, NextSequence: e.next}
	if e.result != nil {
		result := *e.result
		value.Result = &result
	}
	return value
}

func (e *Execution) Wait(ctx context.Context) (Snapshot, error) {
	select {
	case <-e.done:
		e.mu.Lock()
		err := e.waitErr
		e.mu.Unlock()
		return e.Snapshot(), err
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

func (e *Execution) Next(ctx context.Context, from uint64) (Event, error) {
	for {
		e.mu.Lock()
		if from < e.earliest {
			e.mu.Unlock()
			return Event{}, ErrReplayUnavailable
		}
		if from < e.next {
			event := e.events[from-e.earliest]
			e.mu.Unlock()
			return cloneEvent(event), nil
		}
		wake := e.wake
		terminal := terminalState(e.state)
		e.mu.Unlock()
		if terminal {
			return Event{}, io.EOF
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return Event{}, ctx.Err()
		}
	}
}

// OpenReader registers a live delivery cursor. Replay remains bounded when no
// reader is attached; an attached reader pins unread events and backpressures
// the child process instead of allowing ordinary live output to become a gap.
func (e *Execution) OpenReader(from uint64) (*Reader, error) {
	if e == nil || from == 0 {
		return nil, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if from < e.earliest {
		return nil, ErrReplayUnavailable
	}
	e.nextReader++
	if e.nextReader == 0 {
		return nil, ErrCapacity
	}
	id := e.nextReader
	e.readers[id] = from
	return &Reader{execution: e, id: id, next: from}, nil
}

func (r *Reader) Next(ctx context.Context) (Event, func(), error) {
	if r == nil || r.execution == nil || ctx == nil {
		return Event{}, nil, ErrInvalid
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Event{}, nil, io.EOF
	}
	from := r.next
	r.mu.Unlock()
	event, err := r.execution.Next(ctx, from)
	if err != nil {
		return Event{}, nil, err
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			if !r.closed && r.next == event.Sequence {
				r.next = event.Sequence + 1
			}
			next, closed := r.next, r.closed
			r.mu.Unlock()
			if !closed {
				r.execution.advanceReader(r.id, next)
			}
		})
	}
	return event, release, nil
}

func (r *Reader) Close() error {
	if r == nil || r.execution == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	r.execution.removeReader(r.id)
	return nil
}

func (e *Execution) advanceReader(id, next uint64) {
	e.mu.Lock()
	if _, ok := e.readers[id]; ok {
		e.readers[id] = next
		e.evictLocked()
		e.signalLocked()
	}
	e.mu.Unlock()
}

func (e *Execution) removeReader(id uint64) {
	e.mu.Lock()
	delete(e.readers, id)
	e.evictLocked()
	e.signalLocked()
	e.mu.Unlock()
}

func (e *Execution) Write(data []byte) (int, error) {
	e.mu.Lock()
	process := e.process
	e.mu.Unlock()
	if process == nil {
		return 0, ErrInvalid
	}
	return process.Write(data)
}
func (e *Execution) CloseInput() error {
	e.mu.Lock()
	process := e.process
	e.mu.Unlock()
	if process == nil {
		return ErrInvalid
	}
	return process.CloseInput()
}
func (e *Execution) Signal(signal pty.Signal) error {
	e.mu.Lock()
	process := e.process
	e.mu.Unlock()
	if process == nil {
		return ErrInvalid
	}
	return process.Signal(signal)
}
func (e *Execution) Resize(dimensions pty.Dimensions) error {
	e.mu.Lock()
	process := e.process
	isPTY := e.request.PTY
	e.mu.Unlock()
	if process == nil || !isPTY {
		return ErrInvalid
	}
	return process.Resize(dimensions)
}

func (e *Execution) Cancel(ctx context.Context) error {
	e.mu.Lock()
	process := e.process
	terminal := terminalState(e.state)
	if !terminal {
		e.cancelRequested = true
	}
	e.mu.Unlock()
	if terminal {
		return nil
	}
	if process == nil {
		return nil
	}
	result, err := process.Terminate(ctx, e.manager.config.CancelGrace)
	if err == nil {
		e.finish(StateCanceled, result, "exec_canceled")
	}
	return err
}

func (e *Execution) run(parent context.Context) {
	e.transition(StateStarting, nil, "")
	ctx := parent
	var cancel context.CancelFunc
	if e.request.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, e.request.Timeout)
		defer cancel()
	}
	process, err := newProcess(processConfig{Request: e.request, WorkspaceRoot: e.manager.config.WorkspaceRoot, BaseEnvironment: e.manager.config.BaseEnvironment, ChunkBytes: e.manager.config.ChunkBytes, Output: e.output})
	if err != nil {
		e.finish(StateFailed, Result{ExitedAt: e.manager.config.Clock()}, "exec_start_failed")
		return
	}
	if e.canceled() || ctx.Err() != nil {
		e.finish(StateCanceled, Result{ExitedAt: e.manager.config.Clock()}, "exec_canceled")
		return
	}
	if err := process.Start(ctx); err != nil {
		e.finish(StateFailed, Result{ExitedAt: e.manager.config.Clock()}, "exec_start_failed")
		return
	}
	e.mu.Lock()
	e.process = process
	canceled := e.cancelRequested
	e.mu.Unlock()
	if canceled {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), e.manager.config.CancelGrace+5*time.Second)
		result, terminateErr := process.Terminate(cleanupCtx, e.manager.config.CancelGrace)
		cleanupCancel()
		if terminateErr != nil {
			e.finish(StateFailed, Result{ExitedAt: e.manager.config.Clock()}, "exec_cancel_failed")
		} else {
			e.finish(StateCanceled, result, "exec_canceled")
		}
		return
	}
	now := e.manager.config.Clock()
	e.mu.Lock()
	e.startedAt = &now
	e.mu.Unlock()
	e.transition(StateRunning, nil, "")
	result, err := process.Wait(ctx)
	state, code := StateExited, ""
	if ctx.Err() != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), e.manager.config.CancelGrace+5*time.Second)
		var terminateErr error
		result, terminateErr = process.Terminate(cleanupCtx, e.manager.config.CancelGrace)
		cleanupCancel()
		if terminateErr != nil {
			state, code = StateFailed, "exec_cancel_failed"
		} else {
			state, code = StateCanceled, "exec_timeout"
		}
	} else if e.canceled() {
		state, code = StateCanceled, "exec_canceled"
	} else if err != nil {
		state, code = StateFailed, "exec_wait_failed"
	} else if result.Signal != "" {
		state = StateSignaled
	}
	e.finish(state, result, code)
}

func (e *Execution) output(stream string, data []byte) {
	if len(data) == 0 {
		return
	}
	e.mu.Lock()
	sequence := e.streamSequences[stream]
	e.streamSequences[stream] += uint64(len(data))
	e.appendLocked(Event{Stream: stream, StreamSequence: sequence, Data: append([]byte(nil), data...)})
	for e.eventBytes > e.manager.config.ReplayBytes && len(e.readers) > 0 {
		wake := e.wake
		e.mu.Unlock()
		<-wake
		e.mu.Lock()
		e.evictLocked()
	}
	e.mu.Unlock()
}

func (e *Execution) transition(state State, result *Result, code string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if terminalState(e.state) {
		return
	}
	e.state, e.errorCode = state, code
	if result != nil {
		copy := *result
		e.result = &copy
	}
	e.appendLocked(Event{State: state, Result: result, ErrorCode: code})
}

func (e *Execution) finish(state State, result Result, code string) {
	e.doneOnce.Do(func() {
		var persistenceErr error
		if e.manager.config.Store != nil {
			snapshot := Snapshot{OperationID: e.request.OperationID, State: state, Result: &result, ErrorCode: code, NextSequence: e.next + 1}
			encoded, marshalErr := json.Marshal(snapshot)
			if marshalErr != nil {
				persistenceErr = marshalErr
			} else {
				persistenceErr = e.manager.config.Store.CompleteOperation(context.Background(), store.OperationResult{OperationID: persistencePrefix + e.request.OperationID, RequestHash: e.hash[:], State: "completed", Result: encoded, ErrorCode: code, CompletedAt: e.manager.config.Clock(), ExpiresAt: e.manager.config.Clock().Add(e.manager.config.Retention)})
			}
			if persistenceErr != nil {
				log.Printf("exec operation persistence failed operation_id=%s: %v", e.request.OperationID, persistenceErr)
				code = "persistence_failed"
			}
		}
		e.transition(state, &result, code)
		e.mu.Lock()
		e.waitErr = persistenceErr
		e.mu.Unlock()
		close(e.done)
		e.manager.mu.Lock()
		e.manager.active--
		e.manager.order = append(e.manager.order, e.request.OperationID)
		e.manager.mu.Unlock()
	})
}

func (m *Manager) load(ctx context.Context) error {
	records, err := m.config.Store.OperationsWithPrefix(ctx, persistencePrefix, m.config.Clock(), m.config.MaximumOperations)
	if err != nil {
		return err
	}
	for _, record := range records {
		execution, err := m.executionFromRecord(ctx, record)
		if err != nil {
			return err
		}
		m.operations[execution.request.OperationID] = execution
		m.order = append(m.order, execution.request.OperationID)
	}
	return nil
}

func (m *Manager) executionFromRecord(ctx context.Context, record store.OperationResult) (*Execution, error) {
	operationID := strings.TrimPrefix(record.OperationID, persistencePrefix)
	if operationID == record.OperationID || !validID(operationID) || len(record.RequestHash) != sha256.Size {
		return nil, ErrInvalid
	}
	var hash [sha256.Size]byte
	copy(hash[:], record.RequestHash)
	execution := &Execution{manager: m, request: Request{OperationID: operationID}, hash: hash, earliest: 1, next: 1, wake: make(chan struct{}), done: make(chan struct{}), streamSequences: make(map[string]uint64), readers: make(map[uint64]uint64)}
	var snapshot Snapshot
	if record.State == "completed" {
		if json.Unmarshal(record.Result, &snapshot) != nil || snapshot.OperationID != operationID || !terminalState(snapshot.State) || snapshot.Result == nil {
			return nil, ErrInvalid
		}
	} else if record.State == "pending" {
		snapshot = Snapshot{OperationID: operationID, State: StateFailed, Result: &Result{Code: -1, ExitedAt: m.config.Clock()}, ErrorCode: "exec_start_uncertain"}
		encoded, _ := json.Marshal(snapshot)
		if err := m.config.Store.CompleteOperation(ctx, store.OperationResult{OperationID: record.OperationID, RequestHash: record.RequestHash, State: "completed", Result: encoded, ErrorCode: snapshot.ErrorCode, CompletedAt: m.config.Clock(), ExpiresAt: m.config.Clock().Add(m.config.Retention)}); err != nil {
			return nil, err
		}
	} else {
		return nil, ErrInvalid
	}
	if snapshot.NextSequence > 1 {
		execution.earliest = snapshot.NextSequence - 1
		execution.next = execution.earliest
	}
	execution.state, execution.result, execution.errorCode = snapshot.State, snapshot.Result, snapshot.ErrorCode
	execution.appendLocked(Event{State: snapshot.State, Result: snapshot.Result, ErrorCode: snapshot.ErrorCode})
	execution.doneOnce.Do(func() { close(execution.done) })
	return execution, nil
}

func (e *Execution) canceled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cancelRequested
}

func (e *Execution) appendLocked(event Event) {
	event.Sequence = e.next
	e.next++
	e.events = append(e.events, event)
	e.eventBytes += len(event.Data)
	e.evictLocked()
	e.signalLocked()
}

func (e *Execution) evictLocked() {
	minimum := e.next
	for _, next := range e.readers {
		if next < minimum {
			minimum = next
		}
	}
	for e.eventBytes > e.manager.config.ReplayBytes && len(e.events) > 1 && (len(e.readers) == 0 || e.earliest < minimum) {
		e.eventBytes -= len(e.events[0].Data)
		e.events = e.events[1:]
		e.earliest++
	}
}

func (e *Execution) signalLocked() {
	close(e.wake)
	e.wake = make(chan struct{})
}

func validBaseEnvironment(values []string) bool {
	seen := map[string]bool{}
	for _, entry := range values {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !environmentKey.MatchString(key) || strings.ContainsRune(value, '\x00') || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func validID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
func terminalState(state State) bool {
	return state == StateExited || state == StateSignaled || state == StateCanceled || state == StateFailed
}
func cloneEvent(event Event) Event {
	event.Data = append([]byte(nil), event.Data...)
	if event.Result != nil {
		copy := *event.Result
		event.Result = &copy
	}
	return event
}
func mergedEnvironment(base []string, overrides map[string]string) []string {
	values := map[string]string{}
	for _, entry := range base {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}
