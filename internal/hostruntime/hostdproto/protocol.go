// Package hostdproto defines the local, versioned control protocol between the
// stable Paperboat host daemon and a replaceable runtime worker.
//
// It intentionally contains lifecycle messages only. It is not a generic RPC
// tunnel and must not become a way for a worker to execute arbitrary commands
// in the host daemon.
package hostdproto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	SchemaV1      = "paperboat.hostd-worker/v1"
	MaxFrameBytes = 64 << 10
	maxAPIVersion = 1024
)

var (
	ErrInvalidFrame    = errors.New("invalid hostd worker frame")
	ErrIncompatible    = errors.New("incompatible hostd worker API")
	ErrFenced          = errors.New("hostd worker is fenced")
	ErrNotReady        = errors.New("hostd worker is not ready")
	ErrEpochExhausted  = errors.New("hostd worker epoch is exhausted")
	ErrLeaseGeneration = errors.New("hostd worker lease generation failed")
	ErrInvalidConfig   = errors.New("invalid hostd worker controller configuration")
)

var workerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Type string

const (
	TypeHello     Type = "hello"
	TypeWelcome   Type = "welcome"
	TypeReady     Type = "ready"
	TypeActivate  Type = "activate"
	TypeHeartbeat Type = "heartbeat"
	TypeStatus    Type = "status"
	TypeError     Type = "error"
)

// Message is one strictly framed lifecycle message. Each message has a fixed
// body shape selected by Type; no application-defined payload is accepted.
type Message interface {
	messageType() Type
	validate() error
}

// Hello starts a candidate-worker lease negotiation.
type Hello struct {
	WorkerID string `json:"worker_id"`
	Version  string `json:"version"`
	APIMin   uint16 `json:"api_min"`
	APIMax   uint16 `json:"api_max"`
}

func (Hello) messageType() Type { return TypeHello }
func (m Hello) validate() error {
	if !validWorkerID(m.WorkerID) || !validVersion(m.Version) || !validRange(m.APIMin, m.APIMax) {
		return ErrInvalidFrame
	}
	return nil
}

// Welcome grants a short-lived candidate lease. Epochs are monotonically
// increasing fence tokens: a message from an earlier epoch is never accepted
// after another worker is activated.
type Welcome struct {
	WorkerID   string `json:"worker_id"`
	APIVersion uint16 `json:"api_version"`
	Epoch      uint64 `json:"epoch"`
	Lease      string `json:"lease"`
}

func (Welcome) messageType() Type { return TypeWelcome }
func (m Welcome) validate() error {
	if !validWorkerID(m.WorkerID) || !validAPIVersion(m.APIVersion) || m.Epoch == 0 || !validLease(m.Lease) {
		return ErrInvalidFrame
	}
	return nil
}

// Ready proves that a candidate has finished its private startup checks.
type Ready struct {
	WorkerID   string `json:"worker_id"`
	APIVersion uint16 `json:"api_version"`
	Epoch      uint64 `json:"epoch"`
	Lease      string `json:"lease"`
}

func (Ready) messageType() Type { return TypeReady }
func (m Ready) validate() error {
	return validateLeaseMessage(m.WorkerID, m.APIVersion, m.Epoch, m.Lease)
}

// Activate requests promotion of a ready candidate to the sole active worker.
type Activate struct {
	WorkerID   string `json:"worker_id"`
	APIVersion uint16 `json:"api_version"`
	Epoch      uint64 `json:"epoch"`
	Lease      string `json:"lease"`
}

func (Activate) messageType() Type { return TypeActivate }
func (m Activate) validate() error {
	return validateLeaseMessage(m.WorkerID, m.APIVersion, m.Epoch, m.Lease)
}

// Heartbeat is accepted only from the active, unfenced worker.
type Heartbeat struct {
	WorkerID   string `json:"worker_id"`
	APIVersion uint16 `json:"api_version"`
	Epoch      uint64 `json:"epoch"`
	Lease      string `json:"lease"`
}

func (Heartbeat) messageType() Type { return TypeHeartbeat }
func (m Heartbeat) validate() error {
	return validateLeaseMessage(m.WorkerID, m.APIVersion, m.Epoch, m.Lease)
}

type State string

const (
	StateCandidate State = "candidate"
	StateActive    State = "active"
	StateEmpty     State = "empty"
)

// Status confirms the active fence. It intentionally does not reveal a lease.
type Status struct {
	State                  State  `json:"state"`
	WorkerID               string `json:"worker_id,omitempty"`
	APIVersion             uint16 `json:"api_version,omitempty"`
	Epoch                  uint64 `json:"epoch,omitempty"`
	LastHeartbeatUnixMilli int64  `json:"last_heartbeat_unix_milli,omitempty"`
}

func (Status) messageType() Type { return TypeStatus }
func (m Status) validate() error {
	switch m.State {
	case StateEmpty:
		if m.WorkerID != "" || m.APIVersion != 0 || m.Epoch != 0 || m.LastHeartbeatUnixMilli != 0 {
			return ErrInvalidFrame
		}
	case StateCandidate, StateActive:
		if !validWorkerID(m.WorkerID) || !validAPIVersion(m.APIVersion) || m.Epoch == 0 || m.LastHeartbeatUnixMilli < 0 {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	return nil
}

type Error struct {
	Code string `json:"code"`
}

func (Error) messageType() Type { return TypeError }
func (m Error) validate() error {
	if !validErrorCode(m.Code) {
		return ErrInvalidFrame
	}
	return nil
}

type envelope struct {
	Schema string          `json:"schema"`
	Type   Type            `json:"type"`
	Body   json.RawMessage `json:"body"`
}

// Encode serializes exactly one message. Callers must still apply a transport
// length prefix with WriteFrame when using a stream Unix socket.
func Encode(message Message) ([]byte, error) {
	if message == nil || message.validate() != nil {
		return nil, ErrInvalidFrame
	}
	body, err := json.Marshal(message)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	frame, err := json.Marshal(envelope{Schema: SchemaV1, Type: message.messageType(), Body: body})
	if err != nil || len(frame) == 0 || len(frame) > MaxFrameBytes {
		return nil, ErrInvalidFrame
	}
	return frame, nil
}

// Decode rejects unknown envelope and body fields, trailing values, oversized
// input, and every message type not explicitly defined in this package.
func Decode(frame []byte) (Message, error) {
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return nil, ErrInvalidFrame
	}
	var outer envelope
	if err := decodeStrict(frame, &outer); err != nil || outer.Schema != SchemaV1 || len(outer.Body) == 0 {
		return nil, ErrInvalidFrame
	}
	var message Message
	switch outer.Type {
	case TypeHello:
		message = &Hello{}
	case TypeWelcome:
		message = &Welcome{}
	case TypeReady:
		message = &Ready{}
	case TypeActivate:
		message = &Activate{}
	case TypeHeartbeat:
		message = &Heartbeat{}
	case TypeStatus:
		message = &Status{}
	case TypeError:
		message = &Error{}
	default:
		return nil, ErrInvalidFrame
	}
	if err := decodeStrict(outer.Body, message); err != nil || message.validate() != nil {
		return nil, ErrInvalidFrame
	}
	return message, nil
}

// WriteFrame adds the unambiguous length prefix required for stream sockets.
func WriteFrame(writer io.Writer, message Message) error {
	frame, err := Encode(message)
	if err != nil {
		return err
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeAll(writer, frame)
}

// ReadFrame reads exactly one bounded message. A malformed or truncated length
// prefix is never interpreted as a valid protocol message.
func ReadFrame(reader io.Reader) (Message, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > MaxFrameBytes {
		return nil, ErrInvalidFrame
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, err
	}
	return Decode(frame)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validateLeaseMessage(workerID string, apiVersion uint16, epoch uint64, lease string) error {
	if !validWorkerID(workerID) || !validAPIVersion(apiVersion) || epoch == 0 || !validLease(lease) {
		return ErrInvalidFrame
	}
	return nil
}

func validWorkerID(value string) bool { return workerIDPattern.MatchString(value) }
func validVersion(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !bytes.ContainsAny([]byte(value), "\x00\r\n")
}
func validRange(minimum, maximum uint16) bool {
	return minimum > 0 && minimum <= maximum && maximum <= maxAPIVersion
}
func validAPIVersion(value uint16) bool { return value > 0 && value <= maxAPIVersion }
func validLease(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}
func validErrorCode(value string) bool {
	return value == "incompatible" || value == "fenced" || value == "not_ready" || value == "invalid"
}

// Controller owns the active-worker fence. It is intentionally in-memory: the
// later hostd service must persist the returned active state before admitting
// application work. Keeping this type free of filesystem and service-manager
// concerns makes its fence behavior deterministic and easy to test.
type Controller struct {
	mu        sync.Mutex
	apiMin    uint16
	apiMax    uint16
	random    io.Reader
	active    worker
	candidate worker
	lastEpoch uint64
	persist   func(Status) error
	now       func() time.Time
}

type worker struct {
	workerID      string
	apiVersion    uint16
	epoch         uint64
	lease         string
	ready         bool
	lastHeartbeat time.Time
}

type ControllerConfig struct {
	APIMin       uint16
	APIMax       uint16
	Random       io.Reader
	InitialEpoch uint64
	// PersistActivation must crash-consistently record the new active fence.
	// Activate does not expose or accept the new epoch until this succeeds.
	PersistActivation func(Status) error
	Clock             func() time.Time
}

func NewController(config ControllerConfig) (*Controller, error) {
	if !validRange(config.APIMin, config.APIMax) {
		return nil, ErrInvalidConfig
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Controller{
		apiMin: config.APIMin, apiMax: config.APIMax, random: config.Random,
		lastEpoch: config.InitialEpoch, persist: config.PersistActivation, now: config.Clock,
	}, nil
}

// Negotiate replaces any unready candidate with a freshly fenced candidate.
// It never changes the active worker.
func (c *Controller) Negotiate(hello Hello) (Welcome, error) {
	if hello.validate() != nil {
		return Welcome{}, ErrInvalidFrame
	}
	apiVersion, ok := selectVersion(c.apiMin, c.apiMax, hello.APIMin, hello.APIMax)
	if !ok {
		return Welcome{}, ErrIncompatible
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active.epoch > c.lastEpoch {
		c.lastEpoch = c.active.epoch
	}
	if c.lastEpoch == ^uint64(0) {
		return Welcome{}, ErrEpochExhausted
	}
	lease, err := c.newUniqueLeaseLocked()
	if err != nil {
		return Welcome{}, err
	}
	epoch := c.lastEpoch + 1
	c.lastEpoch = epoch
	c.candidate = worker{workerID: hello.WorkerID, apiVersion: apiVersion, epoch: epoch, lease: lease}
	return Welcome{WorkerID: hello.WorkerID, APIVersion: apiVersion, Epoch: epoch, Lease: lease}, nil
}

// MarkReady accepts readiness only from the current candidate lease.
func (c *Controller) MarkReady(message Ready) error {
	if message.validate() != nil {
		return ErrInvalidFrame
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !matches(c.candidate, message.WorkerID, message.APIVersion, message.Epoch, message.Lease) {
		return ErrFenced
	}
	c.candidate.ready = true
	return nil
}

// Activate promotes a ready candidate and fences the former active worker in
// the same critical section. No active lease survives this method.
func (c *Controller) Activate(message Activate) (Status, error) {
	if message.validate() != nil {
		return Status{}, ErrInvalidFrame
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !matches(c.candidate, message.WorkerID, message.APIVersion, message.Epoch, message.Lease) {
		return Status{}, ErrFenced
	}
	if !c.candidate.ready {
		return Status{}, ErrNotReady
	}
	status := statusFor(c.candidate, StateActive)
	if c.persist != nil {
		if err := c.persist(status); err != nil {
			return Status{}, fmt.Errorf("persist hostd worker activation: %w", err)
		}
	}
	c.active, c.candidate = c.candidate, worker{}
	return status, nil
}

// AcceptHeartbeat is the gate that future worker operations must use before
// they can affect hostd state. A stale worker cannot regain access by sending a
// delayed heartbeat with a valid old lease.
func (c *Controller) AcceptHeartbeat(message Heartbeat) error {
	if message.validate() != nil {
		return ErrInvalidFrame
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !matches(c.active, message.WorkerID, message.APIVersion, message.Epoch, message.Lease) {
		return ErrFenced
	}
	c.active.lastHeartbeat = c.now().UTC()
	return nil
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active.epoch != 0 {
		return statusFor(c.active, StateActive)
	}
	if c.candidate.epoch != 0 {
		return statusFor(c.candidate, StateCandidate)
	}
	return Status{State: StateEmpty}
}

// CandidateStatus is intentionally distinct from Status: while an old worker
// is active, a ready candidate must still receive proof of its own epoch.
func (c *Controller) CandidateStatus() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.candidate.epoch != 0 {
		return statusFor(c.candidate, StateCandidate)
	}
	return Status{State: StateEmpty}
}

// Handle is the only lifecycle dispatch needed by a future local socket
// server. It deliberately accepts no opaque application operation: callers
// must add a separately reviewed, typed hostd API for new worker privileges.
func (c *Controller) Handle(message Message) (Message, error) {
	if message == nil || message.validate() != nil {
		return nil, ErrInvalidFrame
	}
	switch value := message.(type) {
	case Hello:
		return c.Negotiate(value)
	case *Hello:
		return c.Negotiate(*value)
	case Ready:
		if err := c.MarkReady(value); err != nil {
			return nil, err
		}
		return c.CandidateStatus(), nil
	case *Ready:
		if err := c.MarkReady(*value); err != nil {
			return nil, err
		}
		return c.CandidateStatus(), nil
	case Activate:
		return c.Activate(value)
	case *Activate:
		return c.Activate(*value)
	case Heartbeat:
		if err := c.AcceptHeartbeat(value); err != nil {
			return nil, err
		}
		return c.Status(), nil
	case *Heartbeat:
		if err := c.AcceptHeartbeat(*value); err != nil {
			return nil, err
		}
		return c.Status(), nil
	case Status:
		if value.State != StateEmpty {
			return nil, ErrInvalidFrame
		}
		return c.Status(), nil
	case *Status:
		if value.State != StateEmpty {
			return nil, ErrInvalidFrame
		}
		return c.Status(), nil
	default:
		return nil, ErrInvalidFrame
	}
}

func statusFor(value worker, state State) Status {
	status := Status{State: state, WorkerID: value.workerID, APIVersion: value.apiVersion, Epoch: value.epoch}
	if state == StateActive && !value.lastHeartbeat.IsZero() {
		status.LastHeartbeatUnixMilli = value.lastHeartbeat.UnixMilli()
	}
	return status
}

func matches(value worker, workerID string, apiVersion uint16, epoch uint64, lease string) bool {
	return value.epoch != 0 && value.workerID == workerID && value.apiVersion == apiVersion && value.epoch == epoch && value.lease == lease
}

func selectVersion(hostMin, hostMax, workerMin, workerMax uint16) (uint16, bool) {
	minimum := hostMin
	if workerMin > minimum {
		minimum = workerMin
	}
	maximum := hostMax
	if workerMax < maximum {
		maximum = workerMax
	}
	if minimum > maximum {
		return 0, false
	}
	return maximum, true
}

func newLease(random io.Reader) (string, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("create worker lease: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (c *Controller) newUniqueLeaseLocked() (string, error) {
	for range 4 {
		lease, err := newLease(c.random)
		if err != nil {
			return "", err
		}
		if lease != c.active.lease && lease != c.candidate.lease {
			return lease, nil
		}
	}
	return "", ErrLeaseGeneration
}
