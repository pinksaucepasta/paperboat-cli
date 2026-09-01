package observability

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
)

const (
	// EventSchemaV1 is shared with server and edge telemetry for cross-component
	// correlation.
	EventSchemaV1       = "paperboat.edge_event.v1"
	maximumEventLogSize = 4096
)

type EventSeverity string

const (
	SeverityDebug EventSeverity = "debug"
	SeverityInfo  EventSeverity = "info"
	SeverityWarn  EventSeverity = "warn"
	SeverityError EventSeverity = "error"
)

type EventOutcome string

const (
	OutcomeSuccess     EventOutcome = "success"
	OutcomeFailed      EventOutcome = "failed"
	OutcomeRejected    EventOutcome = "rejected"
	OutcomeCanceled    EventOutcome = "canceled"
	OutcomeStateChange EventOutcome = "state_change"
)

// Dimension and retry aliases keep host event construction source-compatible
// with the typed health contract.
// Dimension is a string alias rather than a distinct type so legacy event
// projections can pass component values into generic canonical metadata.
type Dimension = string
type RetryDecision = health.RetryDecision

const (
	DimensionService     = string(health.DimensionService)
	DimensionEdge        = string(health.DimensionEdge)
	DimensionConfig      = string(health.DimensionConfig)
	DimensionRoute       = string(health.DimensionRoute)
	DimensionOrigin      = string(health.DimensionOrigin)
	DimensionDNS         = string(health.DimensionDNS)
	DimensionCertificate = string(health.DimensionCertificate)
	DimensionAccess      = string(health.DimensionAccess)
	DimensionUpdate      = string(health.DimensionUpdate)

	RetryNone          = health.RetryNone
	RetryScheduled     = health.RetryScheduled
	RetryWaitForChange = health.RetryWaitForChange
	RetryNotRetryable  = health.RetryNotRetryable
)

// SafeIDs contains only opaque, prefix-scoped identifiers. Hostnames, URLs,
// credentials and arbitrary user labels must never be put in this object.
type SafeIDs struct {
	AccountID     string `json:"account_id,omitempty"`
	ActorID       string `json:"actor_id,omitempty"`
	TunnelID      string `json:"tunnel_id,omitempty"`
	RouteID       string `json:"route_id,omitempty"`
	ConnectorID   string `json:"connector_id,omitempty"`
	DomainID      string `json:"domain_id,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	AssignmentID  string `json:"assignment_id,omitempty"`
	HostID        string `json:"host_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	OperationID   string `json:"operation_id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	EdgeNodeID    string `json:"edge_node_id,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	ProcessID     string `json:"process_id,omitempty"`
	ConfigID      string `json:"config_id,omitempty"`
}

type Generations struct {
	Config       uint64 `json:"config,omitempty"`
	Route        uint64 `json:"route,omitempty"`
	Assignment   uint64 `json:"assignment,omitempty"`
	Connector    uint64 `json:"connector,omitempty"`
	Process      uint64 `json:"process,omitempty"`
	Session      uint64 `json:"session,omitempty"`
	Installation uint64 `json:"installation,omitempty"`
	Credential   uint64 `json:"credential,omitempty"`
	Certificate  uint64 `json:"certificate,omitempty"`
}

type EventInput struct {
	At            time.Time
	Severity      EventSeverity
	Component     Dimension
	Name          string
	Code          string
	Outcome       EventOutcome
	Message       string
	CorrelationID string
	IDs           SafeIDs
	Generations   Generations
	Retry         RetryDecision
	NextRetryAt   time.Time

	// Convenience identity fields are folded into IDs at construction. They
	// make lifecycle call sites explicit while preserving one wire shape.
	ResourceID string
	SessionID  string
	ProcessID  string
	ConfigID   string
}

var safeIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,127}$`)

func NewEvent(input EventInput) (Event, error) {
	if normalizeEventTime(input.At).IsZero() {
		return Event{}, newError(ErrorInvalidEventTime, "construct host event")
	}
	if !validEventSeverity(input.Severity) || !validEventDimension(input.Component) ||
		!stableEventCodePattern.MatchString(input.Name) || !stableEventCodePattern.MatchString(input.Code) ||
		!validEventOutcome(input.Outcome) {
		return Event{}, newError(ErrorInvalidEvent, "construct host event")
	}
	if !validEventCorrelationID(input.CorrelationID) {
		return Event{}, newError(ErrorInvalidEventID, "construct host event")
	}
	ids := input.IDs
	if err := mergeEventIdentity(&ids, input); err != nil {
		return Event{}, err
	}
	if !validSafeIDs(ids) {
		return Event{}, newError(ErrorInvalidEventID, "construct host event")
	}
	if !validEventRetry(input.Retry, input.NextRetryAt) {
		return Event{}, newError(ErrorInvalidEventRetry, "construct host event")
	}
	message, err := safeBoundedString(input.Message, maximumMessageBytes, true)
	if err != nil {
		return Event{}, newError(ErrorInvalidEventMessage, "construct host event")
	}
	event := Event{
		Schema:        EventSchemaV1,
		At:            normalizeEventTime(input.At),
		Severity:      input.Severity,
		Component:     input.Component,
		Name:          input.Name,
		Code:          input.Code,
		Outcome:       input.Outcome,
		Message:       message,
		CorrelationID: input.CorrelationID,
		IDs:           ids,
		Generations:   input.Generations,
		Retry:         input.Retry,
		// Keep legacy projections useful to callers that pass the event to the
		// existing slog adapter.
		Operation:  input.Name,
		Result:     string(input.Outcome),
		ErrorCode:  input.Code,
		ResourceID: ids.ResourceID,
	}
	if !input.NextRetryAt.IsZero() {
		nextRetry := normalizeEventTime(input.NextRetryAt)
		event.NextRetryAt = &nextRetry
	}
	return event, nil
}

func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

func validEventSeverity(value EventSeverity) bool {
	return value == SeverityDebug || value == SeverityInfo || value == SeverityWarn || value == SeverityError
}

func validEventOutcome(value EventOutcome) bool {
	return value == OutcomeSuccess || value == OutcomeFailed || value == OutcomeRejected || value == OutcomeCanceled || value == OutcomeStateChange
}

func validEventDimension(value Dimension) bool {
	for _, dimension := range health.Dimensions() {
		if value == string(dimension) {
			return true
		}
	}
	return false
}

func validEventCorrelationID(value string) bool {
	return hasEventSafePrefix(value, "corr_", "cor_", "correlation_", "request_", "pb-")
}

func validSafeIDs(ids SafeIDs) bool {
	return optionalEventID(ids.AccountID, "account_") &&
		optionalEventID(ids.ActorID, "actor_") &&
		optionalEventID(ids.TunnelID, "tunnel_") &&
		optionalEventID(ids.RouteID, "route_") &&
		optionalEventID(ids.ConnectorID, "connector_") &&
		optionalEventID(ids.DomainID, "domain_") &&
		optionalEventID(ids.CertificateID, "certificate_") &&
		optionalEventID(ids.AssignmentID, "assignment_") &&
		optionalEventID(ids.HostID, "host_") &&
		optionalEventID(ids.DeviceID, "device_") &&
		optionalEventID(ids.SessionID, "session_", "carrier_") &&
		optionalEventID(ids.OperationID, "operation_", "op_") &&
		optionalEventID(ids.RequestID, "request_", "req_") &&
		optionalEventID(ids.EdgeNodeID, "edge_") &&
		optionalEventID(ids.ResourceID, "resource_", "res_") &&
		optionalEventID(ids.ProcessID, "process_", "proc_") &&
		optionalEventID(ids.ConfigID, "config_", "cfg_")
}

func mergeEventIdentity(ids *SafeIDs, input EventInput) error {
	for value, destination := range map[string]*string{
		input.ResourceID: &ids.ResourceID,
		input.SessionID:  &ids.SessionID,
		input.ProcessID:  &ids.ProcessID,
		input.ConfigID:   &ids.ConfigID,
	} {
		if value == "" {
			continue
		}
		if *destination != "" && *destination != value {
			return newError(ErrorInvalidEventID, "construct host event")
		}
		*destination = value
	}
	return nil
}

func optionalEventID(value string, prefixes ...string) bool {
	return value == "" || hasEventSafePrefix(value, prefixes...)
}

func hasEventSafePrefix(value string, prefixes ...string) bool {
	if !safeIDPattern.MatchString(value) {
		return false
	}
	for _, prefix := range prefixes {
		if len(value) > len(prefix) && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func validEventRetry(decision RetryDecision, next time.Time) bool {
	switch decision {
	case RetryScheduled:
		return !next.IsZero()
	case RetryNone, RetryWaitForChange, RetryNotRetryable:
		return next.IsZero()
	default:
		return false
	}
}

func normalizeEventTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}

// EventLog is a bounded nonblocking producer path backed by an owned worker.
// Record and TryRecord only enqueue into a finite channel and never wait for a
// sink or a slow reader. Accepted events are retained in a bounded ring.
type EventLog struct {
	mu       sync.RWMutex
	gate     sync.RWMutex
	capacity int
	events   []Event
	queue    chan eventItem
	commands chan flushCommand
	stop     chan struct{}
	done     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Uint64
	closeMu  sync.Mutex
}

type eventItem struct {
	event   Event
	barrier chan struct{}
}

type flushCommand struct{ done chan struct{} }

func NewEventLog(capacity int) (*EventLog, error) {
	queueCapacity := capacity * 2
	if queueCapacity < capacity || queueCapacity > maximumEventLogSize {
		queueCapacity = maximumEventLogSize
	}
	return NewEventLogWithQueue(capacity, queueCapacity)
}

func NewEventLogWithQueue(capacity, queueCapacity int) (*EventLog, error) {
	if capacity <= 0 || capacity > maximumEventLogSize || queueCapacity <= 0 || queueCapacity > maximumEventLogSize {
		return nil, newError(ErrorInvalidEventCapacity, "construct host event log")
	}
	log := &EventLog{
		capacity: capacity,
		events:   make([]Event, 0, capacity),
		queue:    make(chan eventItem, queueCapacity),
		commands: make(chan flushCommand),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go log.run()
	return log, nil
}

func (l *EventLog) run() {
	defer close(l.done)
	for {
		select {
		case item := <-l.queue:
			if item.barrier != nil {
				close(item.barrier)
				continue
			}
			l.append(item.event)
		case command := <-l.commands:
			l.drain()
			close(command.done)
		case <-l.stop:
			l.drain()
			return
		}
	}
}

func (l *EventLog) drain() {
	for {
		select {
		case item := <-l.queue:
			if item.barrier != nil {
				close(item.barrier)
			} else {
				l.append(item.event)
			}
		default:
			return
		}
	}
}

func (l *EventLog) append(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == l.capacity {
		copy(l.events, l.events[1:])
		l.events[len(l.events)-1] = cloneEvent(event)
		l.dropped.Add(1)
		return
	}
	l.events = append(l.events, cloneEvent(event))
}

func (l *EventLog) Record(input EventInput) (Event, error) {
	event, err := NewEvent(input)
	if err != nil {
		return Event{}, err
	}
	if l == nil {
		return event, nil
	}
	if !l.gate.TryRLock() {
		l.dropped.Add(1)
		return event, nil
	}
	defer l.gate.RUnlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, nil
	}
	select {
	case l.queue <- eventItem{event: event}:
	default:
		l.dropped.Add(1)
	}
	return event, nil
}

// TryRecord reports whether the event was accepted while retaining the same
// nonblocking semantics as Record.
func (l *EventLog) TryRecord(input EventInput) (Event, bool, error) {
	event, err := NewEvent(input)
	if err != nil {
		return Event{}, false, err
	}
	if l == nil {
		return event, false, nil
	}
	if !l.mu.TryLock() {
		l.dropped.Add(1)
		return event, false, nil
	}
	l.mu.Unlock()
	if !l.gate.TryRLock() {
		l.dropped.Add(1)
		return event, false, nil
	}
	defer l.gate.RUnlock()
	if l.closed.Load() {
		l.dropped.Add(1)
		return event, false, nil
	}
	select {
	case l.queue <- eventItem{event: event}:
		return event, true, nil
	default:
		l.dropped.Add(1)
		return event, false, nil
	}
}

func (l *EventLog) Flush(ctx context.Context) error {
	if l == nil || l.closed.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	command := flushCommand{done: make(chan struct{})}
	select {
	case l.commands <- command:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return nil
	}
	select {
	case <-command.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *EventLog) Snapshot() []Event {
	if l == nil {
		return nil
	}
	_ = l.Flush(context.Background())
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Event, len(l.events))
	for index, event := range l.events {
		result[index] = cloneEvent(event)
	}
	return result
}

func (l *EventLog) DroppedEvents() uint64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

func (l *EventLog) DropCount() uint64 { return l.DroppedEvents() }
func (l *EventLog) Dropped() uint64   { return l.DroppedEvents() }

func (l *EventLog) Close() error {
	if l == nil {
		return nil
	}
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed.Load() {
		<-l.done
		return nil
	}
	l.gate.Lock()
	l.closed.Store(true)
	close(l.stop)
	l.gate.Unlock()
	<-l.done
	return nil
}

func cloneEvent(event Event) Event {
	if event.NextRetryAt != nil {
		next := *event.NextRetryAt
		event.NextRetryAt = &next
	}
	return event
}
