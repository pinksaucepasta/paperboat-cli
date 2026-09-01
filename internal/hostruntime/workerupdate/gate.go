package workerupdate

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

var ErrActivationGate = errors.New("worker update activation gate failed")

// ActivationGate owns the externally observable parts of a worker cutover.
// Candidate must traverse edge, connector, route, and a local health origin.
// Drain must stop new work on the previous generation and wait only until the
// supplied context deadline. Active repeats the end-to-end probe throughout
// the stability window. Rollback proves the restored signed release before a
// failed release is left quarantined.
type ActivationGate interface {
	Candidate(context.Context, GateRequest) error
	Drain(context.Context, GateRequest) error
	Active(context.Context, GateRequest) error
	Commit(context.Context, GateRequest) error
	Rollback(context.Context, GateRequest) error
}

type GateRequest struct {
	TransactionID string
	Previous      Release
	Candidate     Release
	Worker        hostdproto.Status
	Window        time.Duration
	Interval      time.Duration
}

func (r GateRequest) validate(candidateState hostdproto.State) error {
	if !safeEventID(r.TransactionID) || validateRelease(r.Previous) != nil || validateRelease(r.Candidate) != nil ||
		r.Worker.State != candidateState || r.Worker.WorkerID == "" || r.Worker.Epoch == 0 || r.Worker.APIVersion == 0 || r.Window < 0 || r.Interval < 0 {
		return ErrActivationGate
	}
	return nil
}

type EventPhase string

const (
	EventScheduled           EventPhase = "scheduled"
	EventDownloading         EventPhase = "downloading"
	EventCandidateValidating EventPhase = "candidate_validating"
	EventDraining            EventPhase = "draining"
	EventActivating          EventPhase = "activating"
	EventStability           EventPhase = "stability"
	EventCommitted           EventPhase = "committed"
	EventRolledBack          EventPhase = "rolled_back"
	EventQuarantined         EventPhase = "quarantined"
)

type Event struct {
	At            time.Time
	Phase         EventPhase
	TransactionID string
	FromVersion   string
	ToVersion     string
	Failure       string
}

type EventSink interface {
	RecordUpdateEvent(context.Context, Event) error
}

var eventIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func safeEventID(value string) bool { return eventIDPattern.MatchString(value) }
