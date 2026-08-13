package transportstage

import "fmt"

// Error identifies the transport setup boundary that failed while preserving
// the typed root error for callers that decide retry and fallback policy.
type Error struct {
	Stage string
	Err   error
}

func (e *Error) Error() string {
	if e == nil {
		return "transport stage failed"
	}
	return fmt.Sprintf("wss stage %s: %v", e.Stage, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Wrap(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Stage: stage, Err: err}
}
