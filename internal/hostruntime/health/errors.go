package health

import "fmt"

// ErrorCode identifies a health contract violation without making callers
// branch on error text.
type ErrorCode string

const (
	ErrorInvalidDimension   ErrorCode = "invalid_dimension"
	ErrorInvalidStatus      ErrorCode = "invalid_status"
	ErrorInvalidCode        ErrorCode = "invalid_code"
	ErrorInvalidRetry       ErrorCode = "invalid_retry"
	ErrorInvalidTime        ErrorCode = "invalid_time"
	ErrorInvalidString      ErrorCode = "invalid_string"
	ErrorInvalidID          ErrorCode = "invalid_id"
	ErrorInvalidObservation ErrorCode = "invalid_observation"
)

// Error is a typed health error. Operation is deliberately generic and never
// contains an input value, which keeps errors safe to expose to diagnostics.
type Error struct {
	Code      ErrorCode
	Operation string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Code)
}

func newError(code ErrorCode, operation string) error {
	return &Error{Code: code, Operation: operation}
}
