//go:build windows

package updated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/supervisorupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

const ControlProtocolV1 = "paperboat.updated/v1"
const maxUpdateControlTimeout = 15 * time.Minute

var (
	ErrInvalidControl = errors.New("invalid paperboat-updated control request")
	ErrControlDenied  = errors.New("paperboat-updated control peer is not the enrolled user")
)

type ControlRequest struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
	Release   string `json:"release,omitempty"`
}
type ControlResponse struct {
	Schema            string                        `json:"schema"`
	Status            string                        `json:"status"`
	Version           string                        `json:"version,omitempty"`
	Updated           bool                          `json:"updated"`
	Pending           bool                          `json:"pending,omitempty"`
	ActivationFailure string                        `json:"activation_failure,omitempty"`
	Observation       autoupdate.Observation        `json:"observation"`
	ErrorCode         string                        `json:"error_code,omitempty"`
	ErrorMessage      string                        `json:"error_message,omitempty"`
	Supervisor        supervisorupdate.Result       `json:"supervisor,omitempty"`
	Transaction       workerupdate.TransactionState `json:"transaction"`
}

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !validPipePath(socketPath) || timeout <= 0 || timeout > maxUpdateControlTimeout {
		return nil, ErrInvalidControl
	}
	return &Client{socketPath: socketPath, timeout: timeout}, nil
}
func (c *Client) Status(ctx context.Context) (ControlResponse, error) { return c.call(ctx, "status") }
func (c *Client) Check(ctx context.Context) (ControlResponse, error)  { return c.call(ctx, "check") }
func (c *Client) Update(ctx context.Context) (ControlResponse, error) { return c.call(ctx, "update") }
func (c *Client) ApproveMaintenance(ctx context.Context, release string) (ControlResponse, error) {
	return c.callRequest(ctx, ControlRequest{Schema: ControlProtocolV1, Operation: "approve-maintenance", Release: release})
}
func (c *Client) call(ctx context.Context, operation string) (ControlResponse, error) {
	return c.callRequest(ctx, ControlRequest{Schema: ControlProtocolV1, Operation: operation})
}
func (c *Client) callRequest(ctx context.Context, request ControlRequest) (ControlResponse, error) {
	if c == nil || !validControlRequest(request) {
		return ControlResponse{}, ErrInvalidControl
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(dialCtx, c.socketPath)
	if err != nil {
		return ControlResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return ControlResponse{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 16<<10))
	decoder.DisallowUnknownFields()
	var response ControlResponse
	var extra any
	if decoder.Decode(&response) != nil || decoder.Decode(&extra) != io.EOF || response.Schema != ControlProtocolV1 || (response.Status != "ok" && response.Status != "error") || !validControlResponseError(response.Status, response.ErrorCode, response.ErrorMessage) {
		return ControlResponse{}, ErrInvalidControl
	}
	if response.ErrorCode != "" {
		return ControlResponse{}, &ControlError{Code: response.ErrorCode, Message: response.ErrorMessage}
	}
	return response, nil
}

var exactReleasePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

func validControlRequest(request ControlRequest) bool {
	if request.Schema != "" && request.Schema != ControlProtocolV1 {
		return false
	}
	switch request.Operation {
	case "status", "check", "update":
		return request.Release == ""
	case "approve-maintenance":
		return exactReleasePattern.MatchString(request.Release)
	default:
		return false
	}
}

func validPipePath(path string) bool {
	const prefix = `\\.\pipe\`
	return len(path) > len(prefix) && len(path) <= 256 && path[:len(prefix)] == prefix && !containsPipePathSeparator(path[len(prefix):])
}
func containsPipePathSeparator(value string) bool {
	for _, character := range value {
		if character == '/' || character == '\\' || character == ':' || character == '*' || character == '?' || character == '"' || character == '<' || character == '>' || character == '|' {
			return true
		}
	}
	return false
}
