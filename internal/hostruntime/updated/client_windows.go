//go:build windows

package updated

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
)

const ControlProtocolV1 = "paperboat.updated/v1"

var (
	ErrInvalidControl = errors.New("invalid paperboat-updated control request")
	ErrControlDenied  = errors.New("paperboat-updated control peer is not the enrolled user")
)

type ControlRequest struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
}
type ControlResponse struct {
	Schema      string                 `json:"schema"`
	Status      string                 `json:"status"`
	Version     string                 `json:"version,omitempty"`
	Updated     bool                   `json:"updated"`
	Observation autoupdate.Observation `json:"observation"`
	ErrorCode   string                 `json:"error_code,omitempty"`
}

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !validPipePath(socketPath) || timeout <= 0 || timeout > 3*time.Minute {
		return nil, ErrInvalidControl
	}
	return &Client{socketPath: socketPath, timeout: timeout}, nil
}
func (c *Client) Status(ctx context.Context) (ControlResponse, error) { return c.call(ctx, "status") }
func (c *Client) Check(ctx context.Context) (ControlResponse, error)  { return c.call(ctx, "check") }
func (c *Client) Update(ctx context.Context) (ControlResponse, error) { return c.call(ctx, "update") }
func (c *Client) call(ctx context.Context, operation string) (ControlResponse, error) {
	if c == nil || (operation != "status" && operation != "check" && operation != "update") {
		return ControlResponse{}, ErrInvalidControl
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(dialCtx, c.socketPath)
	if err != nil {
		return ControlResponse{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	if err := json.NewEncoder(connection).Encode(ControlRequest{Schema: ControlProtocolV1, Operation: operation}); err != nil {
		return ControlResponse{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 16<<10))
	decoder.DisallowUnknownFields()
	var response ControlResponse
	var extra any
	if decoder.Decode(&response) != nil || decoder.Decode(&extra) != io.EOF || response.Schema != ControlProtocolV1 || (response.Status != "ok" && response.Status != "error") {
		return ControlResponse{}, ErrInvalidControl
	}
	if response.ErrorCode != "" {
		return ControlResponse{}, errors.New(response.ErrorCode)
	}
	return response, nil
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
