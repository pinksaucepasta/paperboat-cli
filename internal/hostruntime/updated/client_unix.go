//go:build darwin || linux

package updated

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

// Client exposes only the fixed local updater operations. It cannot submit a
// binary, a release URL, or an activation command.
type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) || timeout <= 0 || timeout > maxUpdateControlTimeout {
		return nil, ErrInvalidConfig
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
	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "unix", c.socketPath)
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
	closer, ok := connection.(interface{ CloseWrite() error })
	if !ok || closer.CloseWrite() != nil {
		return ControlResponse{}, ErrInvalidControl
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
