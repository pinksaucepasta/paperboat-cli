//go:build windows

package hostservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

const defaultSocketPath = `\\.\pipe\PaperboatHostService`

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !validPipePath(socketPath) || timeout <= 0 || timeout > 2*time.Minute {
		return nil, ErrInvalidConfig
	}
	return &Client{socketPath: socketPath, timeout: timeout}, nil
}
func DefaultSocketPath() string { return defaultSocketPath }
func (c *Client) Activate(ctx context.Context, artifact bootstrap.ArtifactTarget) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(dialCtx, c.socketPath)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	if err := json.NewEncoder(connection).Encode(Request{Schema: ProtocolV1, Operation: "activate_update", Artifact: &artifact}); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 16<<10))
	decoder.DisallowUnknownFields()
	var response Response
	var extra any
	if decoder.Decode(&response) != nil || decoder.Decode(&extra) != io.EOF || response.Schema != ProtocolV1 || response.Scope != "system" || response.HostServiceVersion == "" {
		return "", ErrInvalidRequest
	}
	if response.ErrorCode != "" {
		return "", errors.New(response.ErrorCode)
	}
	if response.UpdateVersion == "" || response.UpdateVersion != artifact.Version {
		return "", ErrInvalidRequest
	}
	return response.UpdateVersion, nil
}
