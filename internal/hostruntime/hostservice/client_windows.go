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

func (c *Client) ReconcileAuthorizedKeys(ctx context.Context, keys []string) (bool, error) {
	if len(keys) > maxAuthorizedKeys {
		return false, ErrInvalidRequest
	}
	requestKeys := make([]string, len(keys))
	copy(requestKeys, keys)
	response, err := c.call(ctx, Request{Schema: ProtocolV1, Operation: "reconcile_ssh_authorized_keys", AuthorizedKeys: &requestKeys})
	if err != nil {
		return false, err
	}
	if !response.AuthorizedKeysReconciled || response.UpdateVersion != "" {
		return false, ErrInvalidRequest
	}
	return response.AuthorizedKeysChanged, nil
}

func (c *Client) Activate(ctx context.Context, artifact bootstrap.ArtifactTarget) (string, error) {
	response, err := c.call(ctx, Request{Schema: ProtocolV1, Operation: "activate_update", Artifact: &artifact})
	if err != nil {
		return "", err
	}
	if response.UpdateVersion == "" || response.UpdateVersion != artifact.Version || response.AuthorizedKeysReconciled || response.AuthorizedKeysChanged {
		return "", ErrInvalidRequest
	}
	return response.UpdateVersion, nil
}

func (c *Client) call(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(dialCtx, c.socketPath)
	if err != nil {
		return Response{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	body, err := json.Marshal(request)
	if err != nil || len(body)+1 > windowsHostServiceMaxRequestSize {
		return Response{}, errors.Join(ErrInvalidRequest, err)
	}
	body = append(body, '\n')
	written, err := connection.Write(body)
	if err != nil {
		return Response{}, err
	}
	if written != len(body) {
		return Response{}, io.ErrShortWrite
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 16<<10))
	decoder.DisallowUnknownFields()
	var response Response
	var extra any
	if decoder.Decode(&response) != nil || decoder.Decode(&extra) != io.EOF || response.Schema != ProtocolV1 || response.Scope != "system" || response.HostServiceVersion == "" {
		return Response{}, ErrInvalidRequest
	}
	if response.ErrorCode != "" {
		return Response{}, errors.New(response.ErrorCode)
	}
	return response, nil
}
