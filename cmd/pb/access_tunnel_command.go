package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	accessTunnelSchema        = "paperboat.private-tcp-access/v1"
	accessTunnelResponseLimit = 16 << 10
)

var (
	ErrAccessTunnelInvalid               = errors.New("invalid private tunnel access request")
	ErrAccessTunnelAuthentication        = errors.New("Paperboat authentication is required")
	ErrAccessTunnelForbidden             = errors.New("Paperboat private access is not allowed")
	ErrAccessTunnelUnavailable           = errors.New("Paperboat private access is temporarily unavailable")
	ErrAccessTunnelRuntimeRPCUnavailable = errors.New("installed hostd does not expose private TCP access")
)

type accessTunnelSession struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	TunnelID      string `json:"tunnel_id"`
	RouteID       string `json:"route_id"`
	ListenAddress string `json:"listen_address"`
}

type accessTunnelRuntime interface {
	Start(context.Context, string, string) (accessTunnelSession, error)
	Release(context.Context, accessTunnelSession) error
}

var accessTunnelRuntimeForCommand = newProductionAccessTunnelRuntime

func accessTunnelCobraCommandV1() *cobra.Command {
	command := tunnelCommand("tunnel <tunnel-or-route>", "Open private TCP access through stable hostd", cobra.ExactArgs(1), runAccessTunnel)
	command.Flags().String("listen", "127.0.0.1:0", "literal-loopback listen address")
	tunnelJSONFlag(command)
	return command
}

func runAccessTunnel(command *cobra.Command, args []string) error {
	listen, _ := command.Flags().GetString("listen")
	normalized, err := literalLoopbackAddress(listen)
	if err != nil {
		return err
	}
	runtime, err := accessTunnelRuntimeForCommand()
	if err != nil {
		return err
	}
	session, err := runtime.Start(command.Context(), args[0], normalized)
	if err != nil {
		return err
	}
	human := fmt.Sprintf("Private access for route %s is listening on %s", session.RouteID, session.ListenAddress)
	if err = tunnelOutput(command, session, human); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(command.Context()), 5*time.Second)
		defer cancel()
		return errors.Join(err, runtime.Release(cleanupCtx, session))
	}
	<-command.Context().Done()
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(command.Context()), 5*time.Second)
	defer cancel()
	if releaseErr := runtime.Release(cleanupCtx, session); releaseErr != nil {
		return releaseErr
	}
	return command.Context().Err()
}

func literalLoopbackAddress(value string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", ErrAccessTunnelInvalid
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || (host != "127.0.0.1" && host != "::1") {
		return "", ErrAccessTunnelInvalid
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 0 || parsed > 65535 || strconv.Itoa(parsed) != port {
		return "", ErrAccessTunnelInvalid
	}
	return net.JoinHostPort(host, port), nil
}

type localAccessTunnelClient struct {
	base   *url.URL
	token  string
	client *http.Client
}

func newProductionAccessTunnelRuntime() (accessTunnelRuntime, error) {
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return nil, errors.Join(ErrAccessTunnelUnavailable, err)
	}
	descriptor, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "worker-local.json"), 4096)
	if err != nil {
		return nil, errors.Join(ErrAccessTunnelUnavailable, err)
	}
	var local struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}
	decoder := json.NewDecoder(bytes.NewReader(descriptor))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&local) != nil || decoder.Decode(&struct{}{}) != io.EOF || local.Schema != "paperboat.worker-local/v1" {
		return nil, ErrAccessTunnelUnavailable
	}
	endpoint, err := url.Parse("http://" + local.ListenAddress)
	if err != nil || endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "::1" || endpoint.Port() == "" {
		return nil, ErrAccessTunnelUnavailable
	}
	token, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "local-control-token"), 1024)
	if err != nil || strings.TrimSpace(string(token)) == "" || len(token) > 1024 {
		return nil, ErrAccessTunnelUnavailable
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAccessTunnelInvalid }}
	return &localAccessTunnelClient{base: endpoint, token: strings.TrimSpace(string(token)), client: client}, nil
}

func (c *localAccessTunnelClient) Start(ctx context.Context, selector, listen string) (accessTunnelSession, error) {
	if c == nil || ctx == nil || !validAccessTunnelSelector(selector) {
		return accessTunnelSession{}, ErrAccessTunnelInvalid
	}
	body, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		Kind          string `json:"kind"`
		Selector      string `json:"selector"`
		ListenAddress string `json:"listen_address"`
	}{accessTunnelSchema, "private_tcp_access_request", selector, listen})
	if err != nil {
		return accessTunnelSession{}, ErrAccessTunnelInvalid
	}
	response, data, err := c.do(ctx, http.MethodPost, "/v1/private-tcp-access", body)
	if err != nil {
		return accessTunnelSession{}, err
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return accessTunnelSession{}, accessTunnelHTTPError(response.StatusCode)
	}
	if rejectAccessTunnelDuplicateJSON(data) != nil {
		return accessTunnelSession{}, ErrAccessTunnelInvalid
	}
	var out accessTunnelSession
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validAccessTunnelSession(out, listen) {
		return accessTunnelSession{}, ErrAccessTunnelInvalid
	}
	return out, nil
}

func (c *localAccessTunnelClient) Release(ctx context.Context, session accessTunnelSession) error {
	if c == nil || ctx == nil || !validAccessTunnelSession(session, session.ListenAddress) {
		return ErrAccessTunnelInvalid
	}
	response, _, err := c.do(ctx, http.MethodDelete, "/v1/private-tcp-access/"+url.PathEscape(session.ID), nil)
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusGone || response.StatusCode == http.StatusNotFound {
		return nil
	}
	return accessTunnelHTTPError(response.StatusCode)
}

func (c *localAccessTunnelClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, []byte, error) {
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, nil, ErrAccessTunnelInvalid
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, nil, errors.Join(ErrAccessTunnelUnavailable, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, accessTunnelResponseLimit+1))
	if err != nil || len(data) > accessTunnelResponseLimit {
		return response, nil, ErrAccessTunnelInvalid
	}
	return response, data, nil
}

func accessTunnelHTTPError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return ErrAccessTunnelAuthentication
	case http.StatusForbidden:
		return ErrAccessTunnelForbidden
	case http.StatusServiceUnavailable:
		return ErrAccessTunnelUnavailable
	case http.StatusNotFound:
		return ErrAccessTunnelRuntimeRPCUnavailable
	default:
		return fmt.Errorf("%w: hostd returned status %d", ErrAccessTunnelInvalid, status)
	}
}
func validAccessTunnelSelector(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && len(v) <= 256 && !strings.ContainsAny(v, "\x00\r\n/\\")
}
func validAccessTunnelSession(v accessTunnelSession, requested string) bool {
	if v.Schema != accessTunnelSchema || v.Kind != "private_tcp_access" || !validAccessTunnelSelector(v.ID) || !validAccessTunnelSelector(v.TunnelID) || !validAccessTunnelSelector(v.RouteID) {
		return false
	}
	wantHost, wantPort, err := net.SplitHostPort(requested)
	if err != nil {
		return false
	}
	gotHost, gotPort, err := net.SplitHostPort(v.ListenAddress)
	if err != nil || gotHost != wantHost {
		return false
	}
	parsed, err := strconv.Atoi(gotPort)
	if err != nil || parsed < 1 || parsed > 65535 {
		return false
	}
	return wantPort == "0" || wantPort == gotPort
}

func rejectAccessTunnelDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrAccessTunnelInvalid
				}
				if _, exists := seen[key]; exists {
					return ErrAccessTunnelInvalid
				}
				seen[key] = struct{}{}
				if err = walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrAccessTunnelInvalid
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrAccessTunnelInvalid
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrAccessTunnelInvalid
	}
	return nil
}
