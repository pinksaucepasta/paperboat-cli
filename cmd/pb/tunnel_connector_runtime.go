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

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/spf13/cobra"
)

var connectorEnrollmentLocalClient = productionConnectorEnrollmentLocalClient

func runProductionTunnelConnectorAdd(command *cobra.Command, tunnelID string) error {
	if command == nil || strings.TrimSpace(tunnelID) == "" {
		return tunnelenrollment.ErrInvalid
	}
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return fmt.Errorf("resolve Paperboat host state: %w", err)
	}
	if err = ensureTunnelHostRuntime(command.Context(), stateRoot); err != nil {
		return err
	}
	client, err := connectorEnrollmentLocalClient(stateRoot)
	if err != nil {
		return err
	}
	key, err := newTunnelIdempotencyKey()
	if err != nil {
		return err
	}
	projection, err := client.Enroll(command.Context(), tunnelID, "connector-add-"+strings.TrimPrefix(key, "pb_tunnel_"))
	if err != nil {
		return err
	}
	return tunnelOutput(command, projection, fmt.Sprintf("Added connector %s to tunnel %s", projection.ConnectorID, projection.TunnelID))
}

type tunnelConnectorEnrollmentClient interface {
	Enroll(context.Context, string, string) (tunnelenrollment.Projection, error)
}

func productionConnectorEnrollmentLocalClient(stateRoot string) (tunnelConnectorEnrollmentClient, error) {
	if !filepath.IsAbs(stateRoot) {
		return nil, tunnelenrollment.ErrUnavailable
	}
	descriptor, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "worker-local.json"), 4096)
	if err != nil {
		return nil, errors.Join(tunnelenrollment.ErrUnavailable, err)
	}
	var local struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}
	decoder := json.NewDecoder(bytes.NewReader(descriptor))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&local) != nil || decoder.Decode(&struct{}{}) != io.EOF || local.Schema != "paperboat.worker-local/v1" {
		return nil, tunnelenrollment.ErrUnavailable
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(local.ListenAddress))
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return nil, tunnelenrollment.ErrUnavailable
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, tunnelenrollment.ErrUnavailable
	}
	token, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "local-control-token"), 1024)
	if err != nil || strings.TrimSpace(string(token)) == "" {
		return nil, tunnelenrollment.ErrUnavailable
	}
	endpoint := (&url.URL{Scheme: "http", Host: local.ListenAddress}).String()
	return tunnelenrollment.NewLocalClient(endpoint, strings.TrimSpace(string(token)), &http.Client{Timeout: 30 * time.Second})
}
