package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntimecmd"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/spf13/cobra"
)

var (
	tunnelHostRuntimeProbe  = probeTunnelHostRuntime
	tunnelHostRuntimeRepair = hostruntimecmd.RepairManagedHost
)

const (
	tunnelHostDiagnosticsPath       = hostruntime.HostDiagnosticsPath
	tunnelHostDiagnosticsSchemaV1   = hostruntime.HostDiagnosticsSchemaV1
	tunnelHostDiagnosticsMaxBytes   = hostruntime.HostDiagnosticsMaxBytes
	tunnelHostDiagnosticsMaxEvents  = hostruntime.HostDiagnosticsMaxEvents
	tunnelHostDiagnosticsMaxMetrics = hostruntime.HostDiagnosticsMaxMetrics
)

var errTunnelHostDiagnosticsUnavailable = errors.New("local host diagnostics unavailable")

type tunnelHostRuntimeDescriptor struct {
	Schema        string `json:"schema"`
	ListenAddress string `json:"listen_address"`
}

type tunnelHostDiagnostics = hostruntime.HostDiagnostics

func productionTunnelClientForCommand(command *cobra.Command) (*api.Client, error) {
	client, err := backendClient(actionContext(command, nil))
	if err != nil {
		return nil, err
	}
	if command == nil || command.Name() != "create" {
		return client, nil
	}
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve Paperboat host state: %w", err)
	}
	store, err := runtimeIdentityStore()
	if err != nil {
		return nil, fmt.Errorf("open Paperboat host identity: %w", err)
	}
	registration, err := store.Registration()
	if err != nil || registration.SetupMode != "host" || registration.InstallationGeneration < 1 {
		return nil, errors.New("durable tunnels require this machine to be enrolled as a Paperboat host; run `pb pair` once, then retry")
	}
	configured, err := configuredTunnelServer(command)
	if err != nil {
		return nil, err
	}
	registered, err := config.NormalizeServerURL(registration.ServerURL)
	if err != nil || registered != configured {
		return nil, errors.New("the enrolled Paperboat host belongs to a different server; select its server or pair this machine again")
	}
	auth, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: registered, StateRoot: stateRoot})
	if err != nil {
		return nil, fmt.Errorf("initialize renewable machine authentication: %w", err)
	}
	if _, err := auth.EnsureInitial(command.Context()); err != nil {
		return nil, fmt.Errorf("authenticate the Paperboat host: %w", err)
	}
	if err := ensureTunnelHostRuntime(command.Context(), stateRoot); err != nil {
		return nil, err
	}
	client.SetSourceMachineID(registration.MachineID)
	client.SetMachineAuth(auth)
	return client, nil
}

func configuredTunnelServer(command *cobra.Command) (string, error) {
	cfg, err := config.Load(configPathFlag(command))
	if err != nil {
		return "", err
	}
	if server, _ := command.Flags().GetString("server"); strings.TrimSpace(server) != "" {
		cfg.ServerURL, err = config.NormalizeServerURL(server)
	} else {
		cfg.ServerURL, err = config.NormalizeServerURL(cfg.ServerURL)
	}
	if err != nil || cfg.ServerURL == "" {
		return "", errors.New("Paperboat server is not configured")
	}
	return cfg.ServerURL, nil
}

func ensureTunnelHostRuntime(ctx context.Context, stateRoot string) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) {
		return errors.New("Paperboat host runtime state is invalid")
	}
	if err := tunnelHostRuntimeProbe(ctx, stateRoot); err == nil {
		return nil
	}
	repairCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := tunnelHostRuntimeRepair(repairCtx); err != nil {
		return fmt.Errorf("repair the Paperboat host service: %w", err)
	}
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := tunnelHostRuntimeProbe(ctx, stateRoot); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Paperboat host service did not become ready after repair")
		case <-ticker.C:
		}
	}
}

func probeTunnelHostRuntime(ctx context.Context, stateRoot string) error {
	body, err := requestTunnelHostRuntime(ctx, stateRoot, "/healthz", 64<<10)
	if err != nil {
		return err
	}
	live, err := decodeTunnelDoctorHealth(bytes.NewReader(body), 64<<10)
	if err != nil || !live {
		return errors.New("Paperboat host health state is unavailable")
	}
	return nil
}

func collectTunnelHostDiagnostics(ctx context.Context) (tunnelHostDiagnostics, error) {
	if ctx == nil {
		return tunnelHostDiagnostics{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return tunnelHostDiagnostics{}, err
	}
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return tunnelHostDiagnostics{}, errTunnelHostDiagnosticsUnavailable
	}
	body, err := requestTunnelHostRuntime(ctx, stateRoot, tunnelHostDiagnosticsPath, tunnelHostDiagnosticsMaxBytes)
	if err != nil {
		return tunnelHostDiagnostics{}, err
	}
	diagnostics, err := decodeTunnelHostDiagnostics(body)
	if err != nil {
		return tunnelHostDiagnostics{}, err
	}
	return diagnostics, nil
}

func requestTunnelHostRuntime(ctx context.Context, stateRoot, endpoint string, maximumBytes int64) ([]byte, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if maximumBytes < 1 || maximumBytes > tunnelHostDiagnosticsMaxBytes || endpoint == "" || !strings.HasPrefix(endpoint, "/") || endpoint != path.Clean(endpoint) || strings.Contains(endpoint, "//") || strings.ContainsAny(endpoint, "?#") {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	local, err := readTunnelHostRuntimeDescriptor(stateRoot)
	if err != nil {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	url, err := tunnelHostRuntimeURL(local.ListenAddress, endpoint)
	if err != nil {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	requestContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, url, nil)
	if err != nil {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	client, err := httptransport.NewLoopbackClient(2 * time.Second)
	if err != nil {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	defer response.Body.Close()
	contentTypes := response.Header.Values("Content-Type")
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || len(contentTypes) != 1 || mediaErr != nil || mediaType != "application/json" {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBytes+1))
	if err != nil || int64(len(body)) > maximumBytes {
		return nil, errTunnelHostDiagnosticsUnavailable
	}
	return body, nil
}

func readTunnelHostRuntimeDescriptor(stateRoot string) (tunnelHostRuntimeDescriptor, error) {
	var local tunnelHostRuntimeDescriptor
	data, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "worker-local.json"), 4096)
	if err != nil {
		return local, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&local) != nil || decoder.Decode(&struct{}{}) != io.EOF || local.Schema != "paperboat.worker-local/v1" {
		return tunnelHostRuntimeDescriptor{}, errors.New("Paperboat host endpoint descriptor is invalid")
	}
	if _, err := tunnelHostRuntimeURL(local.ListenAddress, "/healthz"); err != nil {
		return tunnelHostRuntimeDescriptor{}, err
	}
	return local, nil
}

func tunnelHostRuntimeURL(listenAddress, endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(listenAddress))
	if err != nil || host != "127.0.0.1" && host != "::1" {
		return "", errors.New("Paperboat host endpoint is not literal loopback")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("Paperboat host endpoint port is invalid")
	}
	if endpoint == "" || !strings.HasPrefix(endpoint, "/") || endpoint != path.Clean(endpoint) || strings.Contains(endpoint, "//") || strings.ContainsAny(endpoint, "?#") {
		return "", errors.New("Paperboat host endpoint path is invalid")
	}
	return "http://" + net.JoinHostPort(host, strconv.FormatUint(port, 10)) + endpoint, nil
}

func decodeTunnelHostDiagnostics(body []byte) (tunnelHostDiagnostics, error) {
	if len(body) == 0 || len(body) > tunnelHostDiagnosticsMaxBytes {
		return tunnelHostDiagnostics{}, errTunnelHostDiagnosticsUnavailable
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return tunnelHostDiagnostics{}, errTunnelHostDiagnosticsUnavailable
	}
	var diagnostics tunnelHostDiagnostics
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&diagnostics); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return tunnelHostDiagnostics{}, errTunnelHostDiagnosticsUnavailable
	}
	if diagnostics.Schema != tunnelHostDiagnosticsSchemaV1 || diagnostics.Health.Schema != "" && diagnostics.Health.Schema != health.HealthSchemaV1 || len(diagnostics.Metrics) > tunnelHostDiagnosticsMaxMetrics || len(diagnostics.Events) > tunnelHostDiagnosticsMaxEvents {
		return tunnelHostDiagnostics{}, errTunnelHostDiagnosticsUnavailable
	}
	return diagnostics, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("duplicate-json validator found trailing data")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("diagnostics JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("diagnostics JSON object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("diagnostics JSON object contains duplicate key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("diagnostics JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("diagnostics JSON array is incomplete")
		}
	case '}', ']':
		return errors.New("diagnostics JSON has an unexpected closing delimiter")
	}
	return nil
}
