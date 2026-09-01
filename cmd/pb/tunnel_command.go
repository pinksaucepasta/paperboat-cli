package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/supportbundle"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelcreatejournal"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/spf13/cobra"
)

var tunnelClientForCommand = productionTunnelClientForCommand
var resolveTunnelSelectorForCommand = resolveTunnelSelector
var beginTunnelCreateWorkflowForCommand = beginProductionTunnelCreateWorkflow

var newTunnelIdempotencyKey = func() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "pb_tunnel_" + hex.EncodeToString(value[:]), nil
}

const (
	tunnelOperationWaitDefault     = 2 * time.Minute
	tunnelOperationWaitMaximum     = 10 * time.Minute
	tunnelDoctorBundleMinBytes     = 64 << 10
	tunnelDoctorBundleMaxBytes     = 8 << 20
	tunnelDoctorBundleDefaultBytes = 2 << 20
	tunnelRequestRetryAttempts     = 3
	tunnelRequestRetryBaseDelay    = 100 * time.Millisecond
	tunnelRequestRetryMaximumDelay = 2 * time.Second
)

var tunnelOperationPollInterval = 500 * time.Millisecond

// tunnelRequestRetryDelay is a seam for deterministic command tests. Retries
// are deliberately short and bounded because commands must remain responsive
// while still recovering ordinary transient control-plane failures.
var tunnelRequestRetryDelay = func(attempt int) time.Duration {
	delay := tunnelRequestRetryBaseDelay
	for i := 0; i < attempt; i++ {
		if delay >= tunnelRequestRetryMaximumDelay/2 {
			delay = tunnelRequestRetryMaximumDelay
			break
		}
		delay *= 2
	}
	if delay > tunnelRequestRetryMaximumDelay {
		delay = tunnelRequestRetryMaximumDelay
	}
	// Full jitter avoids synchronized retries when several CLI processes
	// recover from the same control-plane outage.
	var value [8]byte
	if _, err := rand.Read(value[:]); err == nil {
		var random uint64
		for _, b := range value {
			random = random<<8 | uint64(b)
		}
		return time.Duration(random % uint64(delay+1))
	}
	return delay
}

func tunnelRequestRetryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable()
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func retryTunnelRequest(ctx context.Context, request func() error) error {
	if ctx == nil {
		return context.Canceled
	}
	for attempt := 0; attempt < tunnelRequestRetryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := request()
		if err == nil || !tunnelRequestRetryable(err) || attempt == tunnelRequestRetryAttempts-1 {
			return err
		}
		timer := time.NewTimer(tunnelRequestRetryDelay(attempt))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func retryTunnelRead[T any](ctx context.Context, read func() (T, error)) (T, error) {
	var value T
	err := retryTunnelRequest(ctx, func() error {
		var readErr error
		value, readErr = read()
		return readErr
	})
	return value, err
}

var tunnelDoctorLocalReportForCommand = collectTunnelDoctorLocalReport
var tunnelDoctorHostDiagnosticsForCommand = collectTunnelHostDiagnostics
var tunnelDoctorDNSCheckForCommand = func(ctx context.Context) bool {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost")
	return err == nil && len(addresses) > 0
}

type tunnelCreateWorkflow interface {
	Snapshot() tunnelcreatejournal.Journal
	RecordTunnel(context.Context, string, string) error
	RecordConnectorReady(context.Context) error
	RecordDomain(context.Context, int, string) error
	Complete(context.Context) error
	Close() error
}

type tunnelCreateWorkflowRequest struct {
	Name          string
	RequestDigest string
	DomainCount   int
	ExpiresAt     *time.Time
}

func beginProductionTunnelCreateWorkflow(ctx context.Context, request tunnelCreateWorkflowRequest) (tunnelCreateWorkflow, error) {
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return nil, err
	}
	store, err := runtimeIdentityStore()
	if err != nil {
		return nil, err
	}
	registration, err := store.Registration()
	if err != nil || !validTunnelCLIResourceID(registration.MachineID) {
		return nil, errors.Join(tunnelcreatejournal.ErrInvalid, err)
	}
	nameDigest := sha256.Sum256([]byte(request.Name))
	return tunnelcreatejournal.Begin(ctx, tunnelcreatejournal.Config{
		StateRoot:     stateRoot,
		HostID:        registration.MachineID,
		NameDigest:    hex.EncodeToString(nameDigest[:]),
		RequestDigest: request.RequestDigest,
		DomainCount:   request.DomainCount,
		ExpiresAt:     request.ExpiresAt,
		NewKey:        tunnelKey,
	})
}

func collectTunnelDoctorLocalReport(ctx context.Context) (localDoctorReport, error) {
	if ctx == nil {
		return localDoctorReport{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return localDoctorReport{}, err
	}
	report := localDoctorReport{HostRuntime: "unavailable", IdentityState: "unavailable", CredentialState: "unavailable"}
	stateRoot, err := previewRuntimeStateRoot()
	if err != nil {
		return report, nil
	}
	if privateReferenceAvailable(filepath.Join(stateRoot, "machine-identity.json")) && privateReferenceAvailable(filepath.Join(stateRoot, "machine-registration.json")) {
		report.IdentityState = "available"
	}
	if privateReferenceAvailable(filepath.Join(stateRoot, "machine-control.json")) {
		report.CredentialState = "available"
	}
	localBody, err := readOwnerOnlyFile(filepath.Join(stateRoot, "runtime", "worker-local.json"), 4096)
	if err != nil {
		return report, nil
	}
	var local struct {
		Schema        string `json:"schema"`
		ListenAddress string `json:"listen_address"`
	}
	decoder := json.NewDecoder(bytes.NewReader(localBody))
	decoder.DisallowUnknownFields()
	var extra any
	decodeErr := decoder.Decode(&local)
	extraErr := decoder.Decode(&extra)
	host, port, splitErr := net.SplitHostPort(local.ListenAddress)
	address := net.ParseIP(host)
	endpointURL, endpointErr := tunnelHostRuntimeURL(local.ListenAddress, "/healthz")
	if decodeErr != nil || extraErr != io.EOF || local.Schema != "paperboat.worker-local/v1" || splitErr != nil || address == nil || !address.IsLoopback() || port == "" || endpointErr != nil {
		report.HostRuntime = "invalid_local_endpoint"
		return report, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, requestErr := http.NewRequestWithContext(probeCtx, http.MethodGet, endpointURL, nil)
	if requestErr != nil {
		return report, nil
	}
	client, clientErr := httptransport.NewLoopbackClient(2 * time.Second)
	if clientErr != nil {
		return report, nil
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return localDoctorReport{}, contextErr
		}
		return report, nil
	}
	defer response.Body.Close()
	contentTypes := response.Header.Values("Content-Type")
	live, decodeErr := decodeTunnelDoctorHealth(response.Body, 64<<10)
	if response.StatusCode != http.StatusOK || len(contentTypes) != 1 || !strings.EqualFold(strings.TrimSpace(contentTypes[0]), "application/json") || decodeErr != nil || !live {
		report.HostRuntime = "unhealthy"
		return report, nil
	}
	report.HostRuntime = "ready"
	return report, nil
}

func decodeTunnelDoctorHealth(reader io.Reader, maximumBytes int64) (bool, error) {
	if reader == nil || maximumBytes < 1 {
		return false, api.ErrUnsafeTunnelResponse
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if err != nil || int64(len(body)) > maximumBytes {
		return false, api.ErrUnsafeTunnelResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false, api.ErrUnsafeTunnelResponse
	}
	found := false
	live := false
	for decoder.More() {
		nameToken, tokenErr := decoder.Token()
		name, ok := nameToken.(string)
		if tokenErr != nil || !ok || name != "live" || found {
			return false, api.ErrUnsafeTunnelResponse
		}
		if err := decoder.Decode(&live); err != nil {
			return false, api.ErrUnsafeTunnelResponse
		}
		found = true
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || !found {
		return false, api.ErrUnsafeTunnelResponse
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return false, api.ErrUnsafeTunnelResponse
	}
	return live, nil
}

func privateReferenceAvailable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && ownerOnlyRegularFile(path, info)
}

// TunnelOperationOutcomeError preserves the typed terminal operation so
// callers can distinguish a committed failure from a request failure.
type TunnelOperationOutcomeError struct {
	Operation api.TunnelOperation
}

func (e *TunnelOperationOutcomeError) Error() string {
	if e == nil {
		return "tunnel operation failed"
	}
	message := fmt.Sprintf("tunnel operation %s ended in state %s during %s", e.Operation.ID, e.Operation.State, e.Operation.Phase)
	if e.Operation.Error != nil && e.Operation.Error.RepairAction != "" {
		message += "; repair: " + e.Operation.Error.RepairAction
	}
	return message
}

// TunnelOperationWaitTimeoutError reports an observation timeout without
// implying that the already-committed server operation was canceled.
type TunnelOperationWaitTimeoutError struct {
	OperationID string
	Timeout     time.Duration
}

func (e *TunnelOperationWaitTimeoutError) Error() string {
	return fmt.Sprintf("timed out after %s waiting for tunnel operation %s; the operation remains active and can be inspected with `pb tunnel status <tunnel>`", e.Timeout, e.OperationID)
}

// TunnelCreateChangedError means durable tunnel state exists and must not be
// silently recreated or rolled back after a later local/domain step failed.
type TunnelCreateChangedError struct {
	TunnelID        string
	Stage           string
	Outcome         string
	RecoveryCommand string
	Cause           error
}

// TunnelCreateExistingError reports the exact durable tunnel that already
// owns a requested name. A process-restart retry uses a fresh idempotency key,
// so the control plane correctly returns a name conflict instead of silently
// treating an unrelated request as an idempotent replay. The CLI resolves the
// account-scoped resource and gives a safe inspection command without
// attaching this host to it implicitly.
type TunnelCreateExistingError struct {
	TunnelID        string
	Name            string
	RecoveryCommand string
	Cause           error
}

// TunnelSelectorAmbiguousError requires a stable ID when a selector is both
// a tunnel ID and another tunnel's exact name.
type TunnelSelectorAmbiguousError struct{}

func (*TunnelSelectorAmbiguousError) Error() string {
	return "tunnel selector is ambiguous; retry with the stable tunnel ID shown by `pb tunnel list`"
}

type TunnelRouteSelectorAmbiguousError struct{}

func (*TunnelRouteSelectorAmbiguousError) Error() string {
	return "tunnel route selector is ambiguous; retry with the stable route ID shown by `pb tunnel route list`"
}

type TunnelDomainSelectorAmbiguousError struct{}

func (*TunnelDomainSelectorAmbiguousError) Error() string {
	return "tunnel domain selector is ambiguous; retry with the stable domain ID shown by `pb tunnel domain list`"
}

func (e *TunnelCreateExistingError) Error() string {
	if e == nil {
		return "a tunnel with this name already exists"
	}
	message := fmt.Sprintf("tunnel %q already exists as %s; nothing was changed", e.Name, e.TunnelID)
	if e.RecoveryCommand != "" {
		message += "; inspect it with `" + e.RecoveryCommand + "`"
	}
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *TunnelCreateExistingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *TunnelCreateChangedError) Error() string {
	if e == nil {
		return "tunnel creation changed durable state"
	}
	message := fmt.Sprintf("tunnel %s was created, but %s %s; the tunnel was preserved", e.TunnelID, e.Stage, e.Outcome)
	if e.RecoveryCommand != "" {
		message += "; recover with `" + e.RecoveryCommand + "`"
	}
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *TunnelCreateChangedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type tunnelConnectorCreateOutput struct {
	Schema               string     `json:"schema"`
	Kind                 string     `json:"kind"`
	TunnelID             string     `json:"tunnel_id"`
	HostID               string     `json:"host_id"`
	ConnectorID          string     `json:"connector_id"`
	OperationID          string     `json:"operation_id"`
	State                string     `json:"state"`
	CredentialGeneration uint64     `json:"credential_generation"`
	ReadyAt              *time.Time `json:"ready_at,omitempty"`
}

type tunnelCreateDomainOutput struct {
	Domain       api.TunnelDomain          `json:"domain"`
	Operation    api.TunnelOperation       `json:"operation"`
	Instructions api.TunnelDNSInstructions `json:"instructions"`
	Replayed     bool                      `json:"replayed"`
	Changed      bool                      `json:"changed"`
}

type tunnelCreateOutput struct {
	Schema    string                      `json:"schema"`
	Kind      string                      `json:"kind"`
	Tunnel    api.Tunnel                  `json:"tunnel"`
	Operation api.TunnelOperation         `json:"operation"`
	Connector tunnelConnectorCreateOutput `json:"connector"`
	Domains   []tunnelCreateDomainOutput  `json:"domains"`
	Replayed  bool                        `json:"replayed"`
	Changed   bool                        `json:"changed"`
}

func tunnelCobraCommandV1() *cobra.Command {
	root := tunnelCommand("tunnel", "Manage durable tunnels", cobra.NoArgs, nil)
	root.AddCommand(tunnelCreateCommand(), tunnelListCommand(), tunnelShowCommand())
	root.AddCommand(tunnelStatusCommand(), tunnelDoctorCommand(), tunnelLogsCommand())
	for _, action := range []string{"pause", "resume", "delete"} {
		root.AddCommand(tunnelStateCommand(action))
	}
	root.AddCommand(tunnelRouteCommand(), tunnelDomainCommand(), tunnelConnectorCommand())
	root.AddCommand(tunnelCredentialsCommand())
	return root
}

func tunnelStatusCommand() *cobra.Command {
	command := tunnelCommand("status <tunnel>", "Show tunnel health", cobra.ExactArgs(1), runTunnelStatus)
	command.Flags().Bool("watch", false, "watch for health changes")
	command.Flags().Duration("interval", time.Second, "watch polling interval (250ms-1m)")
	tunnelJSONFlag(command)
	return command
}

func runTunnelStatus(command *cobra.Command, args []string) error {
	watch, _ := command.Flags().GetBool("watch")
	interval, _ := command.Flags().GetDuration("interval")
	if interval < 250*time.Millisecond || interval > time.Minute {
		return errors.New("interval must be between 250ms and 1m")
	}
	client, ctx, err := tunnelClient(command)
	if err != nil {
		return err
	}
	tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
	if err != nil {
		return err
	}
	last := ""
	for {
		out, e := retryTunnelRead(ctx, func() (api.TunnelHealth, error) {
			return client.TunnelStatusV1(ctx, tunnelID)
		})
		if e != nil {
			return e
		}
		signatureBytes, marshalErr := json.Marshal(out)
		if marshalErr != nil {
			return fmt.Errorf("encode health update: %w", marshalErr)
		}
		signature := string(signatureBytes)
		if !watch || signature != last {
			if e = tunnelOutput(command, out, fmt.Sprintf("%s\t%s\t%s", out.ResourceID, out.OverallCode, out.Summary)); e != nil {
				return e
			}
			last = signature
		}
		if !watch {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func tunnelDoctorCommand() *cobra.Command {
	command := tunnelCommand("doctor <tunnel>", "Diagnose tunnel health", cobra.ExactArgs(1), runTunnelDoctor)
	command.Flags().String("bundle", "", "absolute path for a local support-bundle preview")
	command.Flags().Bool("write-bundle", false, "write the exact previewed bundle (requires --bundle)")
	command.Flags().Int64("bundle-max-bytes", tunnelDoctorBundleDefaultBytes, "maximum bundle bytes (64KiB-8MiB)")
	tunnelJSONFlag(command)
	return command
}

type tunnelDoctorBundlePreview struct {
	Path       string                 `json:"path"`
	SizeBytes  int64                  `json:"size_bytes"`
	SHA256     string                 `json:"sha256"`
	Redactions int                    `json:"redactions"`
	Manifest   supportbundle.Manifest `json:"manifest"`
}

type tunnelDoctorOutput struct {
	Schema  string                     `json:"schema"`
	Health  api.TunnelHealth           `json:"health"`
	Bundle  *tunnelDoctorBundlePreview `json:"bundle,omitempty"`
	Written *supportbundle.WriteResult `json:"written,omitempty"`
}

type tunnelDoctorEvidence struct {
	Schema string                      `json:"schema"`
	Checks []tunnelDoctorEvidenceCheck `json:"checks"`
}

type tunnelDoctorEvidenceCheck struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Value   string `json:"value,omitempty"`
}

func runTunnelDoctor(command *cobra.Command, args []string) error {
	bundlePath, _ := command.Flags().GetString("bundle")
	writeBundle, _ := command.Flags().GetBool("write-bundle")
	maximumBytes, _ := command.Flags().GetInt64("bundle-max-bytes")
	if writeBundle && bundlePath == "" {
		return errors.New("--write-bundle requires --bundle with an absolute new output path")
	}
	if bundlePath == "" && command.Flags().Changed("bundle-max-bytes") {
		return errors.New("--bundle-max-bytes requires --bundle")
	}
	if bundlePath != "" {
		if maximumBytes < tunnelDoctorBundleMinBytes || maximumBytes > tunnelDoctorBundleMaxBytes {
			return errors.New("bundle-max-bytes must be between 65536 and 8388608")
		}
		if !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
			return errors.New("bundle path must be absolute and clean")
		}
		if err := supportbundle.ValidateOutputPath(bundlePath); err != nil {
			return err
		}
	}

	client, ctx, err := tunnelClient(command)
	if err != nil {
		return err
	}
	tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
	if err != nil {
		return err
	}
	health, err := retryTunnelRead(ctx, func() (api.TunnelHealth, error) {
		return client.TunnelStatusV1(ctx, tunnelID)
	})
	if err != nil {
		return err
	}
	jsonOutput, _ := command.Flags().GetBool("json")
	if bundlePath == "" {
		if jsonOutput {
			return tunnelOutput(command, health, "")
		}
		return writeTunnelDoctorHealth(command.OutOrStdout(), health)
	}

	builder, preview, err := buildTunnelDoctorBundle(ctx, health, maximumBytes)
	if err != nil {
		return err
	}
	bundlePreview := tunnelDoctorBundlePreview{
		Path: bundlePath, SizeBytes: preview.SizeBytes(), SHA256: preview.SHA256(),
		Redactions: preview.Manifest.Redactions, Manifest: preview.Manifest,
	}
	result := tunnelDoctorOutput{Schema: "paperboat.tunnel_doctor.v1", Health: health, Bundle: &bundlePreview}
	if !jsonOutput {
		if err := writeTunnelDoctorHealth(command.OutOrStdout(), health); err != nil {
			return err
		}
		if err := writeTunnelDoctorBundlePreview(command.OutOrStdout(), bundlePreview, writeBundle); err != nil {
			return err
		}
	}
	if writeBundle {
		written, writeErr := builder.Write(ctx, preview, bundlePath)
		if writeErr != nil {
			return writeErr
		}
		result.Written = &written
		if !jsonOutput {
			_, err = fmt.Fprintf(command.OutOrStdout(), "Bundle written: %s\n", written.Path)
			return err
		}
	}
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(result)
	}
	return nil
}

func writeTunnelDoctorHealth(writer io.Writer, health api.TunnelHealth) error {
	if _, err := fmt.Fprintf(writer, "Tunnel %s: %s\n%s\n", health.ResourceID, health.OverallCode, health.Summary); err != nil {
		return err
	}
	for _, dimension := range []struct {
		name  string
		value api.TunnelHealthDimension
	}{{"service", health.Dimensions.Service}, {"edge", health.Dimensions.Edge}, {"config", health.Dimensions.Config}, {"route", health.Dimensions.Route}, {"origin", health.Dimensions.Origin}, {"dns", health.Dimensions.DNS}, {"certificate", health.Dimensions.Certificate}, {"access", health.Dimensions.Access}, {"update", health.Dimensions.Update}} {
		if _, err := fmt.Fprintf(writer, "%-12s %s", dimension.name, dimension.value.Status); err != nil {
			return err
		}
		if dimension.value.Code != "" {
			if _, err := fmt.Fprintf(writer, " (%s)", dimension.value.Code); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	if health.RepairAction != "" {
		_, err := fmt.Fprintf(writer, "Repair: %s\n", health.RepairAction)
		return err
	}
	return nil
}

func writeTunnelDoctorBundlePreview(writer io.Writer, preview tunnelDoctorBundlePreview, writing bool) error {
	lines := []string{
		"Support bundle preview:",
		fmt.Sprintf("Path: %s", preview.Path),
		fmt.Sprintf("Schema: %s", preview.Manifest.SchemaVersion),
		fmt.Sprintf("Format: %s", preview.Manifest.Format),
		fmt.Sprintf("Limits: items=%d item_bytes=%d total_bytes=%d collector_timeout_ms=%d total_timeout_ms=%d", preview.Manifest.Limits.MaxItems, preview.Manifest.Limits.MaxItemBytes, preview.Manifest.Limits.MaxTotalBytes, preview.Manifest.Limits.PerCollectorTimeoutMillis, preview.Manifest.Limits.TotalTimeoutMillis),
		fmt.Sprintf("Items: %d", len(preview.Manifest.Items)),
		fmt.Sprintf("Size: %d bytes", preview.SizeBytes),
		fmt.Sprintf("SHA-256: %s", preview.SHA256),
		fmt.Sprintf("Redactions: %d", preview.Redactions),
		"Collectors:",
	}
	for _, collector := range preview.Manifest.Collectors {
		line := fmt.Sprintf("- %s: %s", collector.Name, collector.Result)
		if collector.ErrorCode != "" {
			line += fmt.Sprintf(" (%s)", collector.ErrorCode)
		}
		lines = append(lines, line)
	}
	lines = append(lines, "Inventory:")
	for _, item := range preview.Manifest.Items {
		lines = append(lines, fmt.Sprintf("- %s: %s, %d bytes, sha256:%s, redactions=%d", item.Path, item.Result, item.SizeBytes, item.SHA256, item.Redactions))
	}
	if writing {
		lines = append(lines, "Explicit write requested; writing the exact previewed bytes.")
	} else {
		lines = append(lines, "No file was written. Review this preview, then add --write-bundle to write it locally.")
	}
	_, err := fmt.Fprintln(writer, strings.Join(lines, "\n"))
	return err
}

func buildTunnelDoctorBundle(ctx context.Context, health api.TunnelHealth, maximumBytes int64) (*supportbundle.Builder, supportbundle.Preview, error) {
	healthBody, err := json.Marshal(health)
	if err != nil {
		return nil, supportbundle.Preview{}, fmt.Errorf("encode tunnel health evidence: %w", err)
	}
	var (
		hostDiagnostics     tunnelHostDiagnostics
		hostDiagnosticsErr  error
		hostDiagnosticsDone bool
	)
	loadHostDiagnostics := func(collectorCtx context.Context) (tunnelHostDiagnostics, error) {
		if !hostDiagnosticsDone {
			hostDiagnostics, hostDiagnosticsErr = tunnelDoctorHostDiagnosticsForCommand(collectorCtx)
			hostDiagnosticsDone = true
		}
		return hostDiagnostics, hostDiagnosticsErr
	}
	collectors := []supportbundle.Collector{
		supportbundle.CollectorFunc{CollectorName: "host_diagnostics", CollectFunc: func(collectorCtx context.Context) ([]supportbundle.CollectedItem, error) {
			diagnostics, collectErr := loadHostDiagnostics(collectorCtx)
			if collectErr != nil {
				if collectorCtx.Err() != nil {
					return nil, collectorCtx.Err()
				}
				// Hostd versions before the typed diagnostics endpoint are a
				// supported installation state. The bundle builder records this
				// bounded collector failure while retaining all other evidence.
				return nil, collectErr
			}
			body, encodeErr := json.Marshal(diagnostics)
			if encodeErr != nil {
				return nil, encodeErr
			}
			return []supportbundle.CollectedItem{{Path: "diagnostics/host-runtime.json", Kind: supportbundle.ItemKindText, Data: append([]byte(nil), body...)}}, nil
		}},
		supportbundle.CollectorFunc{CollectorName: "local_evidence", CollectFunc: func(collectorCtx context.Context) ([]supportbundle.CollectedItem, error) {
			local, collectErr := tunnelDoctorLocalReportForCommand(collectorCtx)
			if collectErr != nil {
				return nil, collectErr
			}
			var diagnostics *tunnelHostDiagnostics
			if value, diagnosticsErr := loadHostDiagnostics(collectorCtx); diagnosticsErr == nil {
				diagnostics = &value
			} else if collectorCtx.Err() != nil {
				return nil, collectorCtx.Err()
			}
			evidence := buildTunnelDoctorEvidenceWithHost(collectorCtx, local, health, diagnostics)
			if err := collectorCtx.Err(); err != nil {
				return nil, err
			}
			evidenceBody, encodeErr := json.Marshal(evidence)
			if encodeErr != nil {
				return nil, encodeErr
			}
			return []supportbundle.CollectedItem{{Path: "diagnostics/local-evidence.json", Kind: supportbundle.ItemKindText, Data: append([]byte(nil), evidenceBody...)}}, nil
		}},
		supportbundle.CollectorFunc{CollectorName: "tunnel_health", CollectFunc: func(context.Context) ([]supportbundle.CollectedItem, error) {
			return []supportbundle.CollectedItem{{Path: "health/tunnel.json", Kind: supportbundle.ItemKindText, Data: append([]byte(nil), healthBody...)}}, nil
		}},
	}
	limits := supportbundle.Defaults()
	limits.MaxItems = 8
	limits.MaxTotalBytes = maximumBytes
	if limits.MaxItemBytes > maximumBytes {
		limits.MaxItemBytes = maximumBytes
	}
	builder, err := supportbundle.New(supportbundle.Config{Limits: limits}, collectors...)
	if err != nil {
		return nil, supportbundle.Preview{}, err
	}
	preview, err := builder.Preview(ctx)
	return builder, preview, err
}

func buildTunnelDoctorEvidenceWithHost(ctx context.Context, local localDoctorReport, tunnelHealth api.TunnelHealth, localDiagnostics *tunnelHostDiagnostics) tunnelDoctorEvidence {
	dnsReady := false
	if ctx != nil && ctx.Err() == nil {
		dnsReady = tunnelDoctorDNSCheckForCommand(ctx)
	}
	runtimeCheck := doctorRuntimeCheck(local.HostRuntime)
	clockCheck := tunnelDoctorUnavailableCheck("clock_sanity", "A trusted server clock comparison is not exposed by the tunnel health contract.")
	transportCheck := tunnelDoctorUnavailableCheck("transport_fallback", "Per-transport fallback evidence is not exposed by the local runtime contract.")
	configurationCheck := tunnelDoctorUnavailableCheck("configuration_generation", "Desired and applied generation numbers are not exposed by the tunnel health response.")
	rollbackCheck := tunnelDoctorUnavailableCheck("rollback_slot", "Detailed rollback-slot evidence is not exposed by the local update contract.")
	if localDiagnostics != nil {
		if localDiagnostics.Health.Schema == health.HealthSchemaV1 {
			runtimeCheck = doctorTypedRuntimeCheck(localDiagnostics.Health)
			clockCheck = doctorTypedClockCheck(localDiagnostics.Health)
		}
		transportCheck = doctorTypedTransportCheck(*localDiagnostics)
		configurationCheck = doctorTypedConfigurationCheck(*localDiagnostics)
		rollbackCheck = doctorTypedRollbackCheck(*localDiagnostics)
	}
	edgeStatus := tunnelHealth.Dimensions.Edge.Status
	originStatus := tunnelHealth.Dimensions.Origin.Status
	routeStatus := tunnelHealth.Dimensions.Route.Status
	dnsStatus := tunnelHealth.Dimensions.DNS.Status
	certificateStatus := tunnelHealth.Dimensions.Certificate.Status
	updateStatus := tunnelHealth.Dimensions.Update.Status
	if localDiagnostics != nil && localDiagnostics.Health.Schema == health.HealthSchemaV1 {
		edgeStatus = doctorLocalDimensionStatus(edgeStatus, localDiagnostics.Health, health.DimensionEdge)
		originStatus = doctorLocalDimensionStatus(originStatus, localDiagnostics.Health, health.DimensionOrigin)
		routeStatus = doctorLocalDimensionStatus(routeStatus, localDiagnostics.Health, health.DimensionRoute)
		dnsStatus = doctorLocalDimensionStatus(dnsStatus, localDiagnostics.Health, health.DimensionDNS)
		certificateStatus = doctorLocalDimensionStatus(certificateStatus, localDiagnostics.Health, health.DimensionCertificate)
		updateStatus = doctorLocalDimensionStatus(updateStatus, localDiagnostics.Health, health.DimensionUpdate)
	}
	checks := []tunnelDoctorEvidenceCheck{
		{Code: "service_installed", Status: "unavailable", Summary: "Native service installation evidence is not available to this user-scoped command."},
		{Code: "service_enabled", Status: "unavailable", Summary: "Native service enablement evidence is not available to this user-scoped command."},
		runtimeCheck,
		{Code: "cli_version", Status: "ready", Summary: "The local CLI version is available.", Value: buildinfo.Version},
		{Code: "daemon_version", Status: "unavailable", Summary: "The daemon version is not exposed by the local health contract."},
		{Code: "connector_version", Status: "unavailable", Summary: "The connector version is not exposed by the local health contract."},
		doctorStateCheck(local.IdentityState),
		doctorCredentialCheck(local.CredentialState),
		clockCheck,
		doctorDNSCheck(dnsReady),
		doctorReportedCheck("edge_reachability", edgeStatus, "Edge reachability is reported by the control plane."),
		transportCheck,
		configurationCheck,
		doctorReportedCheck("origin_connection", originStatus, "Origin connection state is reported by tunnel health."),
		doctorReportedCheck("origin_tls", originStatus, "Origin TLS verification state is reported by tunnel health."),
		doctorReportedCheck("route_state", routeStatus, "Route state is reported by tunnel health."),
		doctorReportedCheck("domain_state", dnsStatus, "Domain and DNS state is reported by tunnel health."),
		doctorReportedCheck("certificate_state", certificateStatus, "Certificate state is reported by tunnel health."),
		doctorReportedCheck("update_health", updateStatus, "Update health is reported by tunnel health."),
		rollbackCheck,
		{Code: "resource_limits", Status: "ready", Summary: "Bounded platform capacity evidence is available.", Value: fmt.Sprintf("%s/%s cpu=%d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())},
	}
	return tunnelDoctorEvidence{Schema: "paperboat.tunnel_doctor_evidence.v1", Checks: checks}
}

func doctorLocalDimensionStatus(remote string, snapshot health.HealthSnapshot, dimension health.Dimension) string {
	if strings.TrimSpace(remote) != "" {
		return remote
	}
	return string(snapshot.Dimensions.Get(dimension).Status)
}

func tunnelDoctorUnavailableCheck(code, summary string) tunnelDoctorEvidenceCheck {
	return tunnelDoctorEvidenceCheck{Code: code, Status: "unavailable", Summary: summary}
}

func doctorTypedRuntimeCheck(snapshot health.HealthSnapshot) tunnelDoctorEvidenceCheck {
	check := tunnelDoctorEvidenceCheck{Code: "service_running", Summary: "The local typed runtime health snapshot is available."}
	check.Value = snapshot.Overall.Code
	switch snapshot.Overall.Status {
	case health.StatusReady, health.StatusNotApplicable:
		check.Status = "ready"
	case health.StatusDegraded, health.StatusUnknown:
		check.Status = "degraded"
	case health.StatusDown:
		check.Status = "degraded"
	default:
		check.Status = "unavailable"
	}
	return check
}

func doctorTypedClockCheck(snapshot health.HealthSnapshot) tunnelDoctorEvidenceCheck {
	if snapshot.UpdatedAt.IsZero() {
		return tunnelDoctorUnavailableCheck("clock_sanity", "The local typed health snapshot has no update timestamp.")
	}
	return tunnelDoctorEvidenceCheck{Code: "clock_sanity", Status: "ready", Summary: "The local typed health snapshot has a valid bounded timestamp.", Value: snapshot.UpdatedAt.UTC().Format(time.RFC3339)}
}

func doctorTypedTransportCheck(diagnostics tunnelHostDiagnostics) tunnelDoctorEvidenceCheck {
	var connected, failed bool
	transports := make([]string, 0, 2)
	for _, series := range diagnostics.Metrics {
		if series.Name != "paperboat_runtime_connector_retries_total" {
			continue
		}
		transport := series.Labels["transport"]
		if transport == "" || transport == "none" {
			continue
		}
		if series.Value > 0 {
			transports = append(transports, transport)
		}
		switch series.Labels["result"] {
		case "connected":
			connected = connected || series.Value > 0
		case "failed":
			failed = failed || series.Value > 0
		}
	}
	if len(transports) == 0 {
		return tunnelDoctorUnavailableCheck("transport_fallback", "The local typed runtime snapshot has no observed connector transport.")
	}
	sort.Strings(transports)
	transports = uniqueStrings(transports)
	check := tunnelDoctorEvidenceCheck{Code: "transport_fallback", Status: "ready", Summary: "The local typed runtime snapshot exposes connector transport activity.", Value: strings.Join(transports, ",")}
	if failed && !connected {
		check.Status = "degraded"
		check.Summary = "The local typed runtime snapshot exposes connector transport failures."
	}
	return check
}

func doctorTypedConfigurationCheck(diagnostics tunnelHostDiagnostics) tunnelDoctorEvidenceCheck {
	var generation uint64
	for _, event := range diagnostics.Events {
		if event.Generations.Config > generation {
			generation = event.Generations.Config
		}
	}
	if generation == 0 {
		return tunnelDoctorUnavailableCheck("configuration_generation", "The local typed runtime snapshot has no observed configuration generation.")
	}
	return tunnelDoctorEvidenceCheck{Code: "configuration_generation", Status: "ready", Summary: "The local typed runtime event log exposes a configuration generation.", Value: strconv.FormatUint(generation, 10)}
}

func doctorTypedRollbackCheck(diagnostics tunnelHostDiagnostics) tunnelDoctorEvidenceCheck {
	for _, series := range diagnostics.Metrics {
		if series.Name != "paperboat_runtime_update_rollbacks_total" {
			continue
		}
		check := tunnelDoctorEvidenceCheck{Code: "rollback_slot", Status: "ready", Summary: "The local typed runtime exposes update rollback evidence.", Value: strconv.FormatFloat(series.Value, 'f', -1, 64)}
		if series.Value > 0 {
			check.Status = "degraded"
			check.Summary = "The local typed runtime recorded one or more update rollbacks."
		}
		return check
	}
	return tunnelDoctorUnavailableCheck("rollback_slot", "The local typed runtime snapshot has no update rollback evidence.")
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func doctorRuntimeCheck(state string) tunnelDoctorEvidenceCheck {
	switch state {
	case "ready":
		return tunnelDoctorEvidenceCheck{Code: "service_running", Status: "ready", Summary: "The local runtime health endpoint is ready."}
	case "unhealthy", "invalid_local_endpoint":
		return tunnelDoctorEvidenceCheck{Code: "service_running", Status: "degraded", Summary: "The local runtime health endpoint is not ready."}
	default:
		return tunnelDoctorEvidenceCheck{Code: "service_running", Status: "unavailable", Summary: "The local runtime health endpoint is unavailable."}
	}
}

func doctorStateCheck(state string) tunnelDoctorEvidenceCheck {
	if state == "valid" || state == "available" {
		return tunnelDoctorEvidenceCheck{Code: "local_state_integrity", Status: "ready", Summary: "Private local identity and registration references are available; their contents were not collected."}
	}
	return tunnelDoctorEvidenceCheck{Code: "local_state_integrity", Status: "unavailable", Summary: "Local identity integrity evidence is unavailable."}
}

func doctorCredentialCheck(state string) tunnelDoctorEvidenceCheck {
	switch state {
	case "valid", "available":
		return tunnelDoctorEvidenceCheck{Code: "credential_availability", Status: "ready", Summary: "A private credential reference is available; credential material was not read."}
	case "grace":
		return tunnelDoctorEvidenceCheck{Code: "credential_availability", Status: "degraded", Summary: "Credential authority is in its renewal grace period; credential material was not read."}
	default:
		return tunnelDoctorEvidenceCheck{Code: "credential_availability", Status: "unavailable", Summary: "Usable credential authority is unavailable; credential material was not read."}
	}
}

func doctorDNSCheck(ready bool) tunnelDoctorEvidenceCheck {
	if ready {
		return tunnelDoctorEvidenceCheck{Code: "dns_sanity", Status: "ready", Summary: "The local resolver can resolve the loopback host name."}
	}
	return tunnelDoctorEvidenceCheck{Code: "dns_sanity", Status: "unavailable", Summary: "The local resolver could not resolve the loopback host name."}
}

func doctorReportedCheck(code, status, summary string) tunnelDoctorEvidenceCheck {
	switch status {
	case "ready", "healthy":
		status = "ready"
	case "degraded", "down", "unknown", "not_applicable":
	default:
		status = "unavailable"
	}
	return tunnelDoctorEvidenceCheck{Code: code, Status: status, Summary: summary}
}

func tunnelLogsCommand() *cobra.Command {
	command := tunnelCommand("logs <tunnel>", "Show tunnel logs", cobra.ExactArgs(1), runTunnelLogs)
	command.Flags().String("cursor", "", "continue after a log cursor")
	command.Flags().Int("limit", 100, "maximum entries per request (1-200)")
	command.Flags().Bool("follow", false, "wait for new log entries")
	command.Flags().Duration("interval", time.Second, "follow polling interval (250ms-1m)")
	tunnelJSONFlag(command)
	return command
}

func runTunnelLogs(command *cobra.Command, args []string) error {
	cursor, _ := command.Flags().GetString("cursor")
	limit, _ := command.Flags().GetInt("limit")
	follow, _ := command.Flags().GetBool("follow")
	interval, _ := command.Flags().GetDuration("interval")
	if limit < 1 || limit > 200 {
		return errors.New("limit must be between 1 and 200")
	}
	if interval < 250*time.Millisecond || interval > time.Minute {
		return errors.New("interval must be between 250ms and 1m")
	}
	if len(cursor) > 4096 || strings.ContainsAny(cursor, "\x00\r\n") {
		return errors.New("cursor is invalid")
	}
	client, ctx, err := tunnelClient(command)
	if err != nil {
		return err
	}
	tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
	if err != nil {
		return err
	}
	for {
		page, requestErr := retryTunnelRead(ctx, func() (api.TunnelLogPage, error) {
			return client.ListTunnelLogsV1(ctx, tunnelID, cursor, limit)
		})
		if requestErr != nil {
			return requestErr
		}
		if err := writeTunnelLogs(command, page, follow); err != nil {
			return err
		}
		previousCursor := cursor
		if page.NextCursor != "" {
			cursor = page.NextCursor
		} else if len(page.Items) > 0 {
			cursor = page.Items[len(page.Items)-1].Cursor
		}
		if !follow {
			return nil
		}
		if cursor != "" && cursor == previousCursor && len(page.Items) > 0 {
			return api.ErrUnsafeTunnelResponse
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func writeTunnelLogs(command *cobra.Command, page api.TunnelLogPage, follow bool) error {
	jsonOutput, _ := command.Flags().GetBool("json")
	writer := command.OutOrStdout()
	if jsonOutput && !follow {
		return json.NewEncoder(writer).Encode(page)
	}
	encoder := json.NewEncoder(writer)
	for _, entry := range page.Items {
		if jsonOutput {
			if err := encoder.Encode(entry); err != nil {
				return err
			}
			continue
		}
		message := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(entry.Message)
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", entry.OccurredAt.UTC().Format(time.RFC3339), entry.Level, entry.Component, entry.Code, message); err != nil {
			return err
		}
	}
	return nil
}

func tunnelCommand(use, short string, args cobra.PositionalArgs, run func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: func(command *cobra.Command, values []string) error {
		if err := commandArgs(args)(command, values); err != nil {
			return err
		}
		for _, value := range values {
			if value == "" || value != strings.TrimSpace(value) || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n/\\") {
				return errors.New("resource argument is invalid")
			}
		}
		return nil
	}, RunE: run, SilenceUsage: true, SilenceErrors: true}
}
func tunnelJSONFlag(command *cobra.Command) {
	command.Flags().Bool("json", false, "print canonical JSON")
}
func tunnelOutput(command *cobra.Command, value any, human string) error {
	jsonOutput, _ := command.Flags().GetBool("json")
	if !jsonOutput {
		_, err := fmt.Fprintln(command.OutOrStdout(), human)
		return err
	}
	encoder := json.NewEncoder(command.OutOrStdout())
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}
func tunnelClient(command *cobra.Command) (*api.Client, context.Context, error) {
	client, err := tunnelClientForCommand(command)
	return client, command.Context(), err
}
func tunnelKey() (string, error) {
	key, err := newTunnelIdempotencyKey()
	if err != nil {
		return "", fmt.Errorf("create idempotency key: %w", err)
	}
	return key, nil
}

func tunnelMutationWaitFlags(command *cobra.Command) {
	command.Flags().Bool("wait", false, "wait for the operation to reach a terminal state")
	command.Flags().Duration("timeout", tunnelOperationWaitDefault, "maximum time to wait for operation completion")
	command.PreRunE = func(command *cobra.Command, _ []string) error {
		wantWait, _ := command.Flags().GetBool("wait")
		if !wantWait {
			return nil
		}
		timeout, _ := command.Flags().GetDuration("timeout")
		if timeout < time.Second || timeout > tunnelOperationWaitMaximum {
			return fmt.Errorf("timeout must be between 1s and %s", tunnelOperationWaitMaximum)
		}
		return nil
	}
}

func waitForTunnelOperation(command *cobra.Command, client *api.Client, initial api.TunnelOperation) (api.TunnelOperation, error) {
	wantWait, _ := command.Flags().GetBool("wait")
	if !wantWait {
		switch initial.State {
		case "pending", "running", "succeeded":
			return initial, nil
		case "failed", "canceled":
			return api.TunnelOperation{}, &TunnelOperationOutcomeError{Operation: initial}
		default:
			return api.TunnelOperation{}, api.ErrUnsafeTunnelResponse
		}
	}
	timeout, _ := command.Flags().GetDuration("timeout")
	if timeout < time.Second || timeout > tunnelOperationWaitMaximum {
		return api.TunnelOperation{}, fmt.Errorf("timeout must be between 1s and %s", tunnelOperationWaitMaximum)
	}
	if client == nil {
		return api.TunnelOperation{}, errors.New("tunnel operation client is unavailable")
	}
	current := initial
	deadlineContext, cancel := context.WithTimeout(command.Context(), timeout)
	defer cancel()
	for {
		switch current.State {
		case "succeeded":
			return current, nil
		case "failed", "canceled":
			return api.TunnelOperation{}, &TunnelOperationOutcomeError{Operation: current}
		case "pending", "running":
		default:
			return api.TunnelOperation{}, api.ErrUnsafeTunnelResponse
		}
		timer := time.NewTimer(tunnelOperationPollInterval)
		select {
		case <-command.Context().Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return api.TunnelOperation{}, command.Context().Err()
		case <-deadlineContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return api.TunnelOperation{}, &TunnelOperationWaitTimeoutError{OperationID: initial.ID, Timeout: timeout}
		case <-timer.C:
		}
		next, err := retryTunnelRead(deadlineContext, func() (api.TunnelOperation, error) {
			return client.GetTunnelOperationV1(deadlineContext, initial.ID)
		})
		if err != nil {
			var apiError *api.APIError
			var networkError net.Error
			if errors.As(err, &apiError) && apiError.Retryable() || errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			if errors.Is(err, context.DeadlineExceeded) && command.Context().Err() == nil {
				return api.TunnelOperation{}, &TunnelOperationWaitTimeoutError{OperationID: initial.ID, Timeout: timeout}
			}
			return api.TunnelOperation{}, err
		}
		if next.ID != initial.ID || next.ResourceKind != initial.ResourceKind || next.ResourceID != initial.ResourceID {
			return api.TunnelOperation{}, api.ErrUnsafeTunnelResponse
		}
		current = next
	}
}

func tunnelOperationHuman(operation api.TunnelOperation) string {
	if operation.State == "succeeded" {
		return "ready"
	}
	return fmt.Sprintf("%s (%s, operation %s)", operation.Phase, operation.State, operation.ID)
}

func activateCreatedTunnelConnector(command *cobra.Command, tunnelID string) (tunnelConnectorCreateOutput, error) {
	if tunnelConnectorAddRuntime == nil {
		return tunnelConnectorCreateOutput{}, ErrTunnelConnectorAddRequiresRuntime
	}
	var output bytes.Buffer
	runtimeCommand := &cobra.Command{}
	runtimeCommand.SetContext(command.Context())
	runtimeCommand.SetOut(&output)
	runtimeCommand.SetErr(command.ErrOrStderr())
	runtimeCommand.Flags().Bool("json", true, "")
	if err := tunnelConnectorAddRuntime(runtimeCommand, tunnelID); err != nil {
		return tunnelConnectorCreateOutput{}, err
	}
	var projection tunnelenrollment.Projection
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&projection) != nil || decoder.Decode(&struct{}{}) != io.EOF || projection.Schema != tunnelenrollment.Schema || projection.Kind != "tunnel_connector" || projection.TunnelID != tunnelID || !validTunnelCLIResourceID(projection.HostID) || !validTunnelCLIResourceID(projection.ConnectorID) || !validTunnelCLIResourceID(projection.OperationID) || projection.State != "ready" || projection.CredentialGeneration == 0 || projection.ReadyAt == nil || projection.ReadyAt.IsZero() {
		return tunnelConnectorCreateOutput{}, api.ErrUnsafeTunnelResponse
	}
	return tunnelConnectorCreateOutput{Schema: projection.Schema, Kind: projection.Kind, TunnelID: projection.TunnelID, HostID: projection.HostID, ConnectorID: projection.ConnectorID, OperationID: projection.OperationID, State: projection.State, CredentialGeneration: projection.CredentialGeneration, ReadyAt: projection.ReadyAt}, nil
}

// resumeCreatedTunnelConnector reconstructs the stable connector projection
// from the control plane after a process crash. The local enrollment endpoint
// is intentionally not called again: an already-recorded ready stage means a
// second enrollment could create a duplicate host attachment.
func resumeCreatedTunnelConnector(ctx context.Context, client *api.Client, journal tunnelcreatejournal.Journal) (tunnelConnectorCreateOutput, error) {
	if ctx == nil || client == nil || !validTunnelCLIResourceID(journal.TunnelID) || !validTunnelCLIResourceID(journal.HostID) {
		return tunnelConnectorCreateOutput{}, api.ErrUnsafeTunnelResponse
	}
	var matches []api.TunnelConnector
	cursor := ""
	seen := map[string]struct{}{cursor: {}}
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := retryTunnelRead(ctx, func() (api.TunnelConnectorPage, error) {
			return client.ListTunnelConnectorsV1(ctx, journal.TunnelID, cursor, 200)
		})
		if err != nil {
			return tunnelConnectorCreateOutput{}, err
		}
		for _, connector := range page.Items {
			if connector.TunnelID != journal.TunnelID || connector.HostID != journal.HostID || connector.DesiredState != "active" || connector.ReadyAt == nil || connector.ReadyAt.IsZero() || connector.RotationGeneration <= 0 || connector.CredentialReference == "" {
				continue
			}
			matches = append(matches, connector)
		}
		if page.NextCursor == "" {
			break
		}
		if _, exists := seen[page.NextCursor]; exists {
			return tunnelConnectorCreateOutput{}, api.ErrUnsafeTunnelResponse
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	if len(matches) != 1 || !validTunnelCLIResourceID(journal.OperationID) {
		if len(matches) > 1 {
			return tunnelConnectorCreateOutput{}, api.ErrUnsafeTunnelResponse
		}
		return tunnelConnectorCreateOutput{}, tunnelenrollment.ErrUnavailable
	}
	connector := matches[0]
	return tunnelConnectorCreateOutput{
		Schema:               tunnelenrollment.Schema,
		Kind:                 "tunnel_connector",
		TunnelID:             connector.TunnelID,
		HostID:               connector.HostID,
		ConnectorID:          connector.ID,
		OperationID:          journal.OperationID,
		State:                "ready",
		CredentialGeneration: uint64(connector.RotationGeneration),
		ReadyAt:              connector.ReadyAt,
	}, nil
}

func validTunnelCLIResourceID(value string) bool {
	return len(value) >= 3 && len(value) <= 128 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n\t /\\?#%")
}

func tunnelCreateConnectorError(tunnelID string, err error) error {
	outcome := "failed"
	if errors.Is(err, tunnelenrollment.ErrUnavailable) || errors.Is(err, tunnelenrollment.ErrActivation) || errors.Is(err, context.DeadlineExceeded) {
		outcome = "has an uncertain outcome"
	}
	return &TunnelCreateChangedError{TunnelID: tunnelID, Stage: "connector activation", Outcome: outcome, RecoveryCommand: "pb tunnel connector add " + tunnelID, Cause: err}
}

func tunnelCreateDomainError(tunnelID, hostname, routeID, stage string, err error) error {
	return &TunnelCreateChangedError{TunnelID: tunnelID, Stage: "custom domain " + hostname + " " + stage, Outcome: "failed", RecoveryCommand: fmt.Sprintf("pb tunnel domain add %s %s --route %s", tunnelID, hostname, routeID), Cause: err}
}

func tunnelCreateJournalError(tunnelID, stage, recovery string, err error) error {
	return &TunnelCreateChangedError{
		TunnelID:        tunnelID,
		Stage:           stage,
		Outcome:         "has an uncertain outcome",
		RecoveryCommand: recovery,
		Cause:           err,
	}
}

func tunnelCreateHumanOutput(result tunnelCreateOutput, origin string) string {
	verb := "Created"
	if result.Replayed {
		verb = "Resumed"
	}
	var output strings.Builder
	fmt.Fprintf(&output, "%s tunnel %s (%s)\n", verb, result.Tunnel.Name, result.Tunnel.ID)
	fmt.Fprintf(&output, "Connector %s is ready\n", result.Connector.ConnectorID)
	fmt.Fprintf(&output, "%s -> %s\n", result.Tunnel.StableEndpoint, origin)
	fmt.Fprintf(&output, "Status: %s", tunnelOperationHuman(result.Operation))
	for _, domain := range result.Domains {
		fmt.Fprintf(&output, "\nDNS for %s:", domain.Domain.Hostname)
		for _, record := range domain.Instructions.Records {
			fmt.Fprintf(&output, "\n%s\t%s\t%s\t%d", record.Name, record.Type, record.Value, record.TTL)
		}
		if domain.Instructions.Note != "" {
			fmt.Fprintf(&output, "\n%s", domain.Instructions.Note)
		}
	}
	return output.String()
}

func tunnelCreateCommand() *cobra.Command {
	command := tunnelCommand("create <name>", "Create a durable tunnel", cobra.ExactArgs(1), func(command *cobra.Command, args []string) (runErr error) {
		name := args[0]
		if !validTunnelCLIName(name, 63) {
			return errors.New("name must be 1-63 ASCII letters, digits, '.', '_' or '-' and cannot start with punctuation")
		}
		origin, _ := command.Flags().GetString("from")
		port, _ := command.Flags().GetInt("port")
		if (origin == "") == (port == 0) {
			return errors.New("exactly one of --port or --from is required")
		}
		if port != 0 {
			if port < 1 || port > 65535 {
				return errors.New("port must be between 1 and 65535")
			}
			origin = fmt.Sprintf("http://127.0.0.1:%d", port)
		}
		private, _ := command.Flags().GetBool("private")
		expiry, _ := command.Flags().GetDuration("duration")
		if command.Flags().Changed("duration") && expiry <= 0 {
			return errors.New("duration must be greater than zero")
		}
		scheme, address, err := splitTunnelOrigin(origin)
		if err != nil {
			return err
		}
		mode := "public"
		if private {
			mode = "private"
		}
		var expires *time.Time
		if expiry > 0 {
			value := time.Now().UTC().Add(expiry)
			expires = &value
		}
		domains, _ := command.Flags().GetStringSlice("domain")
		seenDomains := make(map[string]struct{}, len(domains))
		for i, hostname := range domains {
			hostname = strings.ToLower(strings.TrimSpace(hostname))
			if !validTunnelCLIHostname(hostname) {
				return fmt.Errorf("custom domain %q is invalid", hostname)
			}
			if _, exists := seenDomains[hostname]; exists {
				return fmt.Errorf("custom domain %q was repeated", hostname)
			}
			seenDomains[hostname] = struct{}{}
			domains[i] = hostname
		}
		sort.Strings(domains)
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		requestDigest, err := tunnelCreateRequestDigest(name, mode, scheme, address, expiry, domains)
		if err != nil {
			return err
		}
		workflow, err := beginTunnelCreateWorkflowForCommand(ctx, tunnelCreateWorkflowRequest{Name: name, RequestDigest: requestDigest, DomainCount: len(domains), ExpiresAt: expires})
		if err != nil {
			return fmt.Errorf("begin tunnel create recovery workflow: %w", err)
		}
		defer func() {
			if closeErr := workflow.Close(); closeErr != nil {
				if runErr == nil {
					runErr = closeErr
				} else {
					runErr = errors.Join(runErr, closeErr)
				}
			}
		}()
		journal := workflow.Snapshot()
		hadTunnel := journal.TunnelID != ""
		expires = journal.ExpiresAt
		out, err := retryTunnelRead(ctx, func() (api.TunnelMutation, error) {
			return client.CreateTunnelV1(ctx, api.TunnelCreateInput{Name: name, AccessMode: mode, Origin: api.TunnelOriginInput{Scheme: scheme, Address: address}, ExpiresAt: expires}, journal.TunnelKey)
		})
		if err != nil {
			var apiErr *api.APIError
			if !hadTunnel && errors.As(err, &apiErr) && apiErr.Code == "tunnel_name_conflict" {
				existing, lookupErr := findTunnelByExactName(ctx, client, name)
				if lookupErr == nil {
					if completeErr := workflow.Complete(ctx); completeErr != nil {
						return completeErr
					}
					return &TunnelCreateExistingError{TunnelID: existing.ID, Name: existing.Name, RecoveryCommand: "pb tunnel show " + existing.ID, Cause: err}
				}
			}
			return err
		}
		if hadTunnel && (!out.Replayed || out.Tunnel.ID != journal.TunnelID || out.Operation.ID != journal.OperationID) {
			return api.ErrUnsafeTunnelResponse
		}
		if out.Tunnel.Name != name {
			return api.ErrUnsafeTunnelResponse
		}
		if err := workflow.RecordTunnel(ctx, out.Tunnel.ID, out.Operation.ID); err != nil {
			return tunnelCreateJournalError(out.Tunnel.ID, "recording tunnel creation", "pb tunnel show "+out.Tunnel.ID, err)
		}
		journal = workflow.Snapshot()
		var connector tunnelConnectorCreateOutput
		if journal.Stage == tunnelcreatejournal.StageConnectorReady || journal.Stage == tunnelcreatejournal.StageDomainsReady {
			connector, err = resumeCreatedTunnelConnector(ctx, client, journal)
			if err != nil {
				return tunnelCreateConnectorError(out.Tunnel.ID, err)
			}
		} else {
			connector, err = activateCreatedTunnelConnector(command, out.Tunnel.ID)
			if err != nil {
				return tunnelCreateConnectorError(out.Tunnel.ID, err)
			}
			if err := workflow.RecordConnectorReady(ctx); err != nil {
				return tunnelCreateJournalError(out.Tunnel.ID, "recording connector readiness", "pb tunnel connector add "+out.Tunnel.ID, err)
			}
		}
		out.Operation, err = waitForTunnelOperation(command, client, out.Operation)
		if err != nil {
			return tunnelCreateJournalError(out.Tunnel.ID, "tunnel readiness", "pb tunnel status "+out.Tunnel.ID, err)
		}
		result := tunnelCreateOutput{Schema: api.TunnelV1Schema, Kind: "tunnel_create", Tunnel: out.Tunnel, Operation: out.Operation, Connector: connector, Domains: make([]tunnelCreateDomainOutput, 0, len(domains)), Replayed: out.Replayed, Changed: out.Changed}
		if len(domains) > 0 {
			routes, listErr := retryTunnelRead(ctx, func() (api.TunnelRoutePage, error) {
				return client.ListTunnelRoutesV1(ctx, out.Tunnel.ID, "", 1)
			})
			if listErr != nil || len(routes.Items) != 1 {
				if listErr == nil {
					listErr = errors.New("initial route was not returned")
				}
				return tunnelCreateDomainError(out.Tunnel.ID, strings.Join(domains, ","), "default", "route resolution", listErr)
			}
			journal = workflow.Snapshot()
			for index, hostname := range domains {
				domainState := journal.Domains[index]
				domain, domainErr := retryTunnelRead(ctx, func() (api.TunnelDomainMutation, error) {
					return client.CreateTunnelDomainV1(ctx, out.Tunnel.ID, domainState.Key, api.TunnelDomainInput{Hostname: hostname, RouteID: routes.Items[0].ID, Provider: "generic"})
				})
				if domainErr != nil {
					return tunnelCreateDomainError(out.Tunnel.ID, hostname, routes.Items[0].ID, "addition", domainErr)
				}
				if domainState.ID != "" && (!domain.Replayed || domain.Domain.ID != domainState.ID) {
					return api.ErrUnsafeTunnelResponse
				}
				if domain.Domain.TunnelID != out.Tunnel.ID || domain.Domain.RouteID != routes.Items[0].ID || domain.Domain.Hostname != hostname {
					return api.ErrUnsafeTunnelResponse
				}
				if err := workflow.RecordDomain(ctx, index, domain.Domain.ID); err != nil {
					return tunnelCreateJournalError(out.Tunnel.ID, "recording custom domain "+hostname, fmt.Sprintf("pb tunnel domain add %s %s --route %s", out.Tunnel.ID, hostname, routes.Items[0].ID), err)
				}
				domain.Operation, domainErr = waitForTunnelOperation(command, client, domain.Operation)
				if domainErr != nil {
					return tunnelCreateDomainError(out.Tunnel.ID, hostname, routes.Items[0].ID, "readiness wait", domainErr)
				}
				instructions, instructionsErr := retryTunnelRead(ctx, func() (api.TunnelDNSInstructions, error) {
					return client.TunnelDomainInstructionsV1(ctx, out.Tunnel.ID, domain.Domain.ID)
				})
				if instructionsErr != nil {
					return &TunnelCreateChangedError{TunnelID: out.Tunnel.ID, Stage: "DNS instructions for custom domain " + hostname, Outcome: "could not be read", RecoveryCommand: fmt.Sprintf("pb tunnel domain instructions %s %s", out.Tunnel.ID, hostname), Cause: instructionsErr}
				}
				result.Domains = append(result.Domains, tunnelCreateDomainOutput{Domain: domain.Domain, Operation: domain.Operation, Instructions: instructions, Replayed: domain.Replayed, Changed: domain.Changed})
			}
		}
		if err := tunnelOutput(command, result, tunnelCreateHumanOutput(result, origin)); err != nil {
			return err
		}
		if err := workflow.Complete(ctx); err != nil {
			return tunnelCreateJournalError(out.Tunnel.ID, "cleaning up the local create journal", "pb tunnel status "+out.Tunnel.ID, err)
		}
		return nil
	})
	command.Flags().Int("port", 0, "local TCP port")
	command.Flags().String("from", "", "origin URL (http, https, h2c, or unix)")
	command.Flags().StringSlice("domain", nil, "custom domain to add after creation")
	command.Flags().Bool("private", false, "require authenticated private access")
	command.Flags().Duration("duration", 0, "optional tunnel lifetime")
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func tunnelCreateRequestDigest(name, mode, scheme, address string, duration time.Duration, domains []string) (string, error) {
	request := struct {
		Schema        string   `json:"schema"`
		Name          string   `json:"name"`
		AccessMode    string   `json:"access_mode"`
		OriginScheme  string   `json:"origin_scheme"`
		OriginAddress string   `json:"origin_address"`
		DurationNanos int64    `json:"duration_nanos"`
		Domains       []string `json:"domains"`
	}{"paperboat.tunnel-create-request/v1", name, mode, scheme, address, int64(duration), append([]string(nil), domains...)}
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func findTunnelByExactName(ctx context.Context, client *api.Client, name string) (api.Tunnel, error) {
	if ctx == nil || client == nil || name == "" {
		return api.Tunnel{}, api.ErrUnsafeTunnelResponse
	}
	cursor := ""
	seen := make(map[string]struct{})
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := retryTunnelRead(ctx, func() (api.TunnelPage, error) {
			return client.ListTunnelsV1(ctx, cursor, 200)
		})
		if err != nil {
			return api.Tunnel{}, err
		}
		for _, tunnel := range page.Items {
			if tunnel.Name == name {
				return tunnel, nil
			}
		}
		if page.NextCursor == "" {
			break
		}
		if _, exists := seen[page.NextCursor]; exists {
			return api.Tunnel{}, api.ErrUnsafeTunnelResponse
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	return api.Tunnel{}, api.ErrUnsafeTunnelResponse
}

func resolveTunnelSelector(ctx context.Context, client *api.Client, value string) (string, error) {
	if ctx == nil || client == nil || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
		!validTunnelCLIName(value, 63) && !validTunnelCLIResourceID(value) {
		return "", api.ErrUnsafeTunnelResponse
	}
	canonicalID := ""
	if strings.HasPrefix(value, "tun_") && validTunnelCLIResourceID(value) {
		tunnel, err := retryTunnelRead(ctx, func() (api.Tunnel, error) {
			return client.GetTunnelV1(ctx, value)
		})
		switch {
		case err == nil:
			if tunnel.ID != value {
				return "", api.ErrUnsafeTunnelResponse
			}
			canonicalID = tunnel.ID
		case api.IsNotFound(err):
		default:
			return "", err
		}
	}
	cursor := ""
	seen := map[string]struct{}{cursor: {}}
	matches := make(map[string]struct{})
	if canonicalID != "" {
		matches[canonicalID] = struct{}{}
	}
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := retryTunnelRead(ctx, func() (api.TunnelPage, error) {
			return client.ListTunnelsV1(ctx, cursor, 200)
		})
		if err != nil {
			return "", err
		}
		for _, tunnel := range page.Items {
			if tunnel.ID == value || tunnel.Name == value {
				matches[tunnel.ID] = struct{}{}
				if len(matches) > 1 {
					return "", &TunnelSelectorAmbiguousError{}
				}
			}
		}
		if page.NextCursor == "" {
			if len(matches) == 1 {
				for id := range matches {
					return id, nil
				}
			}
			return "", errors.New("tunnel was not found")
		}
		if _, exists := seen[page.NextCursor]; exists {
			return "", api.ErrUnsafeTunnelResponse
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	return "", api.ErrUnsafeTunnelResponse
}

func splitTunnelOrigin(value string) (string, string, error) {
	return splitTunnelCLIOrigin(value, false)
}

func splitTunnelRouteOrigin(value string) (string, string, error) {
	return splitTunnelCLIOrigin(value, true)
}

func splitTunnelCLIOrigin(value string, allowTCP bool) (string, string, error) {
	value = strings.TrimSpace(value)
	at := strings.Index(value, "://")
	if at < 1 || at == len(value)-3 {
		return "", "", errors.New("origin must include a scheme and address")
	}
	scheme := value[:at]
	if scheme != "http" && scheme != "https" && scheme != "h2c" && scheme != "unix" && (!allowTCP || scheme != "tcp") {
		if allowTCP {
			return "", "", errors.New("origin scheme must be http, https, h2c, unix, or tcp")
		}
		return "", "", errors.New("origin scheme must be http, https, h2c, or unix")
	}
	address := value[at+3:]
	if address != strings.TrimSpace(address) || len(address) > 512 || strings.ContainsAny(address, "\x00\r\n\t@?#") {
		return "", "", errors.New("origin address is invalid")
	}
	if scheme == "unix" {
		if !strings.HasPrefix(address, "/") || path.Clean(address) != address {
			return "", "", errors.New("Unix origin must be a clean absolute path")
		}
	} else {
		host, portText, splitErr := net.SplitHostPort(address)
		port, portErr := strconv.Atoi(portText)
		if splitErr != nil || !validTunnelCLIOriginHost(host) || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
			return "", "", errors.New("origin must contain a canonical host and port")
		}
	}
	return scheme, address, nil
}

func validTunnelCLIName(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || value[0] == '.' || value[0] == '_' || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validTunnelCLIHostname(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n\t /?#@:") {
		return false
	}
	value = strings.TrimPrefix(value, "*.")
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validTunnelCLIOriginHost(value string) bool {
	if net.ParseIP(value) != nil || strings.EqualFold(value, "localhost") {
		return true
	}
	if len(value) < 1 || len(value) > 253 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n\t /?#@:") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func tunnelRouteOriginFlags(command *cobra.Command, preserveDefault bool) {
	command.Flags().Bool("preserve-host", preserveDefault, "preserve the incoming Host header")
	command.Flags().String("host-header", "", "override the origin Host header")
	command.Flags().Bool("clear-host-header", false, "remove the origin Host override")
	command.Flags().String("tls-verification", "", "origin TLS verification (system, custom_ca, or insecure_development)")
	command.Flags().String("tls-server-name", "", "explicit origin TLS server name")
	command.Flags().Bool("clear-tls-server-name", false, "remove the explicit origin TLS server name")
	command.Flags().String("ca-reference", "", "protected custom CA reference")
	command.Flags().Bool("clear-ca-reference", false, "remove the custom CA reference")
	command.Flags().String("client-credential-reference", "", "protected origin mTLS credential reference")
	command.Flags().Bool("clear-client-credential-reference", false, "remove the origin mTLS credential reference")
}

func tunnelRouteOriginFlagsChanged(command *cobra.Command) bool {
	for _, name := range []string{"preserve-host", "host-header", "clear-host-header", "tls-verification", "tls-server-name", "clear-tls-server-name", "ca-reference", "clear-ca-reference", "client-credential-reference", "clear-client-credential-reference"} {
		if command.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func applyTunnelRouteOriginFlags(command *cobra.Command, origin api.TunnelRouteOrigin) (api.TunnelRouteOrigin, error) {
	if command.Flags().Changed("preserve-host") {
		origin.PreserveHost, _ = command.Flags().GetBool("preserve-host")
	}
	hostHeader, _ := command.Flags().GetString("host-header")
	clearHostHeader, _ := command.Flags().GetBool("clear-host-header")
	if command.Flags().Changed("host-header") && clearHostHeader {
		return api.TunnelRouteOrigin{}, errors.New("--host-header and --clear-host-header cannot be combined")
	}
	if command.Flags().Changed("host-header") {
		if !validTunnelCLIOriginHost(hostHeader) {
			return api.TunnelRouteOrigin{}, errors.New("host-header is invalid")
		}
		origin.HostOverride = &hostHeader
	} else if clearHostHeader {
		origin.HostOverride = nil
	}
	if origin.Scheme != "https" {
		for _, name := range []string{"tls-verification", "tls-server-name", "clear-tls-server-name", "ca-reference", "clear-ca-reference", "client-credential-reference", "clear-client-credential-reference"} {
			if command.Flags().Changed(name) {
				return api.TunnelRouteOrigin{}, errors.New("origin TLS flags require an https:// origin")
			}
		}
		origin.TLS = nil
		return origin, nil
	}
	if origin.TLS == nil {
		origin.TLS = &api.TunnelRouteTLS{Verification: "system"}
	}
	tls := *origin.TLS
	if command.Flags().Changed("tls-verification") {
		tls.Verification, _ = command.Flags().GetString("tls-verification")
		if tls.Verification != "system" && tls.Verification != "custom_ca" && tls.Verification != "insecure_development" {
			return api.TunnelRouteOrigin{}, errors.New("tls-verification must be system, custom_ca, or insecure_development")
		}
	}
	serverName, _ := command.Flags().GetString("tls-server-name")
	clearServerName, _ := command.Flags().GetBool("clear-tls-server-name")
	if command.Flags().Changed("tls-server-name") && clearServerName {
		return api.TunnelRouteOrigin{}, errors.New("--tls-server-name and --clear-tls-server-name cannot be combined")
	}
	if command.Flags().Changed("tls-server-name") {
		if !validTunnelCLIOriginHost(serverName) {
			return api.TunnelRouteOrigin{}, errors.New("tls-server-name is invalid")
		}
		tls.ServerName = &serverName
	} else if clearServerName {
		tls.ServerName = nil
	}
	caReference, _ := command.Flags().GetString("ca-reference")
	clearCA, _ := command.Flags().GetBool("clear-ca-reference")
	if command.Flags().Changed("ca-reference") && clearCA {
		return api.TunnelRouteOrigin{}, errors.New("--ca-reference and --clear-ca-reference cannot be combined")
	}
	if command.Flags().Changed("ca-reference") {
		if strings.TrimSpace(caReference) == "" {
			return api.TunnelRouteOrigin{}, errors.New("ca-reference is invalid")
		}
		tls.CAReference = &caReference
		tls.Verification = "custom_ca"
	} else if clearCA {
		tls.CAReference = nil
		if tls.Verification == "custom_ca" {
			tls.Verification = "system"
		}
	}
	clientReference, _ := command.Flags().GetString("client-credential-reference")
	clearClient, _ := command.Flags().GetBool("clear-client-credential-reference")
	if command.Flags().Changed("client-credential-reference") && clearClient {
		return api.TunnelRouteOrigin{}, errors.New("--client-credential-reference and --clear-client-credential-reference cannot be combined")
	}
	if command.Flags().Changed("client-credential-reference") {
		if strings.TrimSpace(clientReference) == "" {
			return api.TunnelRouteOrigin{}, errors.New("client-credential-reference is invalid")
		}
		tls.ClientCredentialReference = &clientReference
	} else if clearClient {
		tls.ClientCredentialReference = nil
	}
	if tls.Verification != "custom_ca" && tls.CAReference != nil {
		return api.TunnelRouteOrigin{}, errors.New("ca-reference requires custom_ca TLS verification")
	}
	if tls.Verification == "custom_ca" && tls.CAReference == nil {
		return api.TunnelRouteOrigin{}, errors.New("custom_ca TLS verification requires --ca-reference")
	}
	origin.TLS = &tls
	return origin, nil
}

func tunnelListCommand() *cobra.Command {
	command := tunnelCommand("list", "List durable tunnels", cobra.NoArgs, func(command *cobra.Command, _ []string) error {
		cursor, _ := command.Flags().GetString("cursor")
		limit, _ := command.Flags().GetInt("limit")
		if limit < 1 || limit > 200 {
			return errors.New("limit must be between 1 and 200")
		}
		if len(cursor) > 4096 || strings.ContainsAny(cursor, "\x00\r\n") {
			return errors.New("cursor is invalid")
		}
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		out, err := retryTunnelRead(ctx, func() (api.TunnelPage, error) {
			return client.ListTunnelsV1(ctx, cursor, limit)
		})
		if err != nil {
			return err
		}
		if jsonOut, _ := command.Flags().GetBool("json"); jsonOut {
			return tunnelOutput(command, out, "")
		}
		for _, v := range out.Items {
			if _, err := fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\t%s\n", v.ID, v.Name, v.AccessMode, v.DesiredState); err != nil {
				return err
			}
		}
		return nil
	})
	command.Flags().String("cursor", "", "continue a previous page")
	command.Flags().Int("limit", 100, "maximum results (1-200)")
	tunnelJSONFlag(command)
	return command
}
func tunnelShowCommand() *cobra.Command {
	command := tunnelCommand("show <tunnel>", "Show a durable tunnel", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
		if err != nil {
			return err
		}
		out, err := retryTunnelRead(ctx, func() (api.Tunnel, error) {
			return client.GetTunnelV1(ctx, tunnelID)
		})
		if err != nil {
			return err
		}
		return tunnelOutput(command, out, fmt.Sprintf("%s\t%s\t%s\t%s", out.ID, out.Name, out.AccessMode, out.DesiredState))
	})
	tunnelJSONFlag(command)
	return command
}
func tunnelStateCommand(action string) *cobra.Command {
	short := strings.ToUpper(action[:1]) + action[1:] + " a durable tunnel"
	if action == "pause" {
		short = "Pause new traffic while preserving tunnel identity and configuration"
	}
	if action == "resume" {
		short = "Resume new traffic for a preserved tunnel"
	}
	if action == "delete" {
		short = "Delete endpoints and routes and revoke connectors while preserving user DNS records"
	}
	command := tunnelCommand(action+" <tunnel>", short, cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		if action == "delete" {
			yes, _ := command.Flags().GetBool("yes")
			if !yes {
				return errors.New("tunnel deletion revokes connector credentials and removes Paperboat endpoints, routes, and domain bindings; user-owned DNS records and audit history are preserved; pass --yes to confirm")
			}
		}
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
		if err != nil {
			return err
		}
		current, err := retryTunnelRead(ctx, func() (api.Tunnel, error) {
			return client.GetTunnelV1(ctx, tunnelID)
		})
		if err != nil {
			return err
		}
		key, err := tunnelKey()
		if err != nil {
			return err
		}
		out, err := retryTunnelRead(ctx, func() (api.TunnelMutation, error) {
			return client.ChangeTunnelStateV1(ctx, tunnelID, action, current.ETag, key)
		})
		if err != nil {
			return err
		}
		out.Operation, err = waitForTunnelOperation(command, client, out.Operation)
		if err != nil {
			return err
		}
		return tunnelOutput(command, out, fmt.Sprintf("%s tunnel %s; status: %s", tunnelActionPastTense(action), out.Tunnel.ID, tunnelOperationHuman(out.Operation)))
	})
	if action == "delete" {
		command.Flags().Bool("yes", false, "confirm endpoint, route, domain-binding, and connector-credential removal")
	}
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func tunnelActionPastTense(action string) string {
	switch action {
	case "pause":
		return "Paused"
	case "resume":
		return "Resumed"
	case "delete":
		return "Deleted"
	case "remove":
		return "Removed"
	case "verify":
		return "Verified"
	case "drain":
		return "Drained"
	case "revoke":
		return "Revoked"
	default:
		return action
	}
}

func tunnelRouteCommand() *cobra.Command {
	root := tunnelCommand("route", "Manage tunnel routes", cobra.NoArgs, nil)
	root.AddCommand(routeListCommand(), routeAddCommand(), routeUpdateCommand(), routeRemoveCommand())
	return root
}
func routeListCommand() *cobra.Command {
	command := tunnelCommand("list <tunnel>", "List tunnel routes", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		cursor, limit, e := tunnelPageFlags(command)
		if e != nil {
			return e
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelRoutePage, error) {
			return c.ListTunnelRoutesV1(ctx, tunnelID, cursor, limit)
		})
		if e != nil {
			return e
		}
		if jsonOutput, _ := command.Flags().GetBool("json"); jsonOutput {
			return tunnelOutput(command, out, "")
		}
		for _, route := range out.Items {
			match := route.HostMatch.Type
			if route.HostMatch.Hostname != "" {
				match = route.HostMatch.Hostname
			}
			if route.PathPrefix != nil {
				match += *route.PathPrefix
			}
			if _, err := fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\t%s\t%s://%s\t%s\n", route.ID, route.Name, route.Protocol, match, route.Origin.Scheme, route.Origin.Address, route.DesiredState); err != nil {
				return err
			}
		}
		return nil
	})
	tunnelPageFlag(command)
	tunnelJSONFlag(command)
	return command
}
func routeAddCommand() *cobra.Command {
	command := tunnelCommand("add <tunnel>", "Add a tunnel route", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		name, _ := command.Flags().GetString("name")
		protocol, _ := command.Flags().GetString("protocol")
		host, _ := command.Flags().GetString("domain")
		origin, _ := command.Flags().GetString("to")
		scheme, address, e := splitTunnelRouteOrigin(origin)
		if e != nil {
			return e
		}
		if !validTunnelCLIName(name, 80) {
			return errors.New("route name is invalid")
		}
		if protocol != "http" && protocol != "tcp_private" {
			return errors.New("protocol must be http or tcp_private")
		}
		pathPrefix, _ := command.Flags().GetString("path")
		var pathValue *string
		if pathPrefix != "" {
			var pathErr error
			pathPrefix, pathErr = normalizeTunnelCLIPathPrefix(pathPrefix)
			if pathErr != nil {
				return pathErr
			}
			pathValue = &pathPrefix
		}
		priority, _ := command.Flags().GetInt32("priority")
		connectTimeout, _ := command.Flags().GetDuration("connect-timeout")
		idleTimeout, _ := command.Flags().GetDuration("idle-timeout")
		maxStreams, _ := command.Flags().GetInt32("max-streams")
		if priority < 0 || priority > 1000000 {
			return errors.New("priority must be between 0 and 1000000")
		}
		if connectTimeout < 100*time.Millisecond || connectTimeout > 120*time.Second {
			return errors.New("connect-timeout must be between 100ms and 2m")
		}
		if idleTimeout < time.Second || idleTimeout > time.Hour {
			return errors.New("idle-timeout must be between 1s and 1h")
		}
		if maxStreams < 1 || maxStreams > 10000 {
			return errors.New("max-streams must be between 1 and 10000")
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		hostMatch := api.TunnelRouteHostMatch{Type: "catch_all"}
		if host != "" {
			if !validTunnelCLIHostname(host) {
				return errors.New("domain is invalid")
			}
			hostMatch = api.TunnelRouteHostMatch{Type: "exact", Hostname: strings.ToLower(host)}
			if strings.HasPrefix(host, "*.") {
				one := 1
				hostMatch = api.TunnelRouteHostMatch{Type: "one_label_wildcard", Hostname: strings.ToLower(host), WildcardLabels: &one}
			}
		}
		if protocol == "tcp_private" && (host != "" || pathValue != nil || scheme != "tcp") {
			return errors.New("tcp_private routes require tcp:// origin without domain or path matching")
		}
		if protocol == "http" && scheme == "tcp" {
			return errors.New("HTTP routes cannot target a tcp origin")
		}
		preserveHost, _ := command.Flags().GetBool("preserve-host")
		originValue := api.TunnelRouteOrigin{Scheme: scheme, Address: address, PreserveHost: preserveHost}
		if scheme == "https" {
			originValue.TLS = &api.TunnelRouteTLS{Verification: "system"}
		}
		originValue, e = applyTunnelRouteOriginFlags(command, originValue)
		if e != nil {
			return e
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelRouteMutation, error) {
			return c.CreateTunnelRouteV1(ctx, tunnelID, key, api.TunnelRouteInput{Name: name, Protocol: protocol, HostMatch: hostMatch, PathPrefix: pathValue, Origin: originValue, Priority: priority, ConnectTimeoutMS: int32(connectTimeout / time.Millisecond), IdleTimeoutMS: int32(idleTimeout / time.Millisecond), MaxConcurrentStreams: maxStreams})
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		return tunnelOutput(command, out, fmt.Sprintf("Created route %s; status: %s", out.Route.ID, tunnelOperationHuman(out.Operation)))
	})
	for _, flag := range []string{"name", "to"} {
		command.Flags().String(flag, "", flag)
		_ = command.MarkFlagRequired(flag)
	}
	command.Flags().String("domain", "", "exact hostname or one-label wildcard match")
	command.Flags().String("path", "", "HTTP path prefix, optionally ending in *")
	command.Flags().String("protocol", "http", "route protocol (http or tcp_private)")
	tunnelRouteOriginFlags(command, true)
	command.Flags().Int32("priority", 0, "route priority")
	command.Flags().Duration("connect-timeout", 10*time.Second, "origin connect timeout")
	command.Flags().Duration("idle-timeout", 5*time.Minute, "stream idle timeout")
	command.Flags().Int32("max-streams", 128, "maximum concurrent streams")
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}
func routeUpdateCommand() *cobra.Command {
	command := tunnelCommand("update <tunnel> <route>", "Update a tunnel route", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		var patch api.TunnelRoutePatch
		changed := false
		originTargetChanged := false
		var requestedOriginScheme, requestedOriginAddress string
		if command.Flags().Changed("name") {
			v, _ := command.Flags().GetString("name")
			if !validTunnelCLIName(v, 80) {
				return errors.New("route name is invalid")
			}
			patch.Name = &v
			changed = true
		}
		if command.Flags().Changed("to") {
			v, _ := command.Flags().GetString("to")
			scheme, address, err := splitTunnelRouteOrigin(v)
			if err != nil {
				return err
			}
			requestedOriginScheme, requestedOriginAddress = scheme, address
			originTargetChanged = true
			changed = true
		}
		if command.Flags().Changed("protocol") {
			v, _ := command.Flags().GetString("protocol")
			if v != "http" && v != "tcp_private" {
				return errors.New("protocol must be http or tcp_private")
			}
			patch.Protocol = &v
			changed = true
		}
		if command.Flags().Changed("domain") {
			v, _ := command.Flags().GetString("domain")
			match := api.TunnelRouteHostMatch{Type: "catch_all"}
			if v != "" {
				if !validTunnelCLIHostname(v) {
					return errors.New("domain is invalid")
				}
				match = api.TunnelRouteHostMatch{Type: "exact", Hostname: strings.ToLower(v)}
				if strings.HasPrefix(v, "*.") {
					one := 1
					match = api.TunnelRouteHostMatch{Type: "one_label_wildcard", Hostname: strings.ToLower(v), WildcardLabels: &one}
				}
			}
			patch.HostMatch = &match
			changed = true
		}
		if command.Flags().Changed("path") {
			v, _ := command.Flags().GetString("path")
			var pathErr error
			v, pathErr = normalizeTunnelCLIPathPrefix(v)
			if pathErr != nil {
				return pathErr
			}
			patch.PathPrefix = &v
			patch.PathPrefixSet = true
			changed = true
		}
		clearPath, _ := command.Flags().GetBool("clear-path")
		if clearPath {
			if command.Flags().Changed("path") {
				return errors.New("--path and --clear-path cannot be combined")
			}
			patch.PathPrefix = nil
			patch.PathPrefixSet = true
			changed = true
		}
		if command.Flags().Changed("priority") {
			v, _ := command.Flags().GetInt32("priority")
			if v < 0 || v > 1000000 {
				return errors.New("priority must be between 0 and 1000000")
			}
			patch.Priority = &v
			changed = true
		}
		if command.Flags().Changed("connect-timeout") {
			v, _ := command.Flags().GetDuration("connect-timeout")
			if v < 100*time.Millisecond || v > 120*time.Second {
				return errors.New("connect-timeout must be between 100ms and 2m")
			}
			ms := int32(v / time.Millisecond)
			patch.ConnectTimeoutMS = &ms
			changed = true
		}
		if command.Flags().Changed("idle-timeout") {
			v, _ := command.Flags().GetDuration("idle-timeout")
			if v < time.Second || v > time.Hour {
				return errors.New("idle-timeout must be between 1s and 1h")
			}
			ms := int32(v / time.Millisecond)
			patch.IdleTimeoutMS = &ms
			changed = true
		}
		if command.Flags().Changed("max-streams") {
			v, _ := command.Flags().GetInt32("max-streams")
			if v < 1 || v > 10000 {
				return errors.New("max-streams must be between 1 and 10000")
			}
			patch.MaxConcurrentStreams = &v
			changed = true
		}
		enable, _ := command.Flags().GetBool("enable")
		disable, _ := command.Flags().GetBool("disable")
		if enable && disable {
			return errors.New("--enable and --disable cannot be combined")
		}
		if enable || disable {
			state := "active"
			if disable {
				state = "disabled"
			}
			patch.DesiredState = &state
			changed = true
		}
		if tunnelRouteOriginFlagsChanged(command) {
			changed = true
		}
		if !changed {
			return errors.New("at least one update flag is required")
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		current, e := resolveTunnelRoute(ctx, c, tunnelID, args[1])
		if e != nil {
			return e
		}
		if originTargetChanged || tunnelRouteOriginFlagsChanged(command) {
			origin := current.Origin
			if originTargetChanged {
				origin.Scheme, origin.Address = requestedOriginScheme, requestedOriginAddress
			}
			origin, e = applyTunnelRouteOriginFlags(command, origin)
			if e != nil {
				return e
			}
			patch.Origin = &origin
		}
		effectiveProtocol, effectiveOrigin, effectiveMatch, effectivePath := current.Protocol, current.Origin, current.HostMatch, current.PathPrefix
		if patch.Protocol != nil {
			effectiveProtocol = *patch.Protocol
		}
		if patch.Origin != nil {
			effectiveOrigin = *patch.Origin
		}
		if patch.HostMatch != nil {
			effectiveMatch = *patch.HostMatch
		}
		if patch.PathPrefix != nil {
			effectivePath = patch.PathPrefix
		} else if patch.PathPrefixSet {
			effectivePath = nil
		}
		if effectiveProtocol == "tcp_private" && (effectiveOrigin.Scheme != "tcp" || effectiveMatch.Type != "catch_all" || effectivePath != nil) {
			return errors.New("tcp_private routes require tcp:// origin without domain or path matching")
		}
		if effectiveProtocol == "http" && effectiveOrigin.Scheme == "tcp" {
			return errors.New("HTTP routes cannot target a tcp origin")
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelRouteMutation, error) {
			return c.PatchTunnelRouteV1(ctx, tunnelID, current.ID, current.ETag, key, patch)
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		return tunnelOutput(command, out, fmt.Sprintf("Updated route %s; status: %s", out.Route.ID, tunnelOperationHuman(out.Operation)))
	})
	command.Flags().String("name", "", "new route name")
	command.Flags().String("to", "", "new origin URL")
	command.Flags().String("protocol", "", "new route protocol (http or tcp_private)")
	command.Flags().String("domain", "", "new exact hostname, wildcard, or empty catch-all")
	command.Flags().String("path", "", "new HTTP path prefix")
	command.Flags().Bool("clear-path", false, "remove the HTTP path prefix")
	command.Flags().Int32("priority", 0, "new route priority")
	command.Flags().Duration("connect-timeout", 0, "new origin connect timeout")
	command.Flags().Duration("idle-timeout", 0, "new stream idle timeout")
	command.Flags().Int32("max-streams", 0, "new maximum concurrent streams")
	command.Flags().Bool("enable", false, "enable the route")
	command.Flags().Bool("disable", false, "disable the route")
	tunnelRouteOriginFlags(command, true)
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}
func routeRemoveCommand() *cobra.Command {
	command := tunnelCommand("remove <tunnel> <route>", "Remove a tunnel route", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		yes, _ := command.Flags().GetBool("yes")
		if !yes {
			return errors.New("route removal stops matching traffic but preserves the tunnel, domains, and connectors; pass --yes to confirm")
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		current, e := resolveTunnelRoute(ctx, c, tunnelID, args[1])
		if e != nil {
			return e
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelRouteMutation, error) {
			return c.DeleteTunnelRouteV1(ctx, tunnelID, current.ID, current.ETag, key)
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		return tunnelOutput(command, out, fmt.Sprintf("Removed route %s; tunnel and connector are preserved; status: %s", out.Route.ID, tunnelOperationHuman(out.Operation)))
	})
	command.Flags().Bool("yes", false, "confirm route removal while preserving the tunnel")
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func tunnelDomainCommand() *cobra.Command {
	root := tunnelCommand("domain", "Manage tunnel domains", cobra.NoArgs, nil)
	root.AddCommand(domainListCommand(), domainAddCommand(), domainInstructionsCommand())
	for _, a := range []string{"remove", "verify"} {
		root.AddCommand(domainMutationCommand(a))
	}
	return root
}

func domainInstructionsCommand() *cobra.Command {
	command := tunnelCommand("instructions <tunnel> <domain>", "Show authoritative DNS instructions for a tunnel domain", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
		if err != nil {
			return err
		}
		domain, err := resolveTunnelDomain(ctx, client, tunnelID, args[1])
		if err != nil {
			return err
		}
		instructions, err := retryTunnelRead(ctx, func() (api.TunnelDNSInstructions, error) {
			return client.TunnelDomainInstructionsV1(ctx, tunnelID, domain.ID)
		})
		if err != nil {
			return err
		}
		if jsonOutput, _ := command.Flags().GetBool("json"); jsonOutput {
			return tunnelOutput(command, instructions, "")
		}
		writer := command.OutOrStdout()
		for _, record := range instructions.Records {
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%d\n", record.Name, record.Type, record.Value, record.TTL); err != nil {
				return err
			}
		}
		if instructions.Note != "" {
			if _, err := fmt.Fprintln(writer, instructions.Note); err != nil {
				return err
			}
		}
		return nil
	})
	tunnelJSONFlag(command)
	return command
}
func domainListCommand() *cobra.Command {
	command := tunnelCommand("list <tunnel>", "List tunnel domains", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		cursor, limit, e := tunnelPageFlags(command)
		if e != nil {
			return e
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelDomainPage, error) {
			return c.ListTunnelDomainsV1(ctx, tunnelID, cursor, limit)
		})
		if e != nil {
			return e
		}
		if jsonOutput, _ := command.Flags().GetBool("json"); jsonOutput {
			return tunnelOutput(command, out, "")
		}
		for _, domain := range out.Items {
			if _, err := fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\t%s\n", domain.ID, domain.Hostname, domain.State, domain.Certificate.State); err != nil {
				return err
			}
		}
		return nil
	})
	tunnelPageFlag(command)
	tunnelJSONFlag(command)
	return command
}
func domainAddCommand() *cobra.Command {
	command := tunnelCommand("add <tunnel> <hostname>", "Add a tunnel domain", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		host := strings.ToLower(args[1])
		route, _ := command.Flags().GetString("route")
		provider, _ := command.Flags().GetString("provider")
		if !validTunnelCLIHostname(host) {
			return errors.New("domain hostname is invalid")
		}
		if provider == "" || len(provider) > 64 || strings.ContainsAny(provider, "\x00\r\n") {
			return errors.New("DNS provider is invalid")
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		resolvedRoute, e := resolveTunnelRoute(ctx, c, tunnelID, route)
		if e != nil {
			return e
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelDomainMutation, error) {
			return c.CreateTunnelDomainV1(ctx, tunnelID, key, api.TunnelDomainInput{Hostname: host, RouteID: resolvedRoute.ID, Provider: provider})
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		return tunnelOutput(command, out, fmt.Sprintf("Added domain %s; status: %s", out.Domain.ID, tunnelOperationHuman(out.Operation)))
	})
	for _, f := range []string{"route"} {
		command.Flags().String(f, "", f)
		_ = command.MarkFlagRequired(f)
	}
	command.Flags().String("provider", "generic", "DNS provider")
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func resolveTunnelRoute(ctx context.Context, client *api.Client, tunnel, value string) (api.TunnelRoute, error) {
	if ctx == nil || client == nil || strings.TrimSpace(tunnel) == "" || strings.TrimSpace(value) == "" || tunnel != strings.TrimSpace(tunnel) || value != strings.TrimSpace(value) {
		return api.TunnelRoute{}, api.ErrUnsafeTunnelResponse
	}
	cursor := ""
	seen := map[string]struct{}{cursor: {}}
	matches := make(map[string]api.TunnelRoute)
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := retryTunnelRead(ctx, func() (api.TunnelRoutePage, error) {
			return client.ListTunnelRoutesV1(ctx, tunnel, cursor, 200)
		})
		if err != nil {
			return api.TunnelRoute{}, err
		}
		for _, route := range page.Items {
			if route.ID == value || route.Name == value {
				matches[route.ID] = route
				if len(matches) > 1 {
					return api.TunnelRoute{}, &TunnelRouteSelectorAmbiguousError{}
				}
			}
		}
		if page.NextCursor == "" {
			if len(matches) == 1 {
				for _, route := range matches {
					return route, nil
				}
			}
			return api.TunnelRoute{}, errors.New("tunnel route was not found")
		}
		if _, exists := seen[page.NextCursor]; exists {
			return api.TunnelRoute{}, api.ErrUnsafeTunnelResponse
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	return api.TunnelRoute{}, api.ErrUnsafeTunnelResponse
}

func domainMutationCommand(action string) *cobra.Command {
	command := tunnelCommand(action+" <tunnel> <domain>", strings.ToUpper(action[:1])+action[1:]+" a tunnel domain", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		if action == "remove" {
			yes, _ := command.Flags().GetBool("yes")
			if !yes {
				return errors.New("domain removal deletes the Paperboat binding but preserves user-owned DNS records; pass --yes to confirm")
			}
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		current, e := resolveTunnelDomain(ctx, c, tunnelID, args[1])
		if e != nil {
			return e
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		apiAction := action
		if apiAction == "remove" {
			apiAction = "delete"
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelDomainMutation, error) {
			return c.MutateTunnelDomainV1(ctx, tunnelID, current.ID, apiAction, current.ETag, key)
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		human := fmt.Sprintf("%s domain %s; status: %s", tunnelActionPastTense(action), out.Domain.ID, tunnelOperationHuman(out.Operation))
		if action == "remove" {
			human = fmt.Sprintf("Removed domain %s; user-owned DNS records are preserved; status: %s", out.Domain.ID, tunnelOperationHuman(out.Operation))
		}
		return tunnelOutput(command, out, human)
	})
	if action == "remove" {
		command.Flags().Bool("yes", false, "confirm domain-binding removal while preserving user-owned DNS")
	}
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func resolveTunnelDomain(ctx context.Context, client *api.Client, tunnel, value string) (api.TunnelDomain, error) {
	if ctx == nil || client == nil || strings.TrimSpace(tunnel) == "" || strings.TrimSpace(value) == "" || tunnel != strings.TrimSpace(tunnel) || value != strings.TrimSpace(value) {
		return api.TunnelDomain{}, api.ErrUnsafeTunnelResponse
	}
	cursor := ""
	seen := map[string]struct{}{cursor: {}}
	matches := make(map[string]api.TunnelDomain)
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := retryTunnelRead(ctx, func() (api.TunnelDomainPage, error) {
			return client.ListTunnelDomainsV1(ctx, tunnel, cursor, 200)
		})
		if err != nil {
			return api.TunnelDomain{}, err
		}
		for _, domain := range page.Items {
			if domain.ID == value || strings.EqualFold(domain.Hostname, value) {
				matches[domain.ID] = domain
				if len(matches) > 1 {
					return api.TunnelDomain{}, &TunnelDomainSelectorAmbiguousError{}
				}
			}
		}
		if page.NextCursor == "" {
			if len(matches) == 1 {
				for _, domain := range matches {
					return domain, nil
				}
			}
			return api.TunnelDomain{}, errors.New("tunnel domain was not found")
		}
		if _, exists := seen[page.NextCursor]; exists {
			return api.TunnelDomain{}, api.ErrUnsafeTunnelResponse
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	return api.TunnelDomain{}, api.ErrUnsafeTunnelResponse
}

func tunnelConnectorCommand() *cobra.Command {
	root := tunnelCommand("connector", "Manage tunnel connectors", cobra.NoArgs, nil)
	root.AddCommand(connectorListCommand(), connectorAddCommand())
	for _, a := range []string{"drain", "revoke"} {
		root.AddCommand(connectorMutationCommand(a))
	}
	return root
}

var ErrTunnelConnectorAddRequiresRuntime = errors.New("connector add requires the installed Paperboat runtime")

// tunnelConnectorAddRuntime is installed by the stable-runtime integration.
// The CLI surface never consumes or prints enrollment tokens itself.
var tunnelConnectorAddRuntime = runProductionTunnelConnectorAdd

func connectorAddCommand() *cobra.Command {
	command := tunnelCommand("add <tunnel>", "Add a connector on this host", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		if tunnelConnectorAddRuntime == nil {
			return ErrTunnelConnectorAddRequiresRuntime
		}
		client, ctx, err := tunnelClient(command)
		if err != nil {
			return err
		}
		tunnelID, err := resolveTunnelSelectorForCommand(ctx, client, args[0])
		if err != nil {
			return err
		}
		return tunnelConnectorAddRuntime(command, tunnelID)
	})
	tunnelJSONFlag(command)
	return command
}
func connectorListCommand() *cobra.Command {
	command := tunnelCommand("list <tunnel>", "List tunnel connectors", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		cursor, limit, e := tunnelPageFlags(command)
		if e != nil {
			return e
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelConnectorPage, error) {
			return c.ListTunnelConnectorsV1(ctx, tunnelID, cursor, limit)
		})
		if e != nil {
			return e
		}
		if jsonOutput, _ := command.Flags().GetBool("json"); jsonOutput {
			return tunnelOutput(command, out, "")
		}
		for _, connector := range out.Items {
			lastHeartbeat := "never"
			if connector.LastHeartbeatAt != nil {
				lastHeartbeat = connector.LastHeartbeatAt.UTC().Format(time.RFC3339)
			}
			if _, err := fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", connector.ID, connector.HostID, connector.DesiredState, connector.DrainState, lastHeartbeat); err != nil {
				return err
			}
		}
		return nil
	})
	tunnelPageFlag(command)
	tunnelJSONFlag(command)
	return command
}
func connectorMutationCommand(action string) *cobra.Command {
	command := tunnelCommand(action+" <tunnel> <connector>", strings.ToUpper(action[:1])+action[1:]+" a tunnel connector", cobra.ExactArgs(2), func(command *cobra.Command, args []string) error {
		if action == "revoke" {
			yes, _ := command.Flags().GetBool("yes")
			if !yes {
				return errors.New("connector revocation permanently disables this host attachment but preserves the tunnel, routes, domains, and other connectors; pass --yes to confirm")
			}
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		current, e := retryTunnelRead(ctx, func() (api.TunnelConnector, error) {
			return c.GetTunnelConnectorV1(ctx, tunnelID, args[1])
		})
		if e != nil {
			return e
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelConnectorMutation, error) {
			return c.MutateTunnelConnectorV1(ctx, tunnelID, args[1], action, current.ETag, key)
		})
		if e != nil {
			return e
		}
		out.Operation, e = waitForTunnelOperation(command, c, out.Operation)
		if e != nil {
			return e
		}
		human := fmt.Sprintf("%s connector %s; tunnel identity is preserved; status: %s", tunnelActionPastTense(action), out.Connector.ID, tunnelOperationHuman(out.Operation))
		return tunnelOutput(command, out, human)
	})
	if action == "revoke" {
		command.Flags().Bool("yes", false, "confirm permanent connector revocation")
	}
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}
func tunnelCredentialsCommand() *cobra.Command {
	root := tunnelCommand("credentials", "Manage tunnel credentials", cobra.NoArgs, nil)
	root.AddCommand(credentialsRotateCommand())
	return root
}
func credentialsRotateCommand() *cobra.Command {
	command := tunnelCommand("rotate <tunnel>", "Rotate tunnel connector credentials", cobra.ExactArgs(1), func(command *cobra.Command, args []string) error {
		yes, _ := command.Flags().GetBool("yes")
		if !yes {
			return errors.New("credential rotation replaces connector credentials while preserving tunnel identity, routes, and domains; pass --yes to confirm")
		}
		c, ctx, e := tunnelClient(command)
		if e != nil {
			return e
		}
		tunnelID, e := resolveTunnelSelectorForCommand(ctx, c, args[0])
		if e != nil {
			return e
		}
		current, e := retryTunnelRead(ctx, func() (api.Tunnel, error) {
			return c.GetTunnelV1(ctx, tunnelID)
		})
		if e != nil {
			return e
		}
		key, e := tunnelKey()
		if e != nil {
			return e
		}
		out, e := retryTunnelRead(ctx, func() (api.TunnelOperation, error) {
			return c.RotateTunnelCredentialsV1(ctx, tunnelID, current.ETag, key)
		})
		if e != nil {
			return e
		}
		out, e = waitForTunnelOperation(command, c, out)
		if e != nil {
			return e
		}
		return tunnelOutput(command, out, fmt.Sprintf("Rotated tunnel credentials; tunnel identity and routes are preserved; status: %s", tunnelOperationHuman(out)))
	})
	command.Flags().Bool("yes", false, "confirm credential rotation")
	tunnelMutationWaitFlags(command)
	tunnelJSONFlag(command)
	return command
}

func tunnelPageFlag(command *cobra.Command) {
	command.Flags().String("cursor", "", "continue a previous page")
	command.Flags().Int("limit", 100, "maximum results (1-200)")
}

func tunnelPageFlags(command *cobra.Command) (string, int, error) {
	cursor, _ := command.Flags().GetString("cursor")
	limit, _ := command.Flags().GetInt("limit")
	if limit < 1 || limit > 200 {
		return "", 0, errors.New("limit must be between 1 and 200")
	}
	if len(cursor) > 4096 || strings.ContainsAny(cursor, "\x00\r\n") {
		return "", 0, errors.New("cursor is invalid")
	}
	return cursor, limit, nil
}

func normalizeTunnelCLIPathPrefix(value string) (string, error) {
	value = strings.TrimSuffix(value, "*")
	if value == "" || !strings.HasPrefix(value, "/") || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n\x7f*") {
		return "", errors.New("path must be an absolute URL prefix")
	}
	return value, nil
}
