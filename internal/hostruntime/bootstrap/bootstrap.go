package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

var (
	ErrInvalid                 = errors.New("invalid BYOD bootstrap")
	ErrApprovalPending         = errors.New("BYOD pairing approval is pending")
	ErrPairingDenied           = errors.New("BYOD pairing was denied")
	ErrPairingExpired          = errors.New("BYOD pairing expired")
	ErrInstallationUnavailable = errors.New("BYOD installation material is unavailable")
)

const (
	// maxBootstrapResponseBody bounds bytes retained from a server response.
	// The request path already limits response reads to this size; keep the
	// same bound on diagnostics so a malformed server cannot fill the terminal
	// or an error log with unbounded data.
	maxBootstrapResponseBody = 64 << 10
	maxBootstrapErrorBody    = 8 << 10
	bootstrapRequestAttempts = 3
)

type Config struct {
	ServerURL, EnrollmentToken, DisplayName, WorkspaceRoot, Verifier, PublicIdentityKey string
	SSHUser                                                                             string
	SSHPort                                                                             uint16
	CanReuseRuntimeIdentity                                                             bool
	RuntimeVersions                                                                     map[string]string
	HTTP                                                                                *http.Client
}

type Pairing struct {
	ID        string    `json:"id"`
	UserCode  string    `json:"user_code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Material struct {
	Schema                  string          `json:"schema"`
	UserMachineID           string          `json:"user_machine_id"`
	UserMachineEnrollmentID string          `json:"user_machine_enrollment_id"`
	EnvironmentID           string          `json:"environment_id"`
	ControlURL              string          `json:"control_url"`
	HelperID                string          `json:"helper_id"`
	EnrollmentID            string          `json:"enrollment_id"`
	EnrollmentCredential    string          `json:"enrollment_credential"`
	ReuseIdentity           bool            `json:"reuse_identity,omitempty"`
	ExpiresAt               time.Time       `json:"expires_at"`
	Artifact                *ArtifactTarget `json:"artifact,omitempty"`
	HelperListenAddress     string          `json:"helper_listen_address"`
	InstallationGeneration  int64           `json:"installation_generation"`
	SetupRoles              []string        `json:"setup_roles"`
	SetupMode               string          `json:"setup_mode"`
	ClientSession           *ClientSession  `json:"client_session,omitempty"`
}

type ClientSession struct {
	Schema       string `json:"schema"`
	SessionID    string `json:"session_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func CreatePairing(ctx context.Context, config Config) (Pairing, error) {
	base, err := validate(config)
	if err != nil {
		return Pairing{}, err
	}
	body, err := json.Marshal(map[string]any{
		"enrollment_token": config.EnrollmentToken, "verifier": config.Verifier,
		"display_name": config.DisplayName, "platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"workspace_root": config.WorkspaceRoot, "runtime_versions": config.RuntimeVersions, "public_identity_key": config.PublicIdentityKey,
		"can_reuse_runtime_identity": config.CanReuseRuntimeIdentity,
		"ssh_user":                   strings.TrimSpace(config.SSHUser), "ssh_port": config.SSHPort,
	})
	if err != nil {
		return Pairing{}, err
	}
	var pairing Pairing
	if err := request(ctx, client(config), http.MethodPost, base+"/v1/machines/pairings", body, &pairing); err != nil {
		return Pairing{}, err
	}
	if pairing.ID == "" || pairing.UserCode == "" || !time.Now().UTC().Before(pairing.ExpiresAt) {
		return Pairing{}, ErrInvalid
	}
	return pairing, nil
}

func WaitForMaterial(ctx context.Context, config Config, expiresAt time.Time, interval time.Duration) (Material, error) {
	base, err := validate(config)
	if err != nil {
		return Material{}, err
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	body, _ := json.Marshal(map[string]string{"verifier": config.Verifier, "public_identity_key": config.PublicIdentityKey})
	for time.Now().UTC().Before(expiresAt) {
		material, err := requestMaterial(ctx, config, base, body)
		if err == nil {
			return material, nil
		}
		if !errors.Is(err, ErrApprovalPending) && !transientBootstrapError(err) {
			return Material{}, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Material{}, ctx.Err()
		case <-timer.C:
		}
	}
	return Material{}, ErrPairingExpired
}

// RecoverMaterial makes one verifier-bound renewal/replay request without
// applying the original pairing deadline. A protected paired resume journal
// can outlive that deadline after the server issued material but the client
// crashed before persisting or installing it.
func RecoverMaterial(ctx context.Context, config Config, runtimeEnrolled bool) (Material, error) {
	base, err := validate(config)
	if err != nil {
		return Material{}, err
	}
	body, _ := json.Marshal(map[string]any{"verifier": config.Verifier, "public_identity_key": config.PublicIdentityKey, "runtime_enrolled": runtimeEnrolled})
	return requestMaterial(ctx, config, base, body)
}

func requestMaterial(ctx context.Context, config Config, base string, body []byte) (Material, error) {
	var material Material
	if err := request(ctx, client(config), http.MethodPost, base+"/v1/machines/pairings/installation", body, &material); err != nil {
		return Material{}, err
	}
	if err := validateMaterial(material); err != nil {
		return Material{}, err
	}
	if normalizeBootstrapURL(material.ControlURL) != normalizeBootstrapURL(config.ServerURL) {
		return Material{}, fmt.Errorf("%w: control URL does not match pairing server", ErrInvalid)
	}
	return material, nil
}

func validateMaterial(material Material) error {
	return validateMaterialFreshness(material, true)
}

// validateMaterialFreshness validates all server material fields. Resume
// loading skips only freshness so an expired, securely bound journal can ask
// the server for renewed material instead of being mistaken for corruption.
func validateMaterialFreshness(material Material, requireFresh bool) error {
	validEnrollment := material.ReuseIdentity && material.EnrollmentID == "" && material.EnrollmentCredential == "" || !material.ReuseIdentity && material.EnrollmentID != "" && len(material.EnrollmentCredential) >= 32
	validSetupMode := material.SetupMode == "host" || material.SetupMode == "client"
	validSetupRole := (material.SetupMode == "host" && hasRole(material.SetupRoles, "host")) ||
		(material.SetupMode == "client" && hasRole(material.SetupRoles, "interactive"))
	validClientSession := material.ClientSession != nil && (material.SetupMode == "host" || material.SetupMode == "client") && validBootstrapClientSession(*material.ClientSession)
	checks := []struct {
		invalid bool
		reason  string
	}{
		{material.Schema != "paperboat.byod-installation/v1", "schema"},
		{material.UserMachineID == "", "user machine id"},
		{material.UserMachineEnrollmentID == "", "enrollment id"},
		{material.EnvironmentID == "", "environment id"},
		{material.HelperID == "", "helper id"},
		{!validBootstrapControlURL(material.ControlURL), "control URL"},
		{!validEnrollment, "enrollment credential"},
		{!validLoopbackAddress(material.HelperListenAddress), "helper listen address"},
		{material.InstallationGeneration < 1, "installation generation"},
		{!validSetupMode, "setup mode"},
		{!validSetupRole, "setup role"},
		{!validClientSession, "client session"},
		{requireFresh && !time.Now().UTC().Before(material.ExpiresAt), "expiration"},
		{material.Artifact == nil, "artifact"},
	}
	for _, check := range checks {
		if check.invalid {
			return fmt.Errorf("%w: %s", ErrInvalid, check.reason)
		}
	}
	if err := VerifyArtifactTarget(*material.Artifact); err != nil {
		return fmt.Errorf("%w: artifact target: %v", ErrInvalid, err)
	}
	return nil
}

func validBootstrapControlURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.User == nil && parsed.Hostname() != "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func normalizeBootstrapURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func validBootstrapClientSession(session ClientSession) bool {
	return session.Schema == "paperboat.cli-session/v1" && boundedBootstrapValue(session.SessionID, 1, 256) &&
		boundedBootstrapValue(session.AccessToken, 32, 16<<10) && boundedBootstrapValue(session.RefreshToken, 32, 16<<10) &&
		session.TokenType == "Bearer" && session.ExpiresIn > 0 && session.ExpiresIn <= 7*24*60*60 &&
		(len(session.Scope) == 0 || boundedBootstrapValue(session.Scope, 1, 4<<10))
}

func boundedBootstrapValue(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func hasRole(roles []string, wanted string) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

// transientBootstrapError reports errors that do not carry pairing-terminal
// meaning: stalled or reset connections and timeouts. Approval polling must
// survive them instead of abandoning a pairing that is still redeemable.
func transientBootstrapError(err error) bool {
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}

func validLoopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ValidateWorkspace(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return ErrInvalid
	}
	return nil
}

func validate(config Config) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(config.ServerURL))
	publicKey, keyErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(config.PublicIdentityKey))
	token := strings.TrimSpace(config.EnrollmentToken)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || token != "" && (len(token) < 26 || len(token) > 256) || len(config.Verifier) < 32 || strings.TrimSpace(config.DisplayName) == "" || ValidateWorkspace(config.WorkspaceRoot) != nil || keyErr != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func client(config Config) *http.Client {
	if config.HTTP != nil {
		return config.HTTP
	}
	return &http.Client{Transport: httptransport.Default(), Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
}

func request(ctx context.Context, client *http.Client, method, target string, body []byte, output any) error {
	var response *http.Response
	for attempt := 0; attempt < bootstrapRequestAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		var wroteRequest atomic.Bool
		trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) }}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
		response, err = client.Do(request)
		if err == nil {
			break
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A dashboard token is single-use and CreatePairing is not itself
		// idempotent. Retry only while net/http proves that no request bytes
		// reached the connection. Once WroteRequest fires, the protected
		// verifier resume flow owns uncertain-outcome recovery.
		if wroteRequest.Load() || !transientBootstrapError(err) || attempt+1 == bootstrapRequestAttempts {
			return err
		}
		delay := 250 * time.Millisecond << attempt
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxBootstrapResponseBody+1))
	if err != nil || len(encoded) > maxBootstrapResponseBody {
		return ErrInvalid
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(encoded, &envelope)
		switch envelope.Error.Code {
		case "machine_approval_pending", "user_machine_approval_pending":
			return bootstrapServerError(ErrApprovalPending, response.StatusCode, envelope.Error.Code, envelope.Error.Message, encoded)
		case "machine_pairing_denied", "user_machine_pairing_denied":
			return bootstrapServerError(ErrPairingDenied, response.StatusCode, envelope.Error.Code, envelope.Error.Message, encoded)
		case "machine_pairing_expired", "user_machine_pairing_expired":
			return bootstrapServerError(ErrPairingExpired, response.StatusCode, envelope.Error.Code, envelope.Error.Message, encoded)
		case "machine_installation_unavailable", "user_machine_installation_unavailable":
			return bootstrapServerError(ErrInstallationUnavailable, response.StatusCode, envelope.Error.Code, envelope.Error.Message, encoded)
		default:
			return bootstrapServerError(ErrInvalid, response.StatusCode, envelope.Error.Code, envelope.Error.Message, encoded)
		}
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(encoded, &envelope) != nil || len(envelope.Data) == 0 || json.Unmarshal(envelope.Data, output) != nil {
		return ErrInvalid
	}
	return nil
}

func bootstrapServerError(kind error, status int, code, message string, body []byte) error {
	// Keep the exact bounded response available in the diagnostic. Quoting it
	// prevents server-controlled newlines or control bytes from forging output
	// while retaining enough information to copy and inspect the body.
	truncated := false
	if len(body) > maxBootstrapErrorBody {
		body = body[:maxBootstrapErrorBody]
		truncated = true
	}
	bodyText := string(body)
	parts := []string{fmt.Sprintf("server status %d", status)}
	if code != "" {
		parts = append(parts, "code "+quoteBootstrapDiagnostic(code, 256))
	}
	if message != "" {
		parts = append(parts, "message "+quoteBootstrapDiagnostic(message, 2048))
	}
	if strings.TrimSpace(bodyText) != "" {
		bodyDiagnostic := strconv.Quote(bodyText)
		if truncated {
			bodyDiagnostic += "...<truncated>"
		}
		parts = append(parts, "body "+bodyDiagnostic)
	}
	return fmt.Errorf("%w: %s", kind, strings.Join(parts, "; "))
}

func quoteBootstrapDiagnostic(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return strconv.Quote(value[:limit]) + "...<truncated>"
	}
	return strconv.Quote(value)
}
