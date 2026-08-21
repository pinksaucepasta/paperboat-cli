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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

type Config struct {
	ServerURL, EnrollmentToken, DisplayName, WorkspaceRoot, Verifier, PublicIdentityKey string
	SSHUser                                                                             string
	SSHPort                                                                             uint16
	CanReuseRuntimeIdentity                                                             bool
	RuntimeVersions                                                                     map[string]string
	HTTP                                                                                *http.Client
	AcceptBetaPlatform                                                                  bool
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
		"accept_beta_platform":       config.AcceptBetaPlatform,
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
	body, _ := json.Marshal(map[string]string{"verifier": config.Verifier})
	for time.Now().UTC().Before(expiresAt) {
		var material Material
		err := request(ctx, client(config), http.MethodPost, base+"/v1/machines/pairings/installation", body, &material)
		if err == nil {
			if validationErr := validateMaterial(material); validationErr != nil {
				return Material{}, validationErr
			}
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

func validateMaterial(material Material) error {
	validEnrollment := material.ReuseIdentity && material.EnrollmentID == "" && material.EnrollmentCredential == "" || !material.ReuseIdentity && material.EnrollmentID != "" && len(material.EnrollmentCredential) >= 32
	checks := []struct {
		invalid bool
		reason  string
	}{
		{material.Schema != "paperboat.byod-installation/v1", "schema"},
		{material.UserMachineID == "", "user machine id"},
		{material.UserMachineEnrollmentID == "", "enrollment id"},
		{material.EnvironmentID == "", "environment id"},
		{material.HelperID == "", "helper id"},
		{!validEnrollment, "enrollment credential"},
		{!validLoopbackAddress(material.HelperListenAddress), "helper listen address"},
		{material.InstallationGeneration < 1, "installation generation"},
		{material.SetupMode != "host", "setup mode"},
		{!hasRole(material.SetupRoles, "host"), "host role"},
		{!time.Now().UTC().Before(material.ExpiresAt), "expiration"},
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
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil || len(encoded) > 64<<10 {
		return ErrInvalid
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(encoded, &envelope) != nil {
			return fmt.Errorf("%w: server status %d", ErrInvalid, response.StatusCode)
		}
		switch envelope.Error.Code {
		case "machine_approval_pending", "user_machine_approval_pending":
			return ErrApprovalPending
		case "machine_pairing_denied", "user_machine_pairing_denied":
			return ErrPairingDenied
		case "machine_pairing_expired", "user_machine_pairing_expired":
			return ErrPairingExpired
		case "machine_installation_unavailable", "user_machine_installation_unavailable":
			return ErrInstallationUnavailable
		default:
			return fmt.Errorf("%w: server status %d", ErrInvalid, response.StatusCode)
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
