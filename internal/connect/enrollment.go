package connect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

var ErrEnrollmentUnavailable = errors.New("connector enrollment is unavailable")

// Enrollment is the secret-bearing material returned once a pairing is
// approved. It is intentionally stored only through the OS credential store
// unless the caller explicitly opts into config.FileSecretStore.
type Enrollment struct {
	MachineID     string `json:"machine_id"`
	EnvironmentID string `json:"environment_id"`
	Agentunnel    string `json:"agentunnel_token"`
	Version       string `json:"version"`
}

type PairingRequest struct {
	Verifier, DisplayName, Platform, Architecture, WorkspaceRoot string
	RuntimeVersions                                              map[string]string
}
type PairingResponse struct {
	UserCode  string    `json:"user_code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type EnrollmentClient struct {
	ServerURL string
	HTTP      *http.Client
}

func NewVerifier() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate enrollment verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (c EnrollmentClient) CreatePairing(ctx context.Context, request PairingRequest) (PairingResponse, error) {
	base, err := normalizeServerURL(c.ServerURL)
	if err != nil || strings.TrimSpace(request.Verifier) == "" {
		return PairingResponse{}, ErrEnrollmentUnavailable
	}
	body, err := json.Marshal(map[string]any{"verifier": request.Verifier, "display_name": request.DisplayName, "platform": request.Platform, "architecture": request.Architecture, "workspace_root": request.WorkspaceRoot, "runtime_versions": request.RuntimeVersions})
	if err != nil {
		return PairingResponse{}, err
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	httpRequest, err := http.NewRequest(http.MethodPost, base+"/api/connected-machines/pairings", strings.NewReader(string(body)))
	if err != nil {
		return PairingResponse{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return PairingResponse{}, ErrEnrollmentUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return PairingResponse{}, ErrEnrollmentUnavailable
	}
	var envelope struct {
		Data PairingResponse `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Data.UserCode == "" || envelope.Data.ExpiresAt.IsZero() {
		return PairingResponse{}, ErrEnrollmentUnavailable
	}
	return envelope.Data, nil
}

func (c EnrollmentClient) ConsumeInstallation(ctx context.Context, verifier string) (Enrollment, error) {
	base, err := normalizeServerURL(c.ServerURL)
	if err != nil || strings.TrimSpace(verifier) == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	body, err := json.Marshal(map[string]string{"verifier": verifier})
	if err != nil {
		return Enrollment{}, err
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/connected-machines/pairings/installation", strings.NewReader(string(body)))
	if err != nil {
		return Enrollment{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	var envelope struct {
		Data Enrollment `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Data.MachineID == "" || envelope.Data.EnvironmentID == "" || envelope.Data.Agentunnel == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	return envelope.Data, nil
}

// EnrollmentStore keeps public metadata in a 0600 JSON file and enrollment
// material in the configured secret store. The record never contains the
// verifier, agentunnel token, or any Paperboat credential.
type EnrollmentStore struct {
	Dir     string
	Secrets config.SecretStore
}

type EnrollmentMetadata struct {
	MachineID, EnvironmentID, Version string
}

func (s EnrollmentStore) Save(value Enrollment) error {
	if s.Secrets == nil || strings.TrimSpace(value.MachineID) == "" || strings.TrimSpace(value.EnvironmentID) == "" || strings.TrimSpace(value.Agentunnel) == "" {
		return ErrEnrollmentUnavailable
	}
	if err := s.Secrets.Set(s.secretRef(), value.Agentunnel); err != nil {
		return fmt.Errorf("store connector enrollment: %w", err)
	}
	metadata, err := json.Marshal(EnrollmentMetadata{MachineID: value.MachineID, EnvironmentID: value.EnvironmentID, Version: value.Version})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.Dir, "enrollment.json"), append(metadata, '\n'), 0o600)
}

func (s EnrollmentStore) Load() (Enrollment, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "enrollment.json"))
	if err != nil {
		return Enrollment{}, err
	}
	var metadata EnrollmentMetadata
	if err := json.Unmarshal(b, &metadata); err != nil || metadata.MachineID == "" || metadata.EnvironmentID == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	secret, err := s.Secrets.Get(s.secretRef())
	if err != nil || secret == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	return Enrollment{MachineID: metadata.MachineID, EnvironmentID: metadata.EnvironmentID, Version: metadata.Version, Agentunnel: secret}, nil
}

func (s EnrollmentStore) secretRef() string {
	sum := sha256.Sum256([]byte(filepath.Clean(s.Dir)))
	return "paperboat-connect:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func normalizeServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrEnrollmentUnavailable
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", ErrEnrollmentUnavailable
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func atomicWrite(path string, value []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".enrollment-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(value); err == nil {
		err = tmp.Chmod(mode)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
