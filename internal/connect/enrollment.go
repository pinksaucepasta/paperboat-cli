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
	MachineID           string             `json:"machine_id"`
	EnvironmentID       string             `json:"environment_id"`
	AgentunnelClientID  string             `json:"agentunnel_client_id"`
	AgentunnelRouteID   string             `json:"agentunnel_route_id"`
	AgentunnelServerURL string             `json:"agentunnel_server_url"`
	PapercodeLocalURL   string             `json:"papercode_local_url"`
	PapercodeBootstrap  PapercodeBootstrap `json:"papercode_bootstrap"`
	Agentunnel          string             `json:"agentunnel_token"`
	Version             string             `json:"version"`
}

type PapercodeBootstrap struct {
	RelayURL              string `json:"relay_url"`
	RelayIssuer           string `json:"relay_issuer"`
	CloudUserID           string `json:"cloud_user_id"`
	EnvironmentCredential string `json:"environment_credential"`
	CloudMintPublicKey    string `json:"cloud_mint_public_key"`
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
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Data.MachineID == "" || envelope.Data.EnvironmentID == "" || envelope.Data.AgentunnelRouteID == "" || envelope.Data.AgentunnelServerURL == "" || envelope.Data.PapercodeLocalURL == "" || envelope.Data.Agentunnel == "" || envelope.Data.PapercodeBootstrap.invalid() {
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
	MachineID, EnvironmentID, AgentunnelClientID, AgentunnelRouteID, AgentunnelServerURL, PapercodeLocalURL, Version string
}

func (b PapercodeBootstrap) invalid() bool {
	return strings.TrimSpace(b.RelayURL) == "" || strings.TrimSpace(b.RelayIssuer) == "" || strings.TrimSpace(b.CloudUserID) == "" || strings.TrimSpace(b.EnvironmentCredential) == "" || strings.TrimSpace(b.CloudMintPublicKey) == ""
}

// PendingEnrollmentStore makes device-style approval resilient to a connector
// restart. The verifier remains in the configured secret store.
type PendingEnrollmentStore struct {
	Dir     string
	Secrets config.SecretStore
}

type PendingEnrollment struct {
	ServerURL string    `json:"server_url"`
	UserCode  string    `json:"user_code"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s PendingEnrollmentStore) Save(value PendingEnrollment, verifier string) error {
	if s.Secrets == nil || strings.TrimSpace(value.ServerURL) == "" || strings.TrimSpace(value.UserCode) == "" || strings.TrimSpace(verifier) == "" {
		return ErrEnrollmentUnavailable
	}
	if err := s.Secrets.Set(s.secretRef(), verifier); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.Dir, "pending-enrollment.json"), append(b, '\n'), 0o600)
}

func (s PendingEnrollmentStore) Load() (PendingEnrollment, string, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "pending-enrollment.json"))
	if err != nil {
		return PendingEnrollment{}, "", err
	}
	var value PendingEnrollment
	if err := json.Unmarshal(b, &value); err != nil || value.ServerURL == "" || value.UserCode == "" || value.ExpiresAt.IsZero() {
		return PendingEnrollment{}, "", ErrEnrollmentUnavailable
	}
	verifier, err := s.Secrets.Get(s.secretRef())
	if err != nil || verifier == "" {
		return PendingEnrollment{}, "", ErrEnrollmentUnavailable
	}
	return value, verifier, nil
}

func (s PendingEnrollmentStore) Delete() {
	_ = os.Remove(filepath.Join(s.Dir, "pending-enrollment.json"))
	if s.Secrets != nil {
		_ = s.Secrets.Delete(s.secretRef())
	}
}

func (s PendingEnrollmentStore) secretRef() string {
	sum := sha256.Sum256([]byte("pending:" + filepath.Clean(s.Dir)))
	return "paperboat-connect:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s EnrollmentStore) Save(value Enrollment) error {
	if s.Secrets == nil || strings.TrimSpace(value.MachineID) == "" || strings.TrimSpace(value.EnvironmentID) == "" || strings.TrimSpace(value.Agentunnel) == "" || value.PapercodeBootstrap.invalid() {
		return ErrEnrollmentUnavailable
	}
	secret, err := json.Marshal(struct {
		Agentunnel string             `json:"agentunnel_token"`
		Bootstrap  PapercodeBootstrap `json:"papercode_bootstrap"`
	}{Agentunnel: value.Agentunnel, Bootstrap: value.PapercodeBootstrap})
	if err != nil {
		return err
	}
	if err := s.Secrets.Set(s.secretRef(), string(secret)); err != nil {
		return fmt.Errorf("store connector enrollment: %w", err)
	}
	metadata, err := json.Marshal(EnrollmentMetadata{MachineID: value.MachineID, EnvironmentID: value.EnvironmentID, AgentunnelClientID: value.AgentunnelClientID, AgentunnelRouteID: value.AgentunnelRouteID, AgentunnelServerURL: value.AgentunnelServerURL, PapercodeLocalURL: value.PapercodeLocalURL, Version: value.Version})
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
	if err := json.Unmarshal(b, &metadata); err != nil || metadata.MachineID == "" || metadata.EnvironmentID == "" || metadata.AgentunnelRouteID == "" || metadata.AgentunnelServerURL == "" || metadata.PapercodeLocalURL == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	secret, err := s.Secrets.Get(s.secretRef())
	if err != nil || secret == "" {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	var stored struct {
		Agentunnel string             `json:"agentunnel_token"`
		Bootstrap  PapercodeBootstrap `json:"papercode_bootstrap"`
	}
	if json.Unmarshal([]byte(secret), &stored) != nil || stored.Agentunnel == "" || stored.Bootstrap.invalid() {
		return Enrollment{}, ErrEnrollmentUnavailable
	}
	return Enrollment{MachineID: metadata.MachineID, EnvironmentID: metadata.EnvironmentID, AgentunnelClientID: metadata.AgentunnelClientID, AgentunnelRouteID: metadata.AgentunnelRouteID, AgentunnelServerURL: metadata.AgentunnelServerURL, PapercodeLocalURL: metadata.PapercodeLocalURL, PapercodeBootstrap: stored.Bootstrap, Version: metadata.Version, Agentunnel: stored.Agentunnel}, nil
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
