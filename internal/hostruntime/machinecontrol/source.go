package machinecontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

var ErrInvalid = errors.New("machine control credential is invalid")

type Config struct {
	ControlURL  string
	StateRoot   string
	Transport   http.RoundTripper
	Timeout     time.Duration
	RenewBefore time.Duration
	Clock       func() time.Time
	OperationID func() (string, error)
}

type Source struct {
	config   Config
	endpoint *url.URL
	client   *http.Client
	mu       sync.Mutex
}

func NewSource(config Config) (*Source, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || config.StateRoot == "" {
		return nil, ErrInvalid
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/machine-control-renewals"
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		config.Timeout = 15 * time.Second
	}
	if config.RenewBefore <= 0 || config.RenewBefore >= time.Hour {
		config.RenewBefore = 10 * time.Minute
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.OperationID == nil {
		config.OperationID = randomOperationID
	}
	return &Source{config: config, endpoint: endpoint, client: &http.Client{Transport: config.Transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}}, nil
}

func (s *Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	store, err := identity.Open(identity.Config{StateRoot: s.config.StateRoot})
	if err != nil {
		return "", ErrInvalid
	}
	now := s.config.Clock().UTC()
	current, err := store.MachineControl(now, time.Hour)
	if err != nil {
		return "", ErrInvalid
	}
	if current.ExpiresAt.After(now.Add(s.config.RenewBefore)) {
		return current.Credential, nil
	}
	operationID, err := s.config.OperationID()
	if err != nil || len(operationID) < 8 || len(operationID) > 128 {
		return "", ErrInvalid
	}
	body, err := json.Marshal(struct {
		OperationID string `json:"operation_id"`
	}{operationID})
	if err != nil {
		return "", err
	}
	proof, err := store.MachineProof(operationID, http.MethodPost, s.endpoint.Path, body, now)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+current.Credential)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.CopyN(io.Discard, response.Body, 32<<10)
		return "", ErrInvalid
	}
	var envelope struct {
		Data identity.MachineControl `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return "", ErrInvalid
	}
	envelope.Data.MachineID = current.MachineID
	envelope.Data.EnvironmentID = current.EnvironmentID
	envelope.Data.InstallationGeneration = current.InstallationGeneration
	envelope.Data.KeyID = current.KeyID
	if err := store.SaveMachineControl(envelope.Data); err != nil {
		return "", err
	}
	return envelope.Data.Credential, nil
}

func (s *Source) Proof(_ context.Context, operationID, method, path string, body []byte) ([]byte, error) {
	store, err := identity.Open(identity.Config{StateRoot: s.config.StateRoot})
	if err != nil {
		return nil, ErrInvalid
	}
	return store.MachineProof(operationID, method, path, body, s.config.Clock().UTC())
}

func randomOperationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "machine-renew-" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}
