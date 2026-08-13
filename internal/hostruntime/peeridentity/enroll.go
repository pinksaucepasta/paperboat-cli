package peeridentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"golang.org/x/crypto/blake2s"
)

var (
	ErrInvalid = errors.New("machine endpoint enrollment is invalid")
	ErrPending = errors.New("machine endpoint approval is pending")
)

type CredentialSource interface {
	Token(context.Context) (string, error)
	Proof(context.Context, string, string, string, []byte) ([]byte, error)
}

type Config struct {
	ControlURL string
	StateRoot  string
	Transport  http.RoundTripper
	Timeout    time.Duration
	Clock      func() time.Time
}

type PendingError struct {
	RequestID  string
	SafetyCode string
	ExpiresAt  time.Time
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("%v: compare code %s and approve request %s", ErrPending, e.SafetyCode, e.RequestID)
}

func (e *PendingError) Unwrap() error { return ErrPending }

type Client struct {
	config Config
	base   *url.URL
	http   *http.Client
	creds  CredentialSource
}

func New(config Config, credentials CredentialSource) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || config.StateRoot == "" || credentials == nil {
		return nil, ErrInvalid
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		config.Timeout = 15 * time.Second
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &Client{config: config, base: base, creds: credentials, http: &http.Client{Transport: config.Transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}}, nil
}

func (c *Client) Ensure(ctx context.Context) error {
	store, err := identitystore.Open(identitystore.Config{StateRoot: c.config.StateRoot})
	if err != nil {
		return err
	}
	endpoint, err := store.PeerEndpoint()
	if err != nil {
		return err
	}
	if len(endpoint.Certificate) > 0 {
		return nil
	}
	registration, err := store.Registration()
	if err != nil || uint64(registration.InstallationGeneration) != endpoint.Generation {
		return ErrInvalid
	}
	noisePublic := endpoint.NoisePublicKey()
	quicPublic := endpoint.QUICPublicKey()
	requestOperation := operationID("op_peer_machine_request_", registration.MachineID, endpoint.Generation, noisePublic[:], quicPublic)
	requestBody, _ := json.Marshal(struct {
		OperationID    string `json:"operation_id"`
		Generation     uint64 `json:"generation"`
		NoisePublicKey string `json:"noise_public_key"`
		QUICPublicKey  string `json:"quic_public_key"`
	}{requestOperation, endpoint.Generation, base64.RawURLEncoding.EncodeToString(noisePublic[:]), base64.RawURLEncoding.EncodeToString(quicPublic)})
	var pending struct {
		RequestID  string    `json:"request_id"`
		EndpointID string    `json:"endpoint_id"`
		Generation uint64    `json:"generation"`
		NoiseKey   string    `json:"noise_public_key"`
		QUICKey    string    `json:"quic_public_key"`
		ExpiresAt  time.Time `json:"expires_at"`
		SafetyCode string    `json:"safety_code"`
	}
	status, err := c.post(ctx, "/v1/machine-peer-identity", requestOperation, requestBody, &pending)
	requestConflict := status == http.StatusConflict
	if err != nil && !requestConflict {
		return err
	}
	if !requestConflict && (status != http.StatusCreated || pending.EndpointID != registration.MachineID || pending.Generation != endpoint.Generation || pending.NoiseKey != base64.RawURLEncoding.EncodeToString(noisePublic[:]) || pending.QUICKey != base64.RawURLEncoding.EncodeToString(quicPublic) || pending.SafetyCode != safetyCode(registration.MachineID, endpoint.Generation, noisePublic, quicPublic)) {
		return ErrInvalid
	}
	statusOperation := operationID("op_peer_machine_status_", registration.MachineID, endpoint.Generation, nil, nil)
	statusBody, _ := json.Marshal(struct {
		OperationID string `json:"operation_id"`
		Generation  uint64 `json:"generation"`
	}{statusOperation, endpoint.Generation})
	var approved struct {
		State         string `json:"state"`
		RootPublicKey string `json:"root_public_key"`
		Certificate   struct {
			Certificate string `json:"certificate"`
		} `json:"certificate"`
	}
	status, err = c.post(ctx, "/v1/machine-peer-identity/status", statusOperation, statusBody, &approved)
	if err != nil {
		return err
	}
	if status == http.StatusAccepted && approved.State == "pending" {
		if requestConflict {
			return ErrPending
		}
		return &PendingError{RequestID: pending.RequestID, SafetyCode: pending.SafetyCode, ExpiresAt: pending.ExpiresAt}
	}
	root, rootErr := base64.RawURLEncoding.Strict().DecodeString(approved.RootPublicKey)
	certificate, certificateErr := base64.RawURLEncoding.Strict().DecodeString(approved.Certificate.Certificate)
	if status != http.StatusOK || approved.State != "approved" || rootErr != nil || len(root) != 32 || certificateErr != nil || len(certificate) == 0 {
		return ErrInvalid
	}
	return store.SavePeerEndpointCertificate(ed25519.PublicKey(root), certificate, c.config.Clock().UTC())
}

func (c *Client) post(ctx context.Context, path, operationID string, body []byte, out any) (int, error) {
	token, err := c.creds.Token(ctx)
	if err != nil {
		return 0, err
	}
	proof, err := c.creds.Proof(ctx, operationID, http.MethodPost, path, body)
	if err != nil {
		return 0, err
	}
	endpoint := c.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusCreated {
		_, _ = io.CopyN(io.Discard, response.Body, 32<<10)
		return response.StatusCode, ErrInvalid
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(envelope.Data) == 0 || json.Unmarshal(envelope.Data, out) != nil {
		return response.StatusCode, ErrInvalid
	}
	return response.StatusCode, nil
}

func operationID(prefix, endpointID string, generation uint64, first, second []byte) string {
	h := sha256.New()
	h.Write([]byte(endpointID))
	var generationBytes [8]byte
	binary.BigEndian.PutUint64(generationBytes[:], generation)
	h.Write(generationBytes[:])
	h.Write(first)
	h.Write(second)
	return prefix + hex.EncodeToString(h.Sum(nil)[:16])
}

func safetyCode(endpointID string, generation uint64, noise [32]byte, quic []byte) string {
	buffer := append([]byte("paperboat-machine-endpoint-v1\x00"), endpointID...)
	buffer = append(buffer, 0)
	buffer = binary.BigEndian.AppendUint64(buffer, generation)
	buffer = append(buffer, noise[:]...)
	buffer = append(buffer, quic...)
	digest := blake2s.Sum256(buffer)
	encoded := hex.EncodeToString(digest[:5])
	return encoded[:5] + "-" + encoded[5:]
}
