package environmentenrollment

import (
	"bytes"
	"context"
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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

const stateSchema = "paperboat.environment-host-enrollment/v1"

var (
	ErrInvalid = errors.New("environment host key enrollment is invalid")
	ErrPending = errors.New("environment host key authorization is required")
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
	Keys       environmentkey.Source
	// Reconcile is the authenticated runtime's view of this exact host
	// binding. The runtime reports Active only after it has verified the
	// authority/binding for the current recipient, and Inactive only after it
	// has verified exclusion. Unknown must remain pending so an expired local
	// request cannot cause a duplicate enrollment while reconciliation is in
	// flight.
	Reconcile func(context.Context) (BindingState, error)
}

// BindingState is deliberately tri-state. A missing observation is not
// evidence that a binding is absent, and callers must fail closed on Unknown.
type BindingState uint8

const (
	BindingUnknown BindingState = iota
	BindingActive
	BindingInactive
)

type PendingError struct {
	RequestID  string
	SafetyCode string
	ExpiresAt  time.Time
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("%v: compare code %s for request %s", ErrPending, e.SafetyCode, e.RequestID)
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
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		!filepath.IsAbs(config.StateRoot) || config.Keys == nil || credentials == nil {
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

type enrollmentState struct {
	Schema            string    `json:"schema"`
	OperationID       string    `json:"operation_id"`
	RequestID         string    `json:"request_id"`
	SafetyCode        string    `json:"safety_code"`
	ExpiresAt         time.Time `json:"expires_at"`
	Proofed           bool      `json:"proofed"`
	Approved          bool      `json:"approved,omitempty"`
	Proof             string    `json:"proof,omitempty"`
	EnrollmentRequest string    `json:"enrollment_request"`
}

func (c *Client) Ensure(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	now := c.config.Clock().UTC().Truncate(time.Second)
	state, stateErr := c.loadState()
	if stateErr == nil {
		current, currentErr := c.stateMatchesCurrentIdentity(ctx, state)
		if currentErr != nil {
			return currentErr
		}
		if current {
			if state.Approved {
				return nil
			}
			if state.Proofed {
				// Proof acceptance is not authority approval. Reconcile before
				// considering a replacement request, including after the local
				// request's expiry. Unknown deliberately stays pending.
				if c.config.Reconcile != nil {
					binding, reconcileErr := c.config.Reconcile(ctx)
					if reconcileErr != nil {
						return reconcileErr
					}
					switch binding {
					case BindingActive:
						if err := c.commitApproved(state); err != nil {
							return err
						}
						return nil
					case BindingUnknown:
						return pendingForState(state)
					case BindingInactive:
						// A verified exclusion is the only condition which
						// permits issuing a replacement operation.
					}
				}
				if now.Before(state.ExpiresAt) {
					return pendingForState(state)
				}
				// A configured reconciler has already returned Inactive here.
				// With no reconciler, preserve the historical expiry retry.
			} else if state.Proof != "" {
				if now.Before(state.ExpiresAt) {
					return c.submitProof(ctx, state)
				}
				// A challenge which was never proofed cannot be submitted
				// after its expiry. Continue to deterministic request creation.
			} else {
				return ErrInvalid
			}
		}
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	// A host may have been approved before its local journal was written (for
	// example, after a crash between runtime delivery and journal commit). Ask
	// the authenticated runtime before creating the first request so that exact
	// active bindings are adopted without rotating the recipient or issuing a
	// duplicate enrollment.
	if errors.Is(stateErr, os.ErrNotExist) && c.config.Reconcile != nil {
		binding, reconcileErr := c.config.Reconcile(ctx)
		if reconcileErr != nil {
			return reconcileErr
		}
		if binding == BindingActive {
			return c.MarkApproved(ctx)
		}
	}
	identity, err := identitystore.Open(identitystore.Config{StateRoot: c.config.StateRoot})
	if err != nil {
		return err
	}
	registration, err := identity.Registration()
	if err != nil || registration.SetupMode != "host" || registration.InstallationGeneration < 1 {
		return ErrInvalid
	}
	endpoint, err := identity.PeerEndpoint()
	if err != nil || len(endpoint.Certificate) == 0 || endpoint.Generation != uint64(registration.InstallationGeneration) {
		return ErrInvalid
	}
	verified, err := endpointidentity.Verify(endpoint.Certificate, endpoint.RootPublicKey, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, Generation: endpoint.Generation}, now)
	if err != nil || verified.Claims.AccountID == "" {
		return ErrInvalid
	}
	material, err := c.config.Keys.Load(ctx)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if material.Generation != endpoint.Generation {
		return ErrInvalid
	}
	public, err := material.Public()
	if err != nil {
		return err
	}
	kid, err := environmente2ee.KeyIDX25519(public[:])
	if err != nil {
		return err
	}
	expiresAt := now.Truncate(4 * time.Minute).Add(5 * time.Minute)
	operation := enrollmentOperation(registration.MachineID, endpoint.Generation, expiresAt, public)
	request := environmente2ee.EnrollmentRequest{
		AccountID: verified.Claims.AccountID, OperationID: operation, SubjectKind: environmente2ee.SubjectHost,
		SubjectID: registration.MachineID, SubjectGeneration: endpoint.Generation, KeyGeneration: material.Generation,
		EndpointCertificate: append([]byte(nil), endpoint.Certificate...), RecipientPublic: public[:], RecipientKeyID: kid,
		RequestExpiresAt: uint64(expiresAt.Unix()),
	}
	canonical, err := environmente2ee.CanonicalEnrollmentRequest(request)
	if err != nil {
		return err
	}
	safetyCode, err := environmente2ee.EnrollmentSafetyCode(request)
	if err != nil {
		return err
	}
	operationID := "envop_" + hex.EncodeToString(operation[:])
	body, err := json.Marshal(struct {
		Schema              string  `json:"schema"`
		OperationID         string  `json:"operation_id"`
		SubjectKind         string  `json:"subject_kind"`
		SubjectID           string  `json:"subject_id"`
		SubjectGeneration   uint64  `json:"subject_generation"`
		KeyGeneration       uint64  `json:"key_generation"`
		EndpointCertificate string  `json:"endpoint_certificate"`
		SigningPublicKey    *string `json:"signing_public_key"`
		SigningKeyID        *string `json:"signing_key_id"`
		SigningProof        *string `json:"signing_proof"`
		RecipientPublicKey  string  `json:"recipient_public_key"`
		RecipientKeyID      string  `json:"recipient_key_id"`
		BindingNotAfter     *string `json:"binding_not_after"`
		RequestExpiresAt    string  `json:"request_expires_at"`
	}{
		Schema: "paperboat.environment-key-enrollment/v1", OperationID: operationID, SubjectKind: "host",
		SubjectID: registration.MachineID, SubjectGeneration: endpoint.Generation, KeyGeneration: material.Generation,
		EndpointCertificate: base64.RawURLEncoding.EncodeToString(endpoint.Certificate), RecipientPublicKey: base64.RawURLEncoding.EncodeToString(public[:]),
		RecipientKeyID: kid, RequestExpiresAt: expiresAt.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	var response enrollmentResponse
	if err := c.call(ctx, http.MethodPost, "/v1/environment-key-enrollments", operationID, body, &response); err != nil {
		return err
	}
	if response.Schema != "paperboat.environment-key-enrollment-state/v1" || response.RequestID == "" ||
		response.ExpiresAt != expiresAt || response.SafetyCode != safetyCode || response.EnrollmentRequest != base64.RawURLEncoding.EncodeToString(canonical) || response.SigningProof != nil {
		return ErrInvalid
	}
	if response.State == "pending" {
		// The server returns this exact state for an idempotent POST replay
		// after recipient proof was already accepted. No challenge is issued a
		// second time, so journal proof completion and wait for the runtime
		// authority reconciliation below.
		if response.Challenge != "" {
			return ErrInvalid
		}
		state := enrollmentState{Schema: stateSchema, OperationID: operationID, RequestID: response.RequestID, SafetyCode: safetyCode, ExpiresAt: expiresAt, Proofed: true, EnrollmentRequest: response.EnrollmentRequest}
		if err := c.writeState(state); err != nil {
			return err
		}
		return pendingForState(state)
	}
	if response.State != "challenge" || response.Challenge == "" {
		return ErrInvalid
	}
	sealed, err := decodeBase64(response.Challenge, 80)
	if err != nil {
		return err
	}
	digest, _ := environmente2ee.EnrollmentRequestDigest(request)
	challengeContext := environmente2ee.EnrollmentChallengeContext{AccountID: request.AccountID, RequestID: response.RequestID, OperationID: operation, RecipientKeyID: kid, RequestDigest: digest}
	challenge, err := environmente2ee.OpenEnrollmentChallenge(challengeContext, material.Private[:], sealed)
	clear(sealed)
	if err != nil {
		return ErrInvalid
	}
	proof, err := environmente2ee.EnrollmentProof(challengeContext, challenge)
	clear(challenge)
	if err != nil {
		return err
	}
	proofBody, _ := json.Marshal(struct {
		Schema string `json:"schema"`
		Proof  string `json:"proof"`
	}{"paperboat.environment-key-enrollment-proof/v1", base64.RawURLEncoding.EncodeToString(proof[:])})
	newState := enrollmentState{Schema: stateSchema, OperationID: operationID, RequestID: response.RequestID, SafetyCode: safetyCode, ExpiresAt: expiresAt, Proof: base64.RawURLEncoding.EncodeToString(proofBody), EnrollmentRequest: response.EnrollmentRequest}
	if err := c.writeState(newState); err != nil {
		clear(proofBody)
		return err
	}
	clear(proofBody)
	return c.submitProof(ctx, newState)
}

// MarkApproved commits the local journal only after an authenticated runtime
// has verified the exact subject, installation generation, host key
// generation, recipient key ID, and endpoint certificate. It is idempotent
// and intentionally does not create state when the host was pre-approved.
func (c *Client) MarkApproved(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	state, err := c.loadState()
	if errors.Is(err, os.ErrNotExist) {
		return c.validateCurrentIdentity(ctx)
	}
	if err != nil {
		return err
	}
	current, err := c.stateMatchesCurrentIdentity(ctx, state)
	if err != nil {
		return err
	}
	if !current {
		return ErrInvalid
	}
	return c.commitApproved(state)
}

func (c *Client) validateCurrentIdentity(ctx context.Context) error {
	identity, err := identitystore.Open(identitystore.Config{StateRoot: c.config.StateRoot})
	if err != nil {
		return err
	}
	registration, err := identity.Registration()
	if err != nil || registration.SetupMode != "host" || registration.InstallationGeneration < 1 {
		return ErrInvalid
	}
	endpoint, err := identity.PeerEndpoint()
	if err != nil || len(endpoint.Certificate) == 0 || endpoint.Generation != uint64(registration.InstallationGeneration) {
		return ErrInvalid
	}
	parsed, err := endpointidentity.Parse(endpoint.Certificate)
	if err != nil {
		return ErrInvalid
	}
	verified, err := endpointidentity.Verify(endpoint.Certificate, endpoint.RootPublicKey, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, Generation: endpoint.Generation}, parsed.Claims.IssuedAt)
	if err != nil || verified.Claims.AccountID == "" {
		return ErrInvalid
	}
	material, err := c.config.Keys.Load(ctx)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if material.Generation != endpoint.Generation {
		return ErrInvalid
	}
	public, err := material.Public()
	if err != nil {
		return err
	}
	_, err = environmente2ee.KeyIDX25519(public[:])
	return err
}

func (c *Client) commitApproved(state enrollmentState) error {
	state.Proofed = true
	state.Approved = true
	state.Proof = ""
	return c.writeState(state)
}

func pendingForState(state enrollmentState) error {
	return &PendingError{RequestID: state.RequestID, SafetyCode: state.SafetyCode, ExpiresAt: state.ExpiresAt}
}

func (c *Client) stateMatchesCurrentIdentity(ctx context.Context, state enrollmentState) (bool, error) {
	raw, err := decodeBase64(state.EnrollmentRequest, -1)
	if err != nil || len(raw) > environmente2ee.MaximumEnrollmentBytes {
		clear(raw)
		return false, ErrInvalid
	}
	request, err := environmente2ee.ParseEnrollmentRequest(raw)
	clear(raw)
	if err != nil || state.ExpiresAt.Unix() != int64(request.RequestExpiresAt) || state.OperationID != "envop_"+hex.EncodeToString(request.OperationID[:]) {
		return false, ErrInvalid
	}
	identity, err := identitystore.Open(identitystore.Config{StateRoot: c.config.StateRoot})
	if err != nil {
		return false, err
	}
	registration, err := identity.Registration()
	if err != nil {
		return false, err
	}
	endpoint, err := identity.PeerEndpoint()
	if err != nil {
		return false, err
	}
	if registration.SetupMode != "host" || registration.InstallationGeneration < 1 || endpoint.Generation != uint64(registration.InstallationGeneration) || len(endpoint.Certificate) == 0 {
		return false, ErrInvalid
	}
	parsed, err := endpointidentity.Parse(endpoint.Certificate)
	if err != nil {
		return false, ErrInvalid
	}
	verified, err := endpointidentity.Verify(endpoint.Certificate, endpoint.RootPublicKey, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, Generation: endpoint.Generation}, parsed.Claims.IssuedAt)
	if err != nil {
		return false, ErrInvalid
	}
	material, err := c.config.Keys.Load(ctx)
	if err != nil {
		return false, err
	}
	defer material.Destroy()
	public, err := material.Public()
	if err != nil {
		return false, err
	}
	keyID, err := environmente2ee.KeyIDX25519(public[:])
	if err != nil {
		return false, err
	}
	return request.AccountID == verified.Claims.AccountID && request.SubjectKind == environmente2ee.SubjectHost && request.SubjectID == registration.MachineID &&
		request.SubjectGeneration == uint64(registration.InstallationGeneration) && request.KeyGeneration == material.Generation &&
		request.RecipientKeyID == keyID && bytes.Equal(request.RecipientPublic, public[:]) && bytes.Equal(request.EndpointCertificate, endpoint.Certificate), nil
}

func (c *Client) submitProof(ctx context.Context, state enrollmentState) error {
	proofBody, err := decodeBase64(state.Proof, -1)
	if err != nil || len(proofBody) > 1024 {
		clear(proofBody)
		return ErrInvalid
	}
	defer clear(proofBody)
	var pending enrollmentResponse
	if err := c.call(ctx, http.MethodPut, "/v1/environment-key-enrollments/"+url.PathEscape(state.RequestID)+"/proof", state.OperationID, proofBody, &pending); err != nil {
		return err
	}
	if pending.Schema != "paperboat.environment-key-enrollment-state/v1" || pending.State != "pending" || pending.RequestID != state.RequestID || pending.ExpiresAt != state.ExpiresAt ||
		pending.SafetyCode != state.SafetyCode || pending.EnrollmentRequest != state.EnrollmentRequest || pending.SigningProof != nil || pending.Challenge != "" {
		return ErrInvalid
	}
	state.Proofed = true
	state.Approved = false
	state.Proof = ""
	if err := c.writeState(state); err != nil {
		return err
	}
	return &PendingError{RequestID: state.RequestID, SafetyCode: state.SafetyCode, ExpiresAt: state.ExpiresAt}
}

type enrollmentResponse struct {
	Schema            string    `json:"schema"`
	RequestID         string    `json:"request_id"`
	State             string    `json:"state"`
	ExpiresAt         time.Time `json:"expires_at"`
	SafetyCode        string    `json:"safety_code"`
	EnrollmentRequest string    `json:"enrollment_request"`
	SigningProof      *string   `json:"signing_proof"`
	Challenge         string    `json:"challenge,omitempty"`
}

func (c *Client) call(ctx context.Context, method, path, operationID string, body []byte, out any) error {
	token, err := c.creds.Token(ctx)
	if err != nil {
		return err
	}
	proof, err := c.creds.Proof(ctx, operationID, method, path, body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base.ResolveReference(&url.URL{Path: path}).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Idempotency-Key", operationID)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.CopyN(io.Discard, response.Body, 8<<10)
		return ErrInvalid
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
	if err != nil || len(encoded) > 16<<10 {
		return ErrInvalid
	}
	if rejectDuplicateJSON(encoded) != nil {
		return ErrInvalid
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(envelope.Data) == 0 {
		return ErrInvalid
	}
	decoder = json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func enrollmentOperation(machineID string, generation uint64, expiresAt time.Time, public [32]byte) [16]byte {
	hash := sha256.New()
	hash.Write([]byte("paperboat-environment-host-enrollment-v1\x00"))
	hash.Write([]byte(machineID))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], generation)
	hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(expiresAt.Unix()))
	hash.Write(number[:])
	hash.Write(public[:])
	var result [16]byte
	digest := hash.Sum(nil)
	copy(result[:], digest[:16])
	return result
}

func (c *Client) statePath() string {
	return filepath.Join(c.config.StateRoot, "environment", "enrollment.json")
}

func (c *Client) loadState() (enrollmentState, error) {
	path := c.statePath()
	info, err := os.Lstat(path)
	if err != nil {
		return enrollmentState{}, err
	}
	if !secureStateFile(path, info, 4096) {
		return enrollmentState{}, ErrInvalid
	}
	body, err := os.ReadFile(path)
	if err != nil || rejectDuplicateJSON(body) != nil {
		return enrollmentState{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state enrollmentState
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validState(state) {
		return enrollmentState{}, ErrInvalid
	}
	return state, nil
}

func (c *Client) writeState(state enrollmentState) error {
	if !validState(state) {
		return ErrInvalid
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath()), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(c.statePath(), body, atomicfile.CurrentOwnerOptions(0o600))
}

func validState(state enrollmentState) bool {
	return state.Schema == stateSchema && strings.HasPrefix(state.OperationID, "envop_") && len(state.OperationID) == 6+32 &&
		state.RequestID != "" && len(state.RequestID) <= 128 && state.SafetyCode != "" && !state.ExpiresAt.IsZero() &&
		state.EnrollmentRequest != "" && (!state.Approved || state.Proofed) && (state.Proofed && state.Proof == "" || !state.Proofed && state.Proof != "")
}

func decodeBase64(value string, exact int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || exact >= 0 && len(decoded) != exact || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}

func rejectDuplicateJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
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
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
