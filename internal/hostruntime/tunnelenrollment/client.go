package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

const serverResponseLimit = 64 << 10

type serverClient struct {
	base *url.URL
	auth MachineAuth
	http *http.Client
}

func newServerClient(raw string, auth MachineAuth, transport http.RoundTripper) (*serverClient, error) {
	base, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || auth == nil {
		return nil, ErrInvalid
	}
	return &serverClient{base: base, auth: auth, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}}, nil
}
func (c *serverClient) issue(ctx context.Context, tunnel, host, key string) (serverEnrollment, error) {
	path := "/v1/tunnels/" + url.PathEscape(tunnel) + "/connectors/enrollments"
	body, _ := json.Marshal(struct {
		HostID       string   `json:"host_id"`
		Capabilities []string `json:"capabilities"`
		TTL          int      `json:"ttl_seconds"`
	}{host, []string{"connector-v1", "data-carrier-v1", "credential-rotation-v1"}, 300})
	var out serverEnrollment
	status, err := c.do(ctx, http.MethodPost, path, key, body, &out)
	if err != nil {
		return out, err
	}
	if status != http.StatusCreated && status != http.StatusOK || out.Schema != api.TunnelV1Schema || out.Kind != "connector_enrollment" || out.TunnelID != tunnel || out.HostID != host || out.ID == "" || len(out.Token) < 32 || !out.ExpiresAt.After(time.Now().UTC()) || out.Replayed {
		return serverEnrollment{}, ErrUnavailable
	}
	return out, nil
}
func (c *serverClient) exchange(ctx context.Context, tunnel, host, key, token string, credential Credential, store CredentialStore) (serverActivation, error) {
	payload := connectorCredentialProofPayload(tunnel, host, token, credential.Reference, credential.Thumbprint, key)
	proof, err := store.Sign(ctx, credential.Reference, payload)
	if err != nil {
		return serverActivation{}, err
	}
	body, err := json.Marshal(struct {
		Token                       string `json:"enrollment_token"`
		HostID                      string `json:"host_id"`
		ProtocolVersion             string `json:"protocol_version"`
		SoftwareVersion             string `json:"software_version"`
		CredentialReference         string `json:"credential_reference"`
		CredentialThumbprint        string `json:"credential_thumbprint"`
		CredentialVerifierAlgorithm string `json:"credential_verifier_algorithm"`
		CredentialVerifierPublicKey string `json:"credential_verifier_public_key"`
		CredentialProof             string `json:"credential_proof"`
		OperatingSystem             string `json:"operating_system"`
		Architecture                string `json:"architecture"`
	}{token, host, "1.0", buildinfo.Version, credential.Reference, credential.Thumbprint, "ed25519", base64.RawURLEncoding.EncodeToString(credential.PublicKey), base64.RawURLEncoding.EncodeToString(proof), runtime.GOOS, runtime.GOARCH})
	if err != nil {
		return serverActivation{}, err
	}
	path := "/v1/tunnels/" + url.PathEscape(tunnel) + "/connectors/enrollments/exchange"
	var out serverActivation
	status, err := c.do(ctx, http.MethodPost, path, key, body, &out)
	if err != nil {
		return out, err
	}
	if status != http.StatusAccepted || out.Schema != api.TunnelV1Schema || out.Kind != "connector_activation" || connectorprotocol.ValidateIdentifier(out.AccountID) != nil || out.TunnelID != tunnel || out.HostID != host || out.ConnectorID == "" || hoststate.ValidateStableEndpointID(out.StableEndpointID) != nil || out.CredentialGeneration == 0 || out.ProcessGeneration == 0 || out.Operation.Schema != api.TunnelV1Schema || out.Operation.Kind != "operation" || out.Operation.ResourceKind != "connector" || out.Operation.ResourceID != out.ConnectorID || out.Operation.ID == "" || out.Operation.State != "running" || out.Operation.Phase != "connecting" {
		return serverActivation{}, ErrUnavailable
	}
	return out, nil
}
func (c *serverClient) do(ctx context.Context, method, path, key string, body []byte, out any) (int, error) {
	if ctx == nil || !safeID(key) || len(body) == 0 {
		return 0, ErrInvalid
	}
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + path
	endpoint.RawPath = ""
	token, err := c.auth.Token(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return 0, ErrAuthentication
	}
	proof, err := c.auth.Proof(ctx, key, method, endpoint.Path, body)
	if err != nil || len(proof) == 0 {
		return 0, ErrAuthentication
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Paperboat-Machine-Identity", token)
	req.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, errors.Join(ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, serverResponseLimit+1))
	if readErr != nil || len(raw) > serverResponseLimit {
		return resp.StatusCode, ErrUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return resp.StatusCode, ErrAuthentication
		case http.StatusForbidden:
			return resp.StatusCode, ErrForbidden
		case http.StatusConflict, http.StatusGone:
			return resp.StatusCode, ErrConflict
		default:
			return resp.StatusCode, ErrUnavailable
		}
	}
	if rejectDuplicateJSON(raw) != nil {
		return resp.StatusCode, ErrUnavailable
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&envelope) != nil || dec.Decode(&struct{}{}) != io.EOF || len(envelope.Data) == 0 {
		return resp.StatusCode, ErrUnavailable
	}
	dec = json.NewDecoder(bytes.NewReader(envelope.Data))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return resp.StatusCode, ErrUnavailable
	}
	return resp.StatusCode, nil
}

// Keep the transcript byte-identical with paperboat-server tunnelv1.
func connectorCredentialProofPayload(tunnel, host, token, reference, thumbprint, key string) []byte {
	digest := sha256.Sum256([]byte(token))
	canonical := struct {
		Purpose               string `json:"purpose"`
		TunnelID              string `json:"tunnel_id"`
		HostID                string `json:"host_id"`
		EnrollmentTokenSHA256 string `json:"enrollment_token_sha256"`
		CredentialReference   string `json:"credential_reference"`
		CredentialThumbprint  string `json:"credential_thumbprint"`
		IdempotencyKey        string `json:"idempotency_key"`
	}{"paperboat.connector.enrollment.v1", tunnel, host, hex.EncodeToString(digest[:]), reference, thumbprint, key}
	encoded, _ := json.Marshal(canonical)
	return encoded
}
