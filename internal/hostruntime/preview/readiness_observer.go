package preview

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

const maxPreviewReadinessResponseBytes = 64 << 10

// HTTPDispatchReadinessObserver reports authenticated edge and origin
// readiness for a server-dispatched preview. The renewable machine identity
// remains in its source and is never copied into the lease or dispatch record.
type HTTPDispatchReadinessObserver struct {
	base       *url.URL
	identities TokenSource
	proofs     ProofSource
	client     *http.Client
}

type HTTPDispatchReadinessObserverConfig struct {
	ControlURL   string
	AllowedHosts []string
	Identities   TokenSource
	Proofs       ProofSource
	Transport    http.RoundTripper
	Timeout      time.Duration
}

func NewHTTPDispatchReadinessObserver(config HTTPDispatchReadinessObserverConfig) (*HTTPDispatchReadinessObserver, error) {
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	base, err := url.Parse(config.ControlURL)
	if err != nil || base.Scheme != "https" || base.User != nil || base.Hostname() == "" || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || config.Identities == nil || config.Proofs == nil {
		return nil, ErrDispatchInvalid
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return nil, ErrDispatchInvalid
	}
	allowed := false
	for _, host := range config.AllowedHosts {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(host), "."), strings.TrimSuffix(base.Hostname(), ".")) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, ErrDispatchInvalid
	}
	transport := config.Transport
	if transport == nil {
		transport = httptransport.Default()
	}
	return &HTTPDispatchReadinessObserver{
		base: base, identities: config.Identities, proofs: config.Proofs,
		client: &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDispatchInvalid }},
	}, nil
}

func (o *HTTPDispatchReadinessObserver) ObservePreviewReadiness(ctx context.Context, metadata DispatchReadiness, lease Lease, expectedGeneration int64) (Lease, error) {
	if o == nil || ctx == nil || expectedGeneration < 1 || metadata.OperationID == "" || metadata.IdempotencyKey == "" || metadata.RequestID == "" || metadata.CorrelationID == "" || lease.ID == "" || lease.OwnerDeviceID == "" || lease.OwnerSessionID == "" || lease.ETag == "" || leaseGenerationForID(lease.ID, lease.ETag) != expectedGeneration {
		return Lease{}, ErrDispatchInvalid
	}
	body, err := json.Marshal(struct {
		OwnerDeviceID   string `json:"owner_device_id"`
		OwnerSessionID  string `json:"owner_session_id"`
		AllocationState string `json:"allocation_state"`
		EdgeState       string `json:"edge_state"`
		OriginState     string `json:"origin_state"`
	}{lease.OwnerDeviceID, lease.OwnerSessionID, "ready", "ready", "ready"})
	if err != nil {
		return Lease{}, errors.Join(ErrDispatchInvalid, err)
	}
	path := "/v1/previews/" + url.PathEscape(lease.ID) + "/readiness"
	identity, err := o.identities.Token(ctx)
	if err != nil || identity == "" || len(identity) > 16<<10 {
		return Lease{}, errors.Join(ErrDispatchUnavailable, err)
	}
	proof, err := o.proofs.Proof(ctx, metadata.OperationID, http.MethodPost, path, body)
	if err != nil || len(proof) == 0 || len(proof) > 16<<10 {
		return Lease{}, errors.Join(ErrDispatchUnavailable, err)
	}
	endpoint := *o.base
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Lease{}, errors.Join(ErrDispatchInvalid, err)
	}
	request.Header.Set("Authorization", "Bearer "+identity)
	request.Header.Set("X-Paperboat-Machine-Identity", identity)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("If-Match", lease.ETag)
	request.Header.Set("Idempotency-Key", metadata.OperationID)
	request.Header.Set("Request-Id", metadata.RequestID)
	request.Header.Set("Correlation-Id", metadata.CorrelationID)
	response, err := o.client.Do(request)
	if err != nil {
		return Lease{}, errors.Join(ErrDispatchUnavailable, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxPreviewReadinessResponseBytes+1))
	if err != nil || len(data) > maxPreviewReadinessResponseBytes {
		return Lease{}, errors.Join(ErrDispatchUnavailable, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusPreconditionFailed {
			return Lease{}, fmt.Errorf("%w: readiness status %d", ErrDispatchConflict, response.StatusCode)
		}
		if response.StatusCode >= 500 {
			return Lease{}, fmt.Errorf("%w: readiness status %d", ErrDispatchUnavailable, response.StatusCode)
		}
		return Lease{}, fmt.Errorf("%w: readiness status %d", ErrDispatchInvalid, response.StatusCode)
	}
	if err := rejectPreviewReadinessDuplicateKeys(data); err != nil {
		return Lease{}, fmt.Errorf("%w: readiness response JSON: %v", ErrDispatchInvalid, err)
	}
	var envelope struct {
		Data api.PreviewLease `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Lease{}, fmt.Errorf("%w: readiness response: %v", ErrDispatchInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Lease{}, fmt.Errorf("%w: readiness response has trailing data", ErrDispatchInvalid)
	}
	envelope.Data.ETag = strings.TrimSpace(response.Header.Get("ETag"))
	observed := leaseFromAPI(envelope.Data)
	if observed.Generation < 1 {
		return Lease{}, fmt.Errorf("%w: readiness response ETag is invalid", ErrDispatchInvalid)
	}
	return observed, nil
}

func rejectPreviewReadinessDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
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
					return ErrDispatchInvalid
				}
				if _, exists := seen[key]; exists {
					return ErrDispatchInvalid
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
			return ErrDispatchInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrDispatchInvalid
	}
	return nil
}

var _ DispatchReadinessObserver = (*HTTPDispatchReadinessObserver)(nil)
