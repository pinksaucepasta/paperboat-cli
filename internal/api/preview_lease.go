package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// PreviewTunnelSchemaV1 is the sole wire schema used by foreground previews.
const PreviewTunnelSchemaV1 = "paperboat.preview-tunnel/v1"

// PreviewLeaseTarget is the origin address owned by a preview lease.
type PreviewLeaseTarget struct {
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
}

// PreviewLease is the safe server projection of a temporary preview lease.
// It deliberately contains no carrier credential or reusable secret.
type PreviewLease struct {
	Schema          string                 `json:"schema"`
	Kind            string                 `json:"kind"`
	ID              string                 `json:"id"`
	AccountID       string                 `json:"account_id"`
	ActorID         string                 `json:"actor_id"`
	OwnerDeviceID   string                 `json:"owner_device_id"`
	OwnerSessionID  string                 `json:"owner_session_id"`
	Target          PreviewLeaseTarget     `json:"target"`
	AccessMode      string                 `json:"access_mode"`
	Persistent      bool                   `json:"persistent"`
	Endpoint        string                 `json:"endpoint"`
	LeaseDeadline   time.Time              `json:"lease_deadline"`
	UserDeadline    *time.Time             `json:"user_deadline"`
	State           string                 `json:"state"`
	AllocationState string                 `json:"allocation_state"`
	EdgeState       string                 `json:"edge_state"`
	OriginState     string                 `json:"origin_state"`
	CreatedAt       time.Time              `json:"created_at"`
	LastRenewedAt   time.Time              `json:"last_renewed_at"`
	Domains         []PreviewDomainSummary `json:"domains,omitempty"`

	// CreateOperationID is transport-only metadata retained from the
	// server's create operation. It is required when a host later requests a
	// carrier attachment, but is never exposed in the preview resource JSON.
	CreateOperationID string `json:"-"`

	// ETag is transport metadata returned in the HTTP response header. It is
	// not serialized into the preview resource.
	ETag string `json:"-"`
}

// PreviewLeaseCreateRequest is the canonical POST /v1/previews payload.
// Hostname allocation is server-owned; callers cannot request a vanity name.
type PreviewLeaseCreateRequest struct {
	OwnerDeviceID  string             `json:"owner_device_id"`
	OwnerSessionID string             `json:"owner_session_id"`
	Target         PreviewLeaseTarget `json:"target"`
	AccessMode     string             `json:"access_mode,omitempty"`
	ExpiresAt      *time.Time         `json:"expires_at,omitempty"`
	Domains        []string           `json:"domains"`
}

// MaxPreviewDomains bounds the number of aliases that can be attached to one
// temporary preview. The server remains authoritative for domain allocation;
// this bound keeps request and read projections small and deterministic.
const MaxPreviewDomains = 8

// PreviewDomainSummary is the safe domain projection nested in a preview
// lease. A preview domain is deliberately target-discriminated: it can never
// also identify a durable tunnel route.
type PreviewDomainSummary struct {
	ID             string                   `json:"id"`
	TargetKind     string                   `json:"target_kind"`
	PreviewID      string                   `json:"preview_id"`
	Hostname       string                   `json:"hostname"`
	MatchType      string                   `json:"match_type"`
	WildcardLabels *int                     `json:"wildcard_labels,omitempty"`
	State          string                   `json:"state"`
	DNS            PreviewDomainDNS         `json:"dns"`
	Certificate    PreviewDomainCertificate `json:"certificate"`
	Generation     int64                    `json:"generation"`
	ETag           string                   `json:"etag"`
	Instructions   *PreviewDNSInstructions  `json:"instructions,omitempty"`
}

type PreviewDomainDNS struct {
	Target          string     `json:"target"`
	ObservedRecords []string   `json:"observed_records,omitempty"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
}

type PreviewDomainCertificate struct {
	State     string         `json:"state"`
	Reference string         `json:"reference,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Failure   map[string]any `json:"failure,omitempty"`
}

type PreviewDNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// PreviewDNSInstructions contains customer-actionable records only. It never
// carries a challenge token, credential, or private key.
type PreviewDNSInstructions struct {
	Schema              string             `json:"schema"`
	Kind                string             `json:"kind"`
	TargetKind          string             `json:"target_kind"`
	PreviewID           string             `json:"preview_id"`
	DomainID            string             `json:"domain_id"`
	Hostname            string             `json:"hostname"`
	Provider            string             `json:"provider"`
	Records             []PreviewDNSRecord `json:"records"`
	CertificateStrategy string             `json:"certificate_strategy"`
	VerificationState   string             `json:"verification_state"`
	Note                string             `json:"note"`
}

// PreviewLeaseOperation is returned when lease creation is still progressing.
// Creation itself is synchronous with respect to the lease identity, so the
// client follows ResourceID and fetches the lease before starting a carrier.
type PreviewLeaseOperation struct {
	Schema        string                 `json:"schema"`
	Kind          string                 `json:"kind"`
	ID            string                 `json:"id"`
	ResourceKind  string                 `json:"resource_kind"`
	ResourceID    string                 `json:"resource_id"`
	Phase         string                 `json:"phase"`
	State         string                 `json:"state"`
	Progress      int                    `json:"progress"`
	Retrying      bool                   `json:"retrying"`
	NextRetryAt   *time.Time             `json:"next_retry_at,omitempty"`
	Error         *PreviewTunnelAPIError `json:"error,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// PreviewTunnelAPIError is the safe typed error carried by v1 operations.
type PreviewTunnelAPIError struct {
	Schema        string     `json:"schema"`
	Kind          string     `json:"kind"`
	Code          string     `json:"code"`
	Component     string     `json:"component"`
	Message       string     `json:"message"`
	Outcome       string     `json:"outcome"`
	Retryable     bool       `json:"retryable"`
	RetryAt       *time.Time `json:"retry_at,omitempty"`
	RepairAction  string     `json:"repair_action,omitempty"`
	RequestID     string     `json:"request_id"`
	CorrelationID string     `json:"correlation_id"`
}

var (
	ErrPreviewLeaseInvalid      = errors.New("invalid preview lease")
	ErrPreviewLeaseETagRequired = errors.New("preview lease ETag is required")
)

type previewLeaseCreateResponse struct {
	Lease     *PreviewLease
	Operation *PreviewLeaseOperation
}

// UnmarshalJSON accepts the v1 response union without weakening the strict
// envelope decoding used by Client.doRequestMeta.
func (r *previewLeaseCreateResponse) UnmarshalJSON(raw []byte) error {
	var discriminator struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil {
		return err
	}
	switch discriminator.Kind {
	case "preview_lease":
		var lease PreviewLease
		if err := decodePreviewLeaseStrict(raw, &lease); err != nil {
			return err
		}
		r.Lease = &lease
	case "operation":
		var operation PreviewLeaseOperation
		if err := decodePreviewLeaseStrict(raw, &operation); err != nil {
			return err
		}
		r.Operation = &operation
	default:
		return fmt.Errorf("%w: unexpected response kind %q", ErrPreviewLeaseInvalid, discriminator.Kind)
	}
	return nil
}

func decodePreviewLeaseStrict(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing response data", ErrPreviewLeaseInvalid)
	}
	return nil
}

// NewPreviewLeaseIdempotencyKey creates an opaque key suitable for one v1
// lease mutation. It carries no credential and is safe to log as metadata.
func NewPreviewLeaseIdempotencyKey() (string, error) {
	bytes := make([]byte, 18)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "preview_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

// CreatePreviewLease creates a lease and fetches the resource when the server
// initially responds with a resumable operation. The returned endpoint is
// still unpublished to users until the host carrier reports readiness.
func (c *Client) CreatePreviewLease(ctx context.Context, input PreviewLeaseCreateRequest, idempotencyKey string) (PreviewLease, error) {
	if err := validatePreviewLeaseIdempotencyKey(idempotencyKey); err != nil {
		return PreviewLease{}, err
	}
	input.OwnerDeviceID = strings.TrimSpace(input.OwnerDeviceID)
	input.OwnerSessionID = strings.TrimSpace(input.OwnerSessionID)
	input.Target.Scheme = strings.ToLower(strings.TrimSpace(input.Target.Scheme))
	input.Target.Address = strings.TrimSpace(input.Target.Address)
	input.AccessMode = strings.ToLower(strings.TrimSpace(input.AccessMode))
	domains, err := NormalizePreviewDomains(input.Domains)
	if err != nil {
		return PreviewLease{}, err
	}
	input.Domains = domains
	if err := validatePreviewLeaseCreateInput(input); err != nil {
		return PreviewLease{}, err
	}
	var response previewLeaseCreateResponse
	var headers http.Header
	err = c.doRequestMeta(ctx, http.MethodPost, "/v1/previews", input, &response, http.Header{
		"Idempotency-Key": []string{idempotencyKey},
		// The control plane's ETag is a strong OCC token. Explicitly request
		// the identity representation so an intermediary compression layer
		// cannot rewrite or remove that validator.
		"Accept-Encoding": []string{"identity"},
	}, true, &headers)
	if err != nil {
		return PreviewLease{}, err
	}
	createOperationID := strings.TrimSpace(headers.Get("X-Paperboat-Operation-ID"))
	if !validPreviewID(createOperationID) {
		return PreviewLease{}, fmt.Errorf("%w: create response has no valid operation ID", ErrPreviewLeaseInvalid)
	}
	if response.Lease != nil {
		response.Lease.CreateOperationID = createOperationID
		response.Lease.ETag = strings.TrimSpace(headers.Get("ETag"))
		if err := validatePreviewLease(*response.Lease); err != nil {
			return PreviewLease{}, err
		}
		if err := validateRequestedPreviewDomains(input.Domains, *response.Lease); err != nil {
			return PreviewLease{}, err
		}
		if _, err := previewLeaseETag(response.Lease.ID, response.Lease.ETag); err != nil {
			return PreviewLease{}, err
		}
		return *response.Lease, nil
	}
	if response.Operation == nil || validatePreviewLeaseOperation(*response.Operation) != nil {
		return PreviewLease{}, fmt.Errorf("%w: create response has neither lease nor resource operation", ErrPreviewLeaseInvalid)
	}
	if response.Operation.ID != createOperationID {
		return PreviewLease{}, fmt.Errorf("%w: create operation header does not match response", ErrPreviewLeaseInvalid)
	}
	if c.machineAuth != nil && strings.TrimSpace(c.accessToken) == "" {
		return PreviewLease{}, ErrMachineAuthReadRequiresClientSession
	}
	lease, err := c.GetPreviewLease(ctx, response.Operation.ResourceID)
	if err != nil {
		return PreviewLease{}, fmt.Errorf("fetch preview lease after operation %s: %w", response.Operation.ID, err)
	}
	lease.CreateOperationID = response.Operation.ID
	if err := validateRequestedPreviewDomains(input.Domains, lease); err != nil {
		return PreviewLease{}, err
	}
	return lease, nil
}

// GetPreviewLease returns the current safe lease projection and its strong
// ETag, which must be sent on every subsequent mutation.
func (c *Client) GetPreviewLease(ctx context.Context, previewID string) (PreviewLease, error) {
	if strings.TrimSpace(previewID) == "" {
		return PreviewLease{}, fmt.Errorf("%w: preview ID is required", ErrPreviewLeaseInvalid)
	}
	var lease PreviewLease
	var headers http.Header
	path := "/v1/previews/" + url.PathEscape(previewID)
	if err := c.doRequestMeta(ctx, http.MethodGet, path, nil, &lease, http.Header{
		// A strong ETag describes the exact representation used for OCC. Do
		// not let a proxy's response encoder transform this representation.
		"Accept-Encoding": []string{"identity"},
	}, true, &headers); err != nil {
		return PreviewLease{}, err
	}
	lease.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validatePreviewLease(lease); err != nil {
		return PreviewLease{}, err
	}
	if lease.ID != previewID {
		return PreviewLease{}, fmt.Errorf("%w: response ID does not match requested preview", ErrPreviewLeaseInvalid)
	}
	if _, err := previewLeaseETag(lease.ID, lease.ETag); err != nil {
		return PreviewLease{}, fmt.Errorf("%w (received %q)", err, lease.ETag)
	}
	return lease, nil
}

// RenewPreviewLease extends a live lease while preserving its server-owned
// endpoint and identity.
func (c *Client) RenewPreviewLease(ctx context.Context, lease PreviewLease, ownerSessionID, idempotencyKey string) (PreviewLease, error) {
	if err := validateMutationLease(lease, idempotencyKey); err != nil {
		return PreviewLease{}, err
	}
	if strings.TrimSpace(ownerSessionID) == "" {
		return PreviewLease{}, fmt.Errorf("%w: owner session is required", ErrPreviewLeaseInvalid)
	}
	var renewed PreviewLease
	var headers http.Header
	path := "/v1/previews/" + url.PathEscape(lease.ID) + "/lease/renew"
	err := c.doRequestMeta(ctx, http.MethodPost, path, struct {
		OwnerSessionID string `json:"owner_session_id"`
	}{OwnerSessionID: ownerSessionID}, &renewed, http.Header{
		"If-Match":        []string{lease.ETag},
		"Idempotency-Key": []string{idempotencyKey},
		"Accept-Encoding": []string{"identity"},
	}, true, &headers)
	if err != nil {
		return PreviewLease{}, err
	}
	renewed.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validatePreviewLease(renewed); err != nil {
		return PreviewLease{}, err
	}
	if _, err := previewLeaseETag(renewed.ID, renewed.ETag); err != nil {
		return PreviewLease{}, err
	}
	if renewed.ID != lease.ID || renewed.Endpoint != lease.Endpoint {
		return PreviewLease{}, fmt.Errorf("%w: renewal changed lease identity or endpoint", ErrPreviewLeaseInvalid)
	}
	return renewed, nil
}

// StopPreviewLease revokes the lease. Stop is intentionally idempotent at the
// server; callers must reuse one idempotency key across retries.
func (c *Client) StopPreviewLease(ctx context.Context, lease PreviewLease, idempotencyKey string) (PreviewLease, error) {
	if err := validateMutationLease(lease, idempotencyKey); err != nil {
		return PreviewLease{}, err
	}
	var stopped PreviewLease
	var headers http.Header
	path := "/v1/previews/" + url.PathEscape(lease.ID)
	err := c.doRequestMeta(ctx, http.MethodDelete, path, nil, &stopped, http.Header{
		"If-Match":        []string{lease.ETag},
		"Idempotency-Key": []string{idempotencyKey},
		"Accept-Encoding": []string{"identity"},
	}, true, &headers)
	if err != nil {
		return PreviewLease{}, err
	}
	stopped.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validatePreviewLease(stopped); err != nil {
		return PreviewLease{}, err
	}
	if _, err := previewLeaseETag(stopped.ID, stopped.ETag); err != nil {
		return PreviewLease{}, err
	}
	if stopped.ID != lease.ID || stopped.Endpoint != lease.Endpoint {
		return PreviewLease{}, fmt.Errorf("%w: stop changed lease identity or endpoint", ErrPreviewLeaseInvalid)
	}
	return stopped, nil
}

// PreviewLeasePage is the keyset-paginated response for GET /v1/previews.
// Items are complete canonical preview_lease resources; the cursor is an
// opaque server value and must only be replayed for the same account.
type PreviewLeasePage struct {
	Items      []PreviewLease `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

// ListPreviewLeases returns one bounded page of temporary preview leases.
// The API owns cursor semantics, so the CLI never decodes or manufactures a
// cursor. A zero limit uses the protocol default; callers cannot request an
// unbounded response.
func (c *Client) ListPreviewLeases(ctx context.Context, cursor string, limit int) (PreviewLeasePage, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 200 {
		return PreviewLeasePage{}, fmt.Errorf("%w: preview page limit must be between 1 and 200", ErrPreviewLeaseInvalid)
	}
	values := url.Values{"limit": []string{strconv.Itoa(limit)}}
	if strings.TrimSpace(cursor) != "" {
		cursor = strings.TrimSpace(cursor)
		if len(cursor) > 4096 || strings.ContainsAny(cursor, "\r\n") {
			return PreviewLeasePage{}, fmt.Errorf("%w: preview cursor is invalid", ErrPreviewLeaseInvalid)
		}
		values.Set("cursor", cursor)
	}
	var page PreviewLeasePage
	path := "/v1/previews?" + values.Encode()
	if err := c.doStrict(ctx, http.MethodGet, path, nil, &page); err != nil {
		return PreviewLeasePage{}, err
	}
	if len(page.Items) > limit {
		return PreviewLeasePage{}, fmt.Errorf("%w: preview page exceeds requested limit", ErrPreviewLeaseInvalid)
	}
	if len(page.NextCursor) > 4096 || strings.ContainsAny(page.NextCursor, "\r\n") {
		return PreviewLeasePage{}, fmt.Errorf("%w: preview next cursor is invalid", ErrPreviewLeaseInvalid)
	}
	seen := make(map[string]struct{}, len(page.Items))
	for index := range page.Items {
		item := page.Items[index]
		if err := validatePreviewLease(item); err != nil {
			return PreviewLeasePage{}, fmt.Errorf("%w: invalid preview at index %d: %v", ErrPreviewLeaseInvalid, index, err)
		}
		if _, ok := seen[item.ID]; ok {
			return PreviewLeasePage{}, fmt.Errorf("%w: duplicate preview %q", ErrPreviewLeaseInvalid, item.ID)
		}
		seen[item.ID] = struct{}{}
	}
	return page, nil
}

// NormalizePreviewDomains converts user-supplied exact, apex, and one-label
// wildcard names into the canonical lower-case IDNA ASCII form. It sorts the
// result and rejects duplicate names after normalization, so the same request
// always has the same JSON and idempotency hash.
func NormalizePreviewDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		// The v1 wire contract requires an explicit array. Returning a
		// non-nil empty slice prevents ordinary previews from silently
		// omitting the field and being rejected by the server.
		return []string{}, nil
	}
	if len(domains) > MaxPreviewDomains {
		return nil, fmt.Errorf("%w: at most %d domains are allowed", ErrPreviewLeaseInvalid, MaxPreviewDomains)
	}
	result := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		name, err := NormalizePreviewDomain(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("%w: duplicate domain %q", ErrPreviewLeaseInvalid, name)
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// NormalizePreviewDomain validates one exact/apex or one-label wildcard
// hostname. A wildcard is allowed only as the complete first label. IP
// literals, ports, URL syntax, recursive wildcards, and local names are not
// preview domains because they cannot be verified as public DNS aliases.
func NormalizePreviewDomain(raw string) (string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" || len(raw) > 253 || strings.ContainsAny(raw, "\r\n\x00 /?#:@") {
		return "", fmt.Errorf("%w: domain %q is invalid", ErrPreviewLeaseInvalid, raw)
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("%w: domain %q contains whitespace or control characters", ErrPreviewLeaseInvalid, raw)
		}
	}
	wildcard := strings.HasPrefix(raw, "*.")
	value := raw
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
		if value == "" || strings.Contains(value, "*") {
			return "", fmt.Errorf("%w: wildcard domain %q is invalid", ErrPreviewLeaseInvalid, raw)
		}
	} else if strings.Contains(raw, "*") {
		return "", fmt.Errorf("%w: wildcard must be the first label in %q", ErrPreviewLeaseInvalid, raw)
	}
	value = strings.TrimSuffix(value, ".")
	if net.ParseIP(value) != nil {
		return "", fmt.Errorf("%w: IP literals are not domains", ErrPreviewLeaseInvalid)
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > 253 || strings.Contains(ascii, "..") {
		return "", fmt.Errorf("%w: domain %q is not valid IDNA", ErrPreviewLeaseInvalid, raw)
	}
	ascii = strings.ToLower(ascii)
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: domain %q must contain a DNS suffix", ErrPreviewLeaseInvalid, raw)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: domain %q has an invalid label", ErrPreviewLeaseInvalid, raw)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("%w: domain %q has an invalid label", ErrPreviewLeaseInvalid, raw)
			}
		}
	}
	if wildcard {
		if len(ascii)+2 > 253 {
			return "", fmt.Errorf("%w: wildcard domain %q is too long", ErrPreviewLeaseInvalid, raw)
		}
		return "*." + ascii, nil
	}
	return ascii, nil
}

func validateRequestedPreviewDomains(requested []string, lease PreviewLease) error {
	canonical, err := NormalizePreviewDomains(requested)
	if err != nil {
		return err
	}
	if len(canonical) == 0 {
		return nil
	}
	if len(lease.Domains) != len(canonical) {
		return fmt.Errorf("%w: server returned %d domains for %d requested domains", ErrPreviewLeaseInvalid, len(lease.Domains), len(canonical))
	}
	seen := make(map[string]struct{}, len(lease.Domains))
	for _, domain := range lease.Domains {
		if _, ok := seen[domain.Hostname]; ok {
			return fmt.Errorf("%w: server returned duplicate domain %q", ErrPreviewLeaseInvalid, domain.Hostname)
		}
		seen[domain.Hostname] = struct{}{}
	}
	for _, want := range canonical {
		found := false
		for _, domain := range lease.Domains {
			if domain.Hostname == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: server omitted requested domain %q", ErrPreviewLeaseInvalid, want)
		}
	}
	return nil
}

func validatePreviewDomainSummaries(lease PreviewLease) error {
	if len(lease.Domains) > MaxPreviewDomains {
		return fmt.Errorf("%w: lease contains too many domains", ErrPreviewLeaseInvalid)
	}
	seenIDs := make(map[string]struct{}, len(lease.Domains))
	seenHosts := make(map[string]struct{}, len(lease.Domains))
	for index, domain := range lease.Domains {
		if err := validatePreviewDomainSummary(lease, domain); err != nil {
			return fmt.Errorf("%w: invalid domain at index %d: %v", ErrPreviewLeaseInvalid, index, err)
		}
		if _, ok := seenIDs[domain.ID]; ok {
			return fmt.Errorf("%w: duplicate domain ID %q", ErrPreviewLeaseInvalid, domain.ID)
		}
		if _, ok := seenHosts[domain.Hostname]; ok {
			return fmt.Errorf("%w: duplicate domain hostname %q", ErrPreviewLeaseInvalid, domain.Hostname)
		}
		seenIDs[domain.ID] = struct{}{}
		seenHosts[domain.Hostname] = struct{}{}
	}
	return nil
}

func validatePreviewDomainSummary(lease PreviewLease, domain PreviewDomainSummary) error {
	if !validPreviewID(domain.ID) || domain.TargetKind != "preview_lease" || domain.PreviewID != lease.ID {
		return errors.New("domain target binding is invalid")
	}
	canonical, err := NormalizePreviewDomain(domain.Hostname)
	if err != nil || canonical != domain.Hostname {
		return errors.New("domain hostname is not canonical")
	}
	switch domain.MatchType {
	case "exact":
		if strings.HasPrefix(domain.Hostname, "*.") || domain.WildcardLabels != nil {
			return errors.New("exact domain cannot have wildcard labels")
		}
	case "one_label_wildcard":
		if !strings.HasPrefix(domain.Hostname, "*.") || domain.WildcardLabels == nil || *domain.WildcardLabels != 1 {
			return errors.New("one-label wildcard domain is invalid")
		}
	default:
		return errors.New("domain match type is invalid")
	}
	if !validatePreviewDomainState(domain.State) || domain.Generation < 1 {
		return errors.New("domain state or generation is invalid")
	}
	if err := validatePreviewDomainDNS(domain.DNS); err != nil {
		return err
	}
	if err := validatePreviewDomainCertificate(domain.Certificate); err != nil {
		return err
	}
	if err := validatePreviewResourceETag(domain.ETag); err != nil {
		return err
	}
	if domain.Instructions != nil {
		if err := validatePreviewDNSInstructions(lease, domain, *domain.Instructions); err != nil {
			return err
		}
	}
	return nil
}

func validatePreviewDomainDNS(dns PreviewDomainDNS) error {
	if strings.TrimSpace(dns.Target) == "" || len(dns.Target) > 253 || strings.ContainsAny(dns.Target, "\r\n\x00") {
		return errors.New("domain DNS target is invalid")
	}
	if len(dns.ObservedRecords) > 32 {
		return errors.New("domain DNS observations exceed the limit")
	}
	for _, record := range dns.ObservedRecords {
		if strings.TrimSpace(record) == "" || len(record) > 253 || strings.ContainsAny(record, "\r\n\x00") {
			return errors.New("domain DNS observation is invalid")
		}
	}
	if dns.LastCheckedAt != nil && dns.LastCheckedAt.IsZero() {
		return errors.New("domain DNS check time is invalid")
	}
	return nil
}

func validatePreviewDomainCertificate(certificate PreviewDomainCertificate) error {
	switch certificate.State {
	case "not_requested", "issuing", "ready", "renewing", "failed", "expired", "revoked":
	default:
		return errors.New("domain certificate state is invalid")
	}
	if certificate.Reference != "" && (len(certificate.Reference) > 512 || strings.ContainsAny(certificate.Reference, "\r\n\x00") || strings.Contains(certificate.Reference, "-----BEGIN")) {
		return errors.New("domain certificate reference is invalid")
	}
	if certificate.ExpiresAt != nil && certificate.ExpiresAt.IsZero() {
		return errors.New("domain certificate expiry is invalid")
	}
	return validatePreviewSafeObject(certificate.Failure, 0)
}

func validatePreviewDNSInstructions(lease PreviewLease, domain PreviewDomainSummary, instructions PreviewDNSInstructions) error {
	if instructions.Schema != PreviewTunnelSchemaV1 || instructions.Kind != "dns_instructions" || instructions.TargetKind != "preview_lease" || instructions.PreviewID != lease.ID || instructions.DomainID != domain.ID || instructions.Hostname != domain.Hostname || strings.TrimSpace(instructions.Provider) == "" || len(instructions.Provider) > 64 || strings.TrimSpace(instructions.Note) == "" || len(instructions.Note) > 512 || strings.ContainsAny(instructions.Note, "\r\n\x00") {
		return errors.New("domain DNS instructions binding is invalid")
	}
	switch instructions.VerificationState {
	case "requested", "waiting_dns", "verified", "issuing_tls", "ready", "conflict", "dns_error", "tls_error", "expired", "quarantined":
	default:
		return errors.New("domain DNS instruction state is invalid")
	}
	if len(instructions.Records) == 0 || len(instructions.Records) > 8 {
		return errors.New("domain DNS instruction records are invalid")
	}
	for _, record := range instructions.Records {
		if record.Type != "CNAME" || record.TTL < 30 || record.TTL > 86400 || len(record.Name) == 0 || len(record.Name) > 253 || len(record.Value) == 0 || len(record.Value) > 253 || strings.ContainsAny(record.Name+record.Value, "\r\n\x00") {
			return errors.New("domain DNS instruction record is invalid")
		}
	}
	return nil
}

func validatePreviewResourceETag(etag string) error {
	if len(etag) < 3 || len(etag) > 512 || etag[0] != '"' || etag[len(etag)-1] != '"' || strings.ContainsAny(etag[1:len(etag)-1], "\r\n\x00\"") {
		return errors.New("domain ETag is not strong")
	}
	return nil
}

func validatePreviewDomainState(value string) bool {
	switch value {
	case "requested", "waiting_dns", "verified", "issuing_tls", "ready", "conflict", "dns_error", "tls_error", "expired", "quarantined", "released":
		return true
	default:
		return false
	}
}

func validatePreviewSafeObject(value map[string]any, depth int) error {
	if value == nil {
		return nil
	}
	if depth > 4 || len(value) > 32 {
		return errors.New("domain failure metadata exceeds the limit")
	}
	for key, item := range value {
		if strings.TrimSpace(key) == "" || len(key) > 64 || strings.ContainsAny(key, "\r\n\x00") || strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "private") || strings.Contains(strings.ToLower(key), "authorization") || strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "cookie") {
			return errors.New("domain failure metadata contains a secret field")
		}
		switch typed := item.(type) {
		case string:
			if len(typed) > 500 || strings.ContainsAny(typed, "\r\n\x00") {
				return errors.New("domain failure metadata string is invalid")
			}
		case map[string]any:
			if err := validatePreviewSafeObject(typed, depth+1); err != nil {
				return err
			}
		case []any:
			if len(typed) > 32 {
				return errors.New("domain failure metadata array exceeds the limit")
			}
			for _, child := range typed {
				if nested, ok := child.(map[string]any); ok {
					if err := validatePreviewSafeObject(nested, depth+1); err != nil {
						return err
					}
				} else if text, ok := child.(string); ok && (len(text) > 500 || strings.ContainsAny(text, "\r\n\x00")) {
					return errors.New("domain failure metadata string is invalid")
				}
			}
		case nil, bool, float64:
		default:
			return errors.New("domain failure metadata type is invalid")
		}
	}
	return nil
}

func validatePreviewLeaseCreateInput(input PreviewLeaseCreateRequest) error {
	if !validPreviewID(input.OwnerDeviceID) || !validPreviewID(input.OwnerSessionID) {
		return fmt.Errorf("%w: owner device and session are required", ErrPreviewLeaseInvalid)
	}
	mode := strings.ToLower(strings.TrimSpace(input.AccessMode))
	if mode != "" && mode != "public" && mode != "private" {
		return fmt.Errorf("%w: access mode must be public or private", ErrPreviewLeaseInvalid)
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("%w: expiration must be in the future", ErrPreviewLeaseInvalid)
	}
	scheme := strings.ToLower(strings.TrimSpace(input.Target.Scheme))
	if scheme != "http" && scheme != "https" && scheme != "h2c" && scheme != "unix" && scheme != "tcp" {
		return fmt.Errorf("%w: target scheme is unsupported", ErrPreviewLeaseInvalid)
	}
	if strings.TrimSpace(input.Target.Address) == "" || len(input.Target.Address) > 512 || strings.ContainsAny(input.Target.Address, "\r\n") {
		return fmt.Errorf("%w: target address is invalid", ErrPreviewLeaseInvalid)
	}
	if _, err := NormalizePreviewDomains(input.Domains); err != nil {
		return err
	}
	return nil
}

func validateMutationLease(lease PreviewLease, idempotencyKey string) error {
	if err := validatePreviewLeaseIdempotencyKey(idempotencyKey); err != nil {
		return err
	}
	if err := validatePreviewLease(lease); err != nil {
		return err
	}
	if strings.TrimSpace(lease.ETag) == "" {
		return ErrPreviewLeaseETagRequired
	}
	if _, err := previewLeaseETag(lease.ID, lease.ETag); err != nil {
		return err
	}
	return nil
}

// validatePreviewLeaseIdempotencyKey keeps mutation keys stable across the
// client/server boundary. Header values containing whitespace, controls, or
// non-ASCII text are rejected instead of being silently trimmed or rewritten,
// which would make the server's idempotency fingerprint ambiguous.
func validatePreviewLeaseIdempotencyKey(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return errors.New("preview lease idempotency key is required")
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("preview lease idempotency key is invalid")
		}
	}
	return nil
}

func validatePreviewLease(lease PreviewLease) error {
	if lease.Schema != PreviewTunnelSchemaV1 || lease.Kind != "preview_lease" || !validPreviewID(lease.ID) || !validPreviewID(lease.AccountID) || !validPreviewID(lease.ActorID) || !validPreviewID(lease.OwnerDeviceID) || !validPreviewID(lease.OwnerSessionID) {
		return fmt.Errorf("%w: required identity fields are missing", ErrPreviewLeaseInvalid)
	}
	if lease.AccessMode != "public" && lease.AccessMode != "private" {
		return fmt.Errorf("%w: unsupported access mode %q", ErrPreviewLeaseInvalid, lease.AccessMode)
	}
	if lease.Persistent {
		return fmt.Errorf("%w: preview leases cannot be persistent", ErrPreviewLeaseInvalid)
	}
	if err := validatePreviewLeaseTarget(lease.Target); err != nil {
		return err
	}
	endpoint, err := url.Parse(lease.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawPath != "" && endpoint.RawPath != "/" {
		return fmt.Errorf("%w: endpoint must be an HTTPS URL", ErrPreviewLeaseInvalid)
	}
	if lease.LeaseDeadline.IsZero() || lease.CreatedAt.IsZero() || lease.LastRenewedAt.IsZero() {
		return fmt.Errorf("%w: lease deadline is missing", ErrPreviewLeaseInvalid)
	}
	if lease.UserDeadline != nil && lease.UserDeadline.IsZero() {
		return fmt.Errorf("%w: user deadline is invalid", ErrPreviewLeaseInvalid)
	}
	if !validPreviewLeaseState(lease.State) || !validPreviewAllocationState(lease.AllocationState) || !validPreviewEdgeState(lease.EdgeState) || !validPreviewOriginState(lease.OriginState) {
		return fmt.Errorf("%w: lease state is invalid", ErrPreviewLeaseInvalid)
	}
	if lease.ETag != "" {
		if _, err := previewLeaseETag(lease.ID, lease.ETag); err != nil {
			return err
		}
	}
	if err := validatePreviewDomainSummaries(lease); err != nil {
		return err
	}
	return nil
}

func validatePreviewLeaseTarget(target PreviewLeaseTarget) error {
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme != "http" && scheme != "https" && scheme != "h2c" && scheme != "unix" && scheme != "tcp" {
		return fmt.Errorf("%w: target scheme is unsupported", ErrPreviewLeaseInvalid)
	}
	if strings.TrimSpace(target.Address) == "" || len(target.Address) > 512 || strings.ContainsAny(target.Address, "\r\n") {
		return fmt.Errorf("%w: target address is invalid", ErrPreviewLeaseInvalid)
	}
	return nil
}

func validatePreviewLeaseOperation(operation PreviewLeaseOperation) error {
	if operation.Schema != PreviewTunnelSchemaV1 || operation.Kind != "operation" || !validPreviewID(operation.ID) || operation.ResourceKind != "preview_lease" || !validPreviewID(operation.ResourceID) || !validPreviewOperationPhase(operation.Phase) || operation.Progress < 0 || operation.Progress > 100 || !validPreviewID(operation.CorrelationID) || operation.CreatedAt.IsZero() || operation.UpdatedAt.IsZero() || operation.NextRetryAt != nil && operation.NextRetryAt.IsZero() {
		return ErrPreviewLeaseInvalid
	}
	switch operation.State {
	case "pending", "running", "succeeded", "failed", "canceled":
		return nil
	default:
		return ErrPreviewLeaseInvalid
	}
}

func validPreviewOperationPhase(value string) bool {
	switch value {
	case "validating", "persisting", "waiting_for_dns", "issuing_certificate", "installing_service", "connecting", "checking_origin", "draining", "rolling_back", "ready", "failed":
		return true
	default:
		return false
	}
}

func validPreviewID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validPreviewLeaseState(value string) bool {
	switch value {
	case "allocating", "connecting", "ready", "owner_disconnected", "expired", "stopped":
		return true
	default:
		return false
	}
}

func validPreviewAllocationState(value string) bool {
	switch value {
	case "pending", "ready", "failed", "released":
		return true
	default:
		return false
	}
}

func validPreviewEdgeState(value string) bool {
	switch value {
	case "pending", "ready", "degraded", "down":
		return true
	default:
		return false
	}
}

func validPreviewOriginState(value string) bool {
	switch value {
	case "unknown", "ready", "unavailable":
		return true
	default:
		return false
	}
}

func previewLeaseETag(id, etag string) (int64, error) {
	value := strings.TrimSpace(etag)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, fmt.Errorf("%w: lease ETag is not strong", ErrPreviewLeaseInvalid)
	}
	parts := strings.Split(strings.Trim(value, `"`), ":")
	if len(parts) != 4 || parts[0] != "ptv1" || parts[1] != "preview_lease" {
		return 0, fmt.Errorf("%w: lease ETag has the wrong resource", ErrPreviewLeaseInvalid)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || string(decoded) != id || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] {
		return 0, fmt.Errorf("%w: lease ETag does not match the resource", ErrPreviewLeaseInvalid)
	}
	generation, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || generation < 1 {
		return 0, fmt.Errorf("%w: lease ETag generation is invalid", ErrPreviewLeaseInvalid)
	}
	return generation, nil
}

// ValidatePreviewLeaseETag validates the strong preview lease precondition
// without exposing its generation parser. Host-runtime subpackages use this
// before signing requests that carry If-Match.
func ValidatePreviewLeaseETag(id, etag string) error {
	_, err := previewLeaseETag(id, etag)
	return err
}
