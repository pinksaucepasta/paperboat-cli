package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	EnvironmentManifestMutationSchemaV1 = "paperboat.environment-manifest-mutation/v1"
	EnvironmentManifestStateSchemaV1    = "paperboat.environment-manifest-state/v1"
	EnvironmentAuthorityStateSchemaV1   = "paperboat.environment-authority-state/v1"
	EnvironmentAuthorityPageSchemaV1    = "paperboat.environment-authority-page/v1"
	EnvironmentScopeInventorySchemaV1   = "paperboat.environment-scope-inventory/v1"

	maximumEnvironmentProtocolVersion = int64(1<<53 - 1)
	maximumEnvironmentManifestBytes   = 1 << 20
	maximumEnvironmentAuthorityBytes  = 2 << 20
)

// EnvironmentScopeInventory is the public, metadata-only preflight for an
// explicit destructive reset. It deliberately excludes envelopes and wraps.
type EnvironmentScopeInventory struct {
	Schema string                     `json:"schema"`
	Scopes []EnvironmentScopeMetadata `json:"scopes"`
}

type EnvironmentScopeMetadata struct {
	Scope      EnvironmentVariableScope `json:"scope"`
	MachineID  *string                  `json:"machine_id,omitempty"`
	ScopeState string                   `json:"scope_state"`
	Version    int64                    `json:"version"`
	KeyEpoch   int64                    `json:"key_epoch"`
	ManifestID string                   `json:"manifest_id"`
	Names      []string                 `json:"names"`
}

// EnvironmentManifestMutation contains an opaque, locally encrypted and
// signed complete scope manifest. It is deliberately impossible to put a
// plaintext value in this request type.
type EnvironmentManifestMutation struct {
	Schema          string `json:"schema"`
	ExpectedVersion int64  `json:"expected_version"`
	OperationID     string `json:"operation_id"`
	Envelope        string `json:"envelope"`
}

// EnvironmentManifestState is public routing metadata plus the exact opaque
// signed envelope. The client must verify the envelope before using it.
type EnvironmentManifestState struct {
	Schema     string                   `json:"schema"`
	Scope      EnvironmentVariableScope `json:"scope"`
	MachineID  string                   `json:"machine_id,omitempty"`
	Version    int64                    `json:"version"`
	KeyEpoch   int64                    `json:"key_epoch"`
	ManifestID string                   `json:"manifest_id"`
	Envelope   string                   `json:"envelope"`
	ETag       string                   `json:"-"`
}

// EnvironmentAuthorityState is the active root-signed ENV authority head.
// Authority is canonical COSE bytes encoded as unpadded base64url.
type EnvironmentAuthorityState struct {
	Schema      string `json:"schema"`
	Generation  int64  `json:"generation"`
	AuthorityID string `json:"authority_id"`
	Authority   string `json:"authority"`
	ETag        string `json:"-"`
}

type EnvironmentAuthorityHead struct {
	Generation  int64  `json:"generation"`
	AuthorityID string `json:"authority_id"`
}

type EnvironmentAuthorityPage struct {
	Schema             string                   `json:"schema"`
	AuthorityHead      EnvironmentAuthorityHead `json:"authority_head"`
	AuthorityDocuments []string                 `json:"authority_documents"`
	HasMore            bool                     `json:"has_more"`
}

func (c *Client) GetEnvironmentScopeInventory(ctx context.Context) (EnvironmentScopeInventory, error) {
	var out EnvironmentScopeInventory
	var headers http.Header
	if err := c.doRequestMeta(ctx, http.MethodGet, "/v1/environment-scopes", nil, &out, environmentNoStoreRequestHeaders(nil), true, &headers); err != nil {
		return EnvironmentScopeInventory{}, err
	}
	if err := validateEnvironmentNoStore(headers); err != nil {
		return EnvironmentScopeInventory{}, err
	}
	if err := validateEnvironmentScopeInventory(out); err != nil {
		return EnvironmentScopeInventory{}, err
	}
	if out.Scopes == nil {
		out.Scopes = []EnvironmentScopeMetadata{}
	}
	return out, nil
}

func validateEnvironmentScopeInventory(value EnvironmentScopeInventory) error {
	if value.Schema != EnvironmentScopeInventorySchemaV1 || len(value.Scopes) == 0 || len(value.Scopes) > 513 {
		return errors.New("paperboat-server returned invalid environment scope inventory")
	}
	seenMachines := make(map[string]struct{}, len(value.Scopes))
	previousMachine := ""
	for index, scope := range value.Scopes {
		if scope.ScopeState != "active" && scope.ScopeState != "retired" || scope.Version < 1 || scope.Version > maximumEnvironmentProtocolVersion || scope.KeyEpoch < 1 || scope.KeyEpoch > maximumEnvironmentProtocolVersion || !environmentDocumentIDPattern.MatchString(scope.ManifestID) || scope.Names == nil || len(scope.Names) > MaximumEnvironmentVariables {
			return errors.New("paperboat-server returned invalid environment scope metadata")
		}
		switch scope.Scope {
		case EnvironmentVariableScopeGlobal:
			if index != 0 || scope.MachineID != nil || scope.ScopeState != "active" {
				return errors.New("paperboat-server returned invalid global environment scope metadata")
			}
		case EnvironmentVariableScopeMachine:
			if index == 0 || scope.MachineID == nil || !environmentIdentifierPattern.MatchString(*scope.MachineID) || previousMachine >= *scope.MachineID {
				return errors.New("paperboat-server returned unsorted machine environment scope metadata")
			}
			if _, duplicate := seenMachines[*scope.MachineID]; duplicate {
				return errors.New("paperboat-server returned duplicate machine environment scope metadata")
			}
			seenMachines[*scope.MachineID] = struct{}{}
			previousMachine = *scope.MachineID
		default:
			return errors.New("paperboat-server returned invalid environment scope kind")
		}
		seenNames := make(map[string]struct{}, len(scope.Names))
		for nameIndex, name := range scope.Names {
			if validateEnvironmentVariableName(name) != nil || nameIndex > 0 && scope.Names[nameIndex-1] >= name {
				return errors.New("paperboat-server returned invalid environment scope names")
			}
			upper := strings.ToUpper(name)
			if _, duplicate := seenNames[upper]; duplicate {
				return errors.New("paperboat-server returned case-insensitive duplicate environment scope name")
			}
			seenNames[upper] = struct{}{}
		}
		if !sort.StringsAreSorted(scope.Names) {
			return errors.New("paperboat-server returned unsorted environment scope names")
		}
	}
	return nil
}

func (c *Client) GetEnvironmentAuthority(ctx context.Context) (EnvironmentAuthorityState, error) {
	var out EnvironmentAuthorityState
	var headers http.Header
	if err := c.doRequestMeta(ctx, http.MethodGet, "/v1/environment-authority", nil, &out, environmentNoStoreRequestHeaders(nil), true, &headers); err != nil {
		return EnvironmentAuthorityState{}, err
	}
	out.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validateEnvironmentNoStore(headers); err != nil {
		return EnvironmentAuthorityState{}, err
	}
	if err := validateEnvironmentAuthorityState(out); err != nil {
		return EnvironmentAuthorityState{}, err
	}
	return out, nil
}

func (c *Client) GetEnvironmentAuthorityDocuments(ctx context.Context, afterGeneration int64, afterID string) (EnvironmentAuthorityPage, error) {
	if afterGeneration < 0 || afterGeneration > maximumEnvironmentProtocolVersion || afterGeneration == 0 && afterID != "" || afterGeneration > 0 && !environmentDocumentIDPattern.MatchString(afterID) {
		return EnvironmentAuthorityPage{}, errors.New("environment authority cursor is invalid")
	}
	query := url.Values{"after_generation": []string{strconv.FormatInt(afterGeneration, 10)}}
	if afterGeneration > 0 {
		query.Set("after_id", afterID)
	}
	var out EnvironmentAuthorityPage
	var headers http.Header
	path := "/v1/environment-authority/documents?" + query.Encode()
	if err := c.doRequestMeta(ctx, http.MethodGet, path, nil, &out, environmentNoStoreRequestHeaders(nil), true, &headers); err != nil {
		return EnvironmentAuthorityPage{}, err
	}
	if err := validateEnvironmentNoStore(headers); err != nil {
		return EnvironmentAuthorityPage{}, err
	}
	if out.Schema != EnvironmentAuthorityPageSchemaV1 || out.AuthorityHead.Generation < 1 || out.AuthorityHead.Generation > maximumEnvironmentProtocolVersion || !environmentDocumentIDPattern.MatchString(out.AuthorityHead.AuthorityID) || out.AuthorityHead.Generation < afterGeneration || len(out.AuthorityDocuments) > 4 || out.HasMore && len(out.AuthorityDocuments) == 0 {
		return EnvironmentAuthorityPage{}, errors.New("paperboat-server returned invalid environment authority page")
	}
	total := 0
	for _, document := range out.AuthorityDocuments {
		raw, err := decodeCanonicalEnvironmentBase64(document, maximumEnvironmentAuthorityBytes)
		if err != nil {
			return EnvironmentAuthorityPage{}, errors.New("paperboat-server returned invalid environment authority document")
		}
		total += len(raw)
		clear(raw)
		if total > 4<<20 {
			return EnvironmentAuthorityPage{}, errors.New("paperboat-server returned an oversized environment authority page")
		}
	}
	if !out.HasMore && int64(len(out.AuthorityDocuments)) != out.AuthorityHead.Generation-afterGeneration {
		return EnvironmentAuthorityPage{}, errors.New("paperboat-server returned an incomplete environment authority page")
	}
	if out.AuthorityDocuments == nil {
		out.AuthorityDocuments = []string{}
	}
	return out, nil
}

func (c *Client) GetEnvironmentManifest(ctx context.Context, machineID string) (EnvironmentManifestState, error) {
	machineID = strings.TrimSpace(machineID)
	var out EnvironmentManifestState
	var headers http.Header
	if err := c.doRequestMeta(ctx, http.MethodGet, environmentManifestPath(machineID), nil, &out, environmentNoStoreRequestHeaders(nil), true, &headers); err != nil {
		return EnvironmentManifestState{}, err
	}
	out.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validateEnvironmentNoStore(headers); err != nil {
		return EnvironmentManifestState{}, err
	}
	if err := validateEnvironmentManifestState(out, machineID, -1, ""); err != nil {
		return EnvironmentManifestState{}, err
	}
	return out, nil
}

// PutEnvironmentManifest publishes an already encrypted and signed manifest.
// expected_version zero is a genesis write and uses If-None-Match: *. Every
// other write requires the exact current scope ETag.
func (c *Client) PutEnvironmentManifest(ctx context.Context, machineID string, mutation EnvironmentManifestMutation, etag string) (EnvironmentManifestState, error) {
	machineID = strings.TrimSpace(machineID)
	if err := validateEnvironmentManifestMutation(mutation); err != nil {
		return EnvironmentManifestState{}, err
	}
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{mutation.OperationID}})
	if mutation.ExpectedVersion == 0 {
		if strings.TrimSpace(etag) != "" {
			return EnvironmentManifestState{}, errors.New("environment manifest genesis must not have a current ETag")
		}
		headers.Set("If-None-Match", "*")
	} else {
		etag = strings.TrimSpace(etag)
		if err := validateEnvironmentVariableETagForVersion(etag, machineID, mutation.ExpectedVersion); err != nil {
			return EnvironmentManifestState{}, err
		}
		headers.Set("If-Match", etag)
	}

	var out EnvironmentManifestState
	var responseHeaders http.Header
	err := c.doRequestMeta(ctx, http.MethodPut, environmentManifestPath(machineID), mutation, &out, headers, true, &responseHeaders)
	if err != nil {
		return EnvironmentManifestState{}, redactEnvironmentE2EEError(err)
	}
	out.ETag = strings.TrimSpace(responseHeaders.Get("ETag"))
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentManifestState{}, err
	}
	if err := validateEnvironmentManifestState(out, machineID, mutation.ExpectedVersion+1, mutation.Envelope); err != nil {
		return EnvironmentManifestState{}, err
	}
	return out, nil
}

func environmentManifestPath(machineID string) string {
	if machineID == "" {
		return "/v1/environment-manifests/global"
	}
	return "/v1/environment-manifests/machines/" + url.PathEscape(machineID)
}

func validateEnvironmentManifestMutation(value EnvironmentManifestMutation) error {
	if value.Schema != EnvironmentManifestMutationSchemaV1 {
		return errors.New("environment manifest mutation schema is invalid")
	}
	if value.ExpectedVersion < 0 || value.ExpectedVersion >= maximumEnvironmentProtocolVersion {
		return errors.New("environment manifest expected version is invalid")
	}
	if !environmentOperationIDPattern.MatchString(value.OperationID) {
		return errors.New("environment manifest operation ID is invalid")
	}
	if _, err := decodeCanonicalEnvironmentBase64(value.Envelope, maximumEnvironmentManifestBytes); err != nil {
		return errors.New("environment manifest envelope is invalid")
	}
	return nil
}

func validateEnvironmentManifestState(value EnvironmentManifestState, machineID string, expectedVersion int64, expectedEnvelope string) error {
	if value.Schema != EnvironmentManifestStateSchemaV1 || value.Scope != expectedEnvironmentVariableScope(machineID) || value.Version < 1 || value.Version > maximumEnvironmentProtocolVersion || value.KeyEpoch < 1 || value.KeyEpoch > maximumEnvironmentProtocolVersion {
		return errors.New("paperboat-server returned invalid environment manifest state")
	}
	if machineID == "" && value.MachineID != "" || machineID != "" && value.MachineID != machineID {
		return errors.New("paperboat-server returned an environment manifest for another scope")
	}
	if expectedVersion >= 0 && value.Version != expectedVersion {
		return errors.New("paperboat-server returned an unexpected environment manifest version")
	}
	if expectedEnvelope != "" && value.Envelope != expectedEnvelope {
		return errors.New("paperboat-server returned a different environment manifest envelope")
	}
	raw, err := decodeCanonicalEnvironmentBase64(value.Envelope, maximumEnvironmentManifestBytes)
	if err != nil || !environmentDocumentIDPattern.MatchString(value.ManifestID) || environmentDocumentID(raw) != value.ManifestID {
		clear(raw)
		return errors.New("paperboat-server returned invalid environment manifest state")
	}
	clear(raw)
	if err := validateEnvironmentVariableETagForVersion(value.ETag, machineID, value.Version); err != nil {
		return err
	}
	return nil
}

func validateEnvironmentAuthorityState(value EnvironmentAuthorityState) error {
	if value.Schema != EnvironmentAuthorityStateSchemaV1 || value.Generation < 1 || value.Generation > maximumEnvironmentProtocolVersion || !environmentDocumentIDPattern.MatchString(value.AuthorityID) {
		return errors.New("paperboat-server returned invalid environment authority state")
	}
	raw, err := decodeCanonicalEnvironmentBase64(value.Authority, maximumEnvironmentAuthorityBytes)
	if err != nil || environmentDocumentID(raw) != value.AuthorityID {
		clear(raw)
		return errors.New("paperboat-server returned invalid environment authority state")
	}
	clear(raw)
	wantETag := fmt.Sprintf(`"environment-authority-%d-%s"`, value.Generation, strings.TrimPrefix(value.AuthorityID, "sha256:"))
	if value.ETag != wantETag {
		return errors.New("paperboat-server returned invalid environment authority ETag")
	}
	return nil
}

func decodeCanonicalEnvironmentBase64(value string, maximum int) ([]byte, error) {
	if value == "" || strings.ContainsAny(value, "=\r\n \t") || len(value) > (maximum*4+2)/3 {
		return nil, errors.New("invalid base64url")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != value {
		clear(raw)
		return nil, errors.New("invalid base64url")
	}
	return raw, nil
}

func environmentDocumentID(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func environmentNoStoreRequestHeaders(headers http.Header) http.Header {
	if headers == nil {
		headers = make(http.Header)
	} else {
		headers = headers.Clone()
	}
	headers.Set("Cache-Control", "no-store")
	headers.Set("Pragma", "no-cache")
	return headers
}

func validateEnvironmentNoStore(headers http.Header) error {
	for _, directive := range strings.Split(strings.ToLower(headers.Get("Cache-Control")), ",") {
		if strings.TrimSpace(directive) == "no-store" {
			return nil
		}
	}
	return errors.New("paperboat-server returned cacheable ENV data")
}

func redactEnvironmentE2EEError(err error) error {
	if err == nil || errors.Is(err, ErrUnauthenticated) {
		return err
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return &APIError{Status: apiErr.Status, Code: apiErr.Code, Message: "ENV Injection request failed", RequestID: apiErr.RequestID}
	}
	return errors.New("ENV Injection request failed")
}

var environmentOperationIDPattern = regexp.MustCompile(`^envop_[0-9a-f]{32}$`)
var environmentDocumentIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
