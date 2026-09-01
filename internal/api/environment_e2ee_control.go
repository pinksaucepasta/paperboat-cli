package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	EnvironmentKeyEnrollmentSchemaV1          = "paperboat.environment-key-enrollment/v1"
	EnvironmentKeyEnrollmentStateSchemaV1     = "paperboat.environment-key-enrollment-state/v1"
	EnvironmentKeyEnrollmentProofSchemaV1     = "paperboat.environment-key-enrollment-proof/v1"
	EnvironmentKeyApprovalSchemaV1            = "paperboat.environment-key-approval/v1"
	EnvironmentAuthorityTransitionSchemaV1    = "paperboat.environment-authority-transition/v1"
	EnvironmentTransitionManifestSchemaV1     = "paperboat.environment-transition-manifest/v1"
	EnvironmentTransitionStateSchemaV1        = "paperboat.environment-authority-transition-state/v1"
	EnvironmentAuthorityTransitionAbortSchema = "paperboat.environment-authority-transition-abort/v1"
)

type EnvironmentKeyEnrollmentRequest struct {
	Schema              string    `json:"schema"`
	OperationID         string    `json:"operation_id"`
	SubjectKind         string    `json:"subject_kind"`
	SubjectID           string    `json:"subject_id"`
	SubjectGeneration   int64     `json:"subject_generation"`
	KeyGeneration       int64     `json:"key_generation"`
	EndpointCertificate *string   `json:"endpoint_certificate"`
	SigningPublicKey    *string   `json:"signing_public_key"`
	SigningKeyID        *string   `json:"signing_key_id"`
	SigningProof        *string   `json:"signing_proof"`
	RecipientPublicKey  string    `json:"recipient_public_key"`
	RecipientKeyID      string    `json:"recipient_key_id"`
	BindingNotAfter     *string   `json:"binding_not_after"`
	RequestExpiresAt    time.Time `json:"request_expires_at"`
}

type EnvironmentKeyEnrollmentState struct {
	Schema            string    `json:"schema"`
	RequestID         string    `json:"request_id"`
	State             string    `json:"state"`
	ExpiresAt         time.Time `json:"expires_at"`
	SafetyCode        string    `json:"safety_code"`
	EnrollmentRequest string    `json:"enrollment_request"`
	SigningProof      *string   `json:"signing_proof"`
	Challenge         *string   `json:"challenge,omitempty"`
}

type EnvironmentKeyEnrollmentPage struct {
	Items []EnvironmentKeyEnrollmentState `json:"items"`
}

type EnvironmentKeyEnrollmentProof struct {
	Schema string `json:"schema"`
	Proof  string `json:"proof"`
}

type EnvironmentKeyApproval struct {
	Schema              string  `json:"schema"`
	ExpectedAuthorityID *string `json:"expected_authority_id"`
	OperationID         string  `json:"operation_id"`
	Binding             string  `json:"binding"`
	Authority           string  `json:"authority"`
}

type EnvironmentAuthorityTransition struct {
	Schema              string `json:"schema"`
	ExpectedAuthorityID string `json:"expected_authority_id"`
	OperationID         string `json:"operation_id"`
	Authority           string `json:"authority"`
}

type EnvironmentTransitionManifest struct {
	Schema          string `json:"schema"`
	ExpectedVersion int64  `json:"expected_version"`
	OperationID     string `json:"operation_id"`
	Envelope        string `json:"envelope"`
}

type EnvironmentAuthorityTransitionAbort struct {
	Schema               string `json:"schema"`
	ExpectedTransitionID string `json:"expected_transition_id"`
	OperationID          string `json:"operation_id"`
	Authorization        string `json:"authorization"`
}

type EnvironmentAuthorityTransitionState struct {
	Schema              string   `json:"schema"`
	TransitionID        string   `json:"transition_id"`
	State               string   `json:"state"`
	ProposedGeneration  int64    `json:"proposed_generation"`
	ProposedAuthorityID string   `json:"proposed_authority_id"`
	RequiredScopes      []string `json:"required_scopes"`
	StagedScopes        []string `json:"staged_scopes"`
}

func (c *Client) CreateEnvironmentKeyEnrollment(ctx context.Context, request EnvironmentKeyEnrollmentRequest) (EnvironmentKeyEnrollmentState, error) {
	if err := validateEnvironmentKeyEnrollmentRequest(request); err != nil {
		return EnvironmentKeyEnrollmentState{}, err
	}
	var out EnvironmentKeyEnrollmentState
	var responseHeaders http.Header
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{request.OperationID}})
	if err := c.doRequestMeta(ctx, http.MethodPost, "/v1/environment-key-enrollments", request, &out, headers, true, &responseHeaders); err != nil {
		return EnvironmentKeyEnrollmentState{}, redactEnvironmentE2EEError(err)
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentKeyEnrollmentState{}, err
	}
	if out.State != "challenge" && out.State != "pending" {
		return EnvironmentKeyEnrollmentState{}, errors.New("paperboat-server returned invalid environment key enrollment state")
	}
	if err := validateEnvironmentEnrollmentState(out, out.State); err != nil {
		return EnvironmentKeyEnrollmentState{}, err
	}
	return out, nil
}

func (c *Client) SubmitEnvironmentKeyEnrollmentProof(ctx context.Context, requestID, operationID string, proof EnvironmentKeyEnrollmentProof) (EnvironmentKeyEnrollmentState, error) {
	if !environmentIdentifierPattern.MatchString(requestID) || !environmentOperationIDPattern.MatchString(operationID) || proof.Schema != EnvironmentKeyEnrollmentProofSchemaV1 || !canonicalEnvironmentBase64Length(proof.Proof, 32) {
		return EnvironmentKeyEnrollmentState{}, errors.New("environment key enrollment proof is invalid")
	}
	var out EnvironmentKeyEnrollmentState
	var responseHeaders http.Header
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{operationID}})
	path := "/v1/environment-key-enrollments/" + url.PathEscape(requestID) + "/proof"
	if err := c.doRequestMeta(ctx, http.MethodPut, path, proof, &out, headers, true, &responseHeaders); err != nil {
		return EnvironmentKeyEnrollmentState{}, redactEnvironmentE2EEError(err)
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentKeyEnrollmentState{}, err
	}
	if err := validateEnvironmentEnrollmentState(out, "pending"); err != nil || out.RequestID != requestID {
		return EnvironmentKeyEnrollmentState{}, errors.New("paperboat-server returned invalid environment key enrollment state")
	}
	return out, nil
}

func (c *Client) ListPendingEnvironmentKeyEnrollments(ctx context.Context) ([]EnvironmentKeyEnrollmentState, error) {
	var out EnvironmentKeyEnrollmentPage
	var responseHeaders http.Header
	if err := c.doRequestMeta(ctx, http.MethodGet, "/v1/environment-key-enrollments/pending", nil, &out, environmentNoStoreRequestHeaders(nil), true, &responseHeaders); err != nil {
		return nil, err
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []EnvironmentKeyEnrollmentState{}
	}
	seen := make(map[string]struct{}, len(out.Items))
	for _, item := range out.Items {
		if err := validateEnvironmentEnrollmentState(item, "pending"); err != nil {
			return nil, err
		}
		if _, exists := seen[item.RequestID]; exists {
			return nil, errors.New("paperboat-server returned duplicate environment key enrollment state")
		}
		seen[item.RequestID] = struct{}{}
	}
	return out.Items, nil
}

func (c *Client) ApproveEnvironmentKeyEnrollment(ctx context.Context, requestID, authorityETag string, approval EnvironmentKeyApproval) (EnvironmentAuthorityTransitionState, error) {
	if !environmentIdentifierPattern.MatchString(requestID) || approval.Schema != EnvironmentKeyApprovalSchemaV1 || !environmentOperationIDPattern.MatchString(approval.OperationID) || !canonicalEnvironmentBase64Within(approval.Binding, 2<<10) || !canonicalEnvironmentBase64Within(approval.Authority, maximumEnvironmentAuthorityBytes) {
		return EnvironmentAuthorityTransitionState{}, errors.New("environment key approval is invalid")
	}
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{approval.OperationID}})
	if approval.ExpectedAuthorityID == nil {
		if strings.TrimSpace(authorityETag) != "" {
			return EnvironmentAuthorityTransitionState{}, errors.New("environment authority genesis must not have a current ETag")
		}
		headers.Set("If-None-Match", "*")
	} else {
		if !environmentDocumentIDPattern.MatchString(*approval.ExpectedAuthorityID) || !validEnvironmentAuthorityETag(authorityETag, *approval.ExpectedAuthorityID) {
			return EnvironmentAuthorityTransitionState{}, errors.New("environment authority approval precondition is invalid")
		}
		headers.Set("If-Match", authorityETag)
	}
	var out EnvironmentAuthorityTransitionState
	var responseHeaders http.Header
	path := "/v1/environment-key-enrollments/" + url.PathEscape(requestID) + "/approve"
	if err := c.doRequestMeta(ctx, http.MethodPost, path, approval, &out, headers, true, &responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, redactEnvironmentE2EEError(err)
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	if err := validateEnvironmentTransitionState(out); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	return out, nil
}

func (c *Client) StartEnvironmentAuthorityTransition(ctx context.Context, authorityETag string, request EnvironmentAuthorityTransition) (EnvironmentAuthorityTransitionState, error) {
	if request.Schema != EnvironmentAuthorityTransitionSchemaV1 || !environmentDocumentIDPattern.MatchString(request.ExpectedAuthorityID) || !environmentOperationIDPattern.MatchString(request.OperationID) || !canonicalEnvironmentBase64Within(request.Authority, maximumEnvironmentAuthorityBytes) || !validEnvironmentAuthorityETag(authorityETag, request.ExpectedAuthorityID) {
		return EnvironmentAuthorityTransitionState{}, errors.New("environment authority transition is invalid")
	}
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{request.OperationID}, "If-Match": []string{authorityETag}})
	return c.environmentTransitionMutation(ctx, http.MethodPost, "/v1/environment-authority/transitions", request, headers)
}

func (c *Client) GetEnvironmentAuthorityTransition(ctx context.Context, transitionID string) (EnvironmentAuthorityTransitionState, error) {
	if !environmentDocumentIDPattern.MatchString(transitionID) {
		return EnvironmentAuthorityTransitionState{}, errors.New("environment authority transition ID is invalid")
	}
	var out EnvironmentAuthorityTransitionState
	var responseHeaders http.Header
	path := "/v1/environment-authority/transitions/" + url.PathEscape(transitionID)
	if err := c.doRequestMeta(ctx, http.MethodGet, path, nil, &out, environmentNoStoreRequestHeaders(nil), true, &responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	if err := validateEnvironmentTransitionState(out); err != nil || out.TransitionID != transitionID {
		return EnvironmentAuthorityTransitionState{}, errors.New("paperboat-server returned invalid environment authority transition state")
	}
	return out, nil
}

func (c *Client) StageEnvironmentTransitionManifest(ctx context.Context, transitionID, machineID, scopeETag string, request EnvironmentTransitionManifest) (EnvironmentAuthorityTransitionState, error) {
	if !environmentDocumentIDPattern.MatchString(transitionID) || request.Schema != EnvironmentTransitionManifestSchemaV1 || request.ExpectedVersion < 0 || request.ExpectedVersion >= maximumEnvironmentProtocolVersion || !environmentOperationIDPattern.MatchString(request.OperationID) || !canonicalEnvironmentBase64Within(request.Envelope, maximumEnvironmentManifestBytes) {
		return EnvironmentAuthorityTransitionState{}, errors.New("environment transition manifest is invalid")
	}
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{request.OperationID}})
	if request.ExpectedVersion == 0 {
		if strings.TrimSpace(scopeETag) != "" {
			return EnvironmentAuthorityTransitionState{}, errors.New("environment transition manifest genesis must not have a current ETag")
		}
		headers.Set("If-None-Match", "*")
	} else {
		if err := validateEnvironmentVariableETagForVersion(scopeETag, machineID, request.ExpectedVersion); err != nil {
			return EnvironmentAuthorityTransitionState{}, err
		}
		headers.Set("If-Match", scopeETag)
	}
	path := "/v1/environment-authority/transitions/" + url.PathEscape(transitionID) + "/scopes/global"
	if machineID != "" {
		path = "/v1/environment-authority/transitions/" + url.PathEscape(transitionID) + "/scopes/machines/" + url.PathEscape(machineID)
	}
	return c.environmentTransitionMutation(ctx, http.MethodPut, path, request, headers)
}

func (c *Client) AbortEnvironmentAuthorityTransition(ctx context.Context, authorityETag string, request EnvironmentAuthorityTransitionAbort) (EnvironmentAuthorityTransitionState, error) {
	if request.Schema != EnvironmentAuthorityTransitionAbortSchema || !environmentDocumentIDPattern.MatchString(request.ExpectedTransitionID) || !environmentOperationIDPattern.MatchString(request.OperationID) || !canonicalEnvironmentBase64Within(request.Authorization, 2<<10) || strings.TrimSpace(authorityETag) == "" {
		return EnvironmentAuthorityTransitionState{}, errors.New("environment authority transition abort is invalid")
	}
	headers := environmentNoStoreRequestHeaders(http.Header{"Idempotency-Key": []string{request.OperationID}, "If-Match": []string{authorityETag}})
	path := "/v1/environment-authority/transitions/" + url.PathEscape(request.ExpectedTransitionID) + "/abort"
	out, err := c.environmentTransitionMutation(ctx, http.MethodPost, path, request, headers)
	if err == nil && (out.TransitionID != request.ExpectedTransitionID || out.State != "aborted") {
		return EnvironmentAuthorityTransitionState{}, errors.New("paperboat-server returned invalid aborted environment transition state")
	}
	return out, err
}

func (c *Client) environmentTransitionMutation(ctx context.Context, method, path string, body any, headers http.Header) (EnvironmentAuthorityTransitionState, error) {
	var out EnvironmentAuthorityTransitionState
	var responseHeaders http.Header
	if err := c.doRequestMeta(ctx, method, path, body, &out, headers, true, &responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, redactEnvironmentE2EEError(err)
	}
	if err := validateEnvironmentNoStore(responseHeaders); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	if err := validateEnvironmentTransitionState(out); err != nil {
		return EnvironmentAuthorityTransitionState{}, err
	}
	return out, nil
}

func validateEnvironmentKeyEnrollmentRequest(value EnvironmentKeyEnrollmentRequest) error {
	if value.Schema != EnvironmentKeyEnrollmentSchemaV1 || !environmentOperationIDPattern.MatchString(value.OperationID) || !environmentIdentifierPattern.MatchString(value.SubjectID) || value.SubjectGeneration < 1 || value.SubjectGeneration > maximumEnvironmentProtocolVersion || value.KeyGeneration < 1 || value.KeyGeneration > maximumEnvironmentProtocolVersion || value.BindingNotAfter != nil || value.RequestExpiresAt.IsZero() {
		return errors.New("environment key enrollment request is invalid")
	}
	if !canonicalEnvironmentBase64Length(value.RecipientPublicKey, 32) || !environmentRecipientKeyIDPattern.MatchString(value.RecipientKeyID) {
		return errors.New("environment key enrollment recipient is invalid")
	}
	switch value.SubjectKind {
	case "manager_cli", "manager_browser":
		if value.SigningPublicKey == nil || value.SigningKeyID == nil || value.SigningProof == nil || !canonicalEnvironmentBase64Length(*value.SigningPublicKey, 32) || !canonicalEnvironmentBase64Length(*value.SigningProof, 64) || !environmentSigningKeyIDPattern.MatchString(*value.SigningKeyID) {
			return errors.New("environment manager enrollment proof is invalid")
		}
		if value.SubjectKind == "manager_cli" && (value.EndpointCertificate == nil || !canonicalEnvironmentBase64Within(*value.EndpointCertificate, 1024)) || value.SubjectKind == "manager_browser" && value.EndpointCertificate != nil {
			return errors.New("environment manager enrollment certificate is invalid")
		}
	case "host":
		if value.EndpointCertificate == nil || !canonicalEnvironmentBase64Within(*value.EndpointCertificate, 1024) || value.SigningPublicKey != nil || value.SigningKeyID != nil || value.SigningProof != nil {
			return errors.New("environment host enrollment request is invalid")
		}
	default:
		return errors.New("environment key enrollment subject kind is invalid")
	}
	return nil
}

func validateEnvironmentEnrollmentState(value EnvironmentKeyEnrollmentState, expectedState string) error {
	if value.Schema != EnvironmentKeyEnrollmentStateSchemaV1 || !environmentIdentifierPattern.MatchString(value.RequestID) || value.State != expectedState || value.ExpiresAt.IsZero() || !environmentSafetyCodePattern.MatchString(value.SafetyCode) || !canonicalEnvironmentBase64Within(value.EnrollmentRequest, 8<<10) {
		return errors.New("paperboat-server returned invalid environment key enrollment state")
	}
	if value.SigningProof != nil && !canonicalEnvironmentBase64Length(*value.SigningProof, 64) {
		return errors.New("paperboat-server returned invalid environment key enrollment state")
	}
	if expectedState == "challenge" {
		if value.Challenge == nil || !canonicalEnvironmentBase64Within(*value.Challenge, 256) {
			return errors.New("paperboat-server returned invalid environment key enrollment challenge")
		}
	} else if value.Challenge != nil {
		return errors.New("paperboat-server returned an unexpected environment key enrollment challenge")
	}
	return nil
}

func validateEnvironmentTransitionState(value EnvironmentAuthorityTransitionState) error {
	if value.Schema != EnvironmentTransitionStateSchemaV1 || !environmentDocumentIDPattern.MatchString(value.TransitionID) || !environmentDocumentIDPattern.MatchString(value.ProposedAuthorityID) || value.ProposedGeneration < 1 || value.ProposedGeneration > maximumEnvironmentProtocolVersion {
		return errors.New("paperboat-server returned invalid environment authority transition state")
	}
	switch value.State {
	case "staged", "ready", "active", "aborted":
	default:
		return errors.New("paperboat-server returned invalid environment authority transition state")
	}
	if value.RequiredScopes == nil || value.StagedScopes == nil || !sortedUniqueEnvironmentScopes(value.RequiredScopes) || !sortedUniqueEnvironmentScopes(value.StagedScopes) {
		return errors.New("paperboat-server returned invalid environment authority transition scopes")
	}
	required := make(map[string]struct{}, len(value.RequiredScopes))
	for _, scope := range value.RequiredScopes {
		required[scope] = struct{}{}
	}
	for _, scope := range value.StagedScopes {
		if _, ok := required[scope]; !ok {
			return errors.New("paperboat-server returned an unexpected staged environment scope")
		}
	}
	return nil
}

func sortedUniqueEnvironmentScopes(values []string) bool {
	for index, value := range values {
		valid := value == "g" || strings.HasPrefix(value, "m:") && environmentIdentifierPattern.MatchString(strings.TrimPrefix(value, "m:"))
		if !valid || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return sort.StringsAreSorted(values)
}

func validEnvironmentAuthorityETag(etag, authorityID string) bool {
	etag = strings.TrimSpace(etag)
	if etag == "" || !environmentDocumentIDPattern.MatchString(authorityID) || !strings.HasPrefix(etag, `"environment-authority-`) || !strings.HasSuffix(etag, `-`+strings.TrimPrefix(authorityID, "sha256:")+`"`) {
		return false
	}
	return !strings.ContainsAny(etag, "\r\n")
}

func canonicalEnvironmentBase64Length(value string, exact int) bool {
	raw, err := decodeCanonicalEnvironmentBase64(value, exact)
	if err != nil || len(raw) != exact {
		clear(raw)
		return false
	}
	clear(raw)
	return true
}

func canonicalEnvironmentBase64Within(value string, maximum int) bool {
	raw, err := decodeCanonicalEnvironmentBase64(value, maximum)
	clear(raw)
	return err == nil
}

var environmentIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var environmentSigningKeyIDPattern = regexp.MustCompile(`^sigk_[A-Za-z0-9_-]{43}$`)
var environmentRecipientKeyIDPattern = regexp.MustCompile(`^envk_[A-Za-z0-9_-]{43}$`)
var environmentSafetyCodePattern = regexp.MustCompile(`^[a-z2-7]{4}(?:-[a-z2-7]{4}){3}$`)
