package environmentmanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

const pendingEnrollmentSchema = "paperboat.environment-pending-enrollment/v1"
const maximumPendingEnrollmentBytes = 64 << 10

type pendingEnrollment struct {
	Schema     string                              `json:"schema"`
	AccountID  string                              `json:"account_id"`
	SubjectID  string                              `json:"subject_id"`
	Genesis    bool                                `json:"genesis"`
	Request    api.EnvironmentKeyEnrollmentRequest `json:"request"`
	Canonical  string                              `json:"canonical_request"`
	RequestID  string                              `json:"request_id,omitempty"`
	SafetyCode string                              `json:"safety_code,omitempty"`
}

func (manager Manager) enrollmentPath() (string, error) {
	directory, err := manager.transitionPath()
	if err != nil {
		return "", err
	}
	digest := documentDigestText(manager.AccountID + "\x00" + manager.SubjectID + "\x00enrollment")
	return filepath.Join(filepath.Dir(directory), "enrollment-"+digest+".json"), nil
}

func (manager Manager) storePendingEnrollment(value pendingEnrollment) error {
	if err := validatePendingEnrollment(value, manager.AccountID, manager.SubjectID); err != nil {
		return err
	}
	path, err := manager.enrollmentPath()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maximumPendingEnrollmentBytes {
		clear(raw)
		return ErrIntegrity
	}
	defer clear(raw)
	return atomicfile.Write(path, raw, atomicfile.CurrentOwnerOptions(0o600))
}

func (manager Manager) loadPendingEnrollment() (pendingEnrollment, bool, error) {
	path, err := manager.enrollmentPath()
	if err != nil {
		return pendingEnrollment{}, false, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return pendingEnrollment{}, false, nil
	}
	if err != nil {
		return pendingEnrollment{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumPendingEnrollmentBytes {
		return pendingEnrollment{}, false, ErrIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPendingEnrollmentBytes+1))
	if err != nil || len(raw) > maximumPendingEnrollmentBytes {
		clear(raw)
		return pendingEnrollment{}, false, ErrIntegrity
	}
	defer clear(raw)
	var value pendingEnrollment
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || validatePendingEnrollment(value, manager.AccountID, manager.SubjectID) != nil {
		return pendingEnrollment{}, false, ErrIntegrity
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytesEqual(canonical, raw) {
		clear(canonical)
		return pendingEnrollment{}, false, ErrIntegrity
	}
	clear(canonical)
	return value, true, nil
}

func (manager Manager) deletePendingEnrollment() error {
	path, err := manager.enrollmentPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncMutationDirectory(filepath.Dir(path))
}

func (manager Manager) resumeEnrollmentLocked(ctx context.Context, client EnrollmentControlPlane, draft pendingEnrollment, now time.Time) (EnrollmentResult, error) {
	canonical, err := decodeBase64(draft.Canonical, environmente2ee.MaximumEnrollmentBytes)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(canonical)
	request, err := environmente2ee.ParseEnrollmentRequest(canonical)
	if err != nil || request.AccountID != manager.AccountID || request.SubjectID != manager.SubjectID || "envop_"+hex.EncodeToString(request.OperationID[:]) != draft.Request.OperationID || int64(request.RequestExpiresAt) != draft.Request.RequestExpiresAt.Unix() {
		return EnrollmentResult{}, ErrIntegrity
	}
	proof, err := decodeOptionalBase64(draft.Request.SigningProof, ed25519.SignatureSize)
	if err != nil || environmente2ee.VerifyEnrollmentRequestSignature(request, proof) != nil {
		clear(proof)
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(proof)
	identity, err := manager.Store.LoadEnvironmentManagerIdentity(manager.Issuer, manager.AccountID, manager.SubjectID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer identity.Clear()
	if draft.RequestID != "" {
		authority, recipient, _, signer, activeErr := manager.activeAuthority(ctx, &identity)
		clearAuthority(&authority)
		clear(recipient.PrivateKey)
		clear(signer)
		if activeErr == nil {
			active := enrollmentResultFromDraft(draft, identity)
			active.AuthorityActive = true
			if err := manager.deletePendingEnrollment(); err != nil {
				return EnrollmentResult{}, err
			}
			return active, nil
		}
	}
	if !now.Before(draft.Request.RequestExpiresAt) {
		if err := manager.deletePendingEnrollment(); err != nil {
			return EnrollmentResult{}, err
		}
		return EnrollmentResult{}, ErrEnrollmentExpired
	}
	state, err := client.CreateEnvironmentKeyEnrollment(ctx, draft.Request)
	if err != nil {
		return EnrollmentResult{}, err
	}
	received, err := decodeBase64(state.EnrollmentRequest, environmente2ee.MaximumEnrollmentBytes)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(received)
	receivedProof, err := decodeOptionalBase64(state.SigningProof, ed25519.SignatureSize)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(receivedProof)
	verified, safety, err := environmente2ee.VerifyPendingEnrollment(received, receivedProof)
	if err != nil || !bytes.Equal(received, canonical) || !enrollmentEqual(verified, request) || safety != state.SafetyCode || !state.ExpiresAt.Equal(draft.Request.RequestExpiresAt) {
		return EnrollmentResult{}, ErrIntegrity
	}
	if draft.RequestID == "" {
		if state.State != "challenge" {
			return EnrollmentResult{}, ErrIntegrity
		}
		draft.RequestID, draft.SafetyCode = state.RequestID, safety
		if err := manager.storePendingEnrollment(draft); err != nil {
			return EnrollmentResult{}, err
		}
	} else if draft.RequestID != state.RequestID || draft.SafetyCode != safety {
		return EnrollmentResult{}, ErrIntegrity
	}
	if state.State == "pending" {
		return enrollmentResultWithRecovery(draft, identity)
	}
	if state.State != "challenge" || state.Challenge == nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	sealed, err := decodeBase64(*state.Challenge, 256)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(sealed)
	digest, _ := environmente2ee.EnrollmentRequestDigest(request)
	challengeContext := environmente2ee.EnrollmentChallengeContext{AccountID: manager.AccountID, RequestID: state.RequestID, OperationID: request.OperationID, RecipientKeyID: request.RecipientKeyID, RequestDigest: digest}
	challenge, err := environmente2ee.OpenEnrollmentChallenge(challengeContext, identity.RecipientPrivate[:], sealed)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	defer clear(challenge)
	enrollmentProof, err := environmente2ee.EnrollmentProof(challengeContext, challenge)
	if err != nil {
		return EnrollmentResult{}, ErrIntegrity
	}
	pending, err := client.SubmitEnvironmentKeyEnrollmentProof(ctx, state.RequestID, draft.Request.OperationID, api.EnvironmentKeyEnrollmentProof{Schema: api.EnvironmentKeyEnrollmentProofSchemaV1, Proof: base64.RawURLEncoding.EncodeToString(enrollmentProof[:])})
	if err != nil {
		return EnrollmentResult{}, err
	}
	if pending.EnrollmentRequest != state.EnrollmentRequest || pending.SigningProof == nil || draft.Request.SigningProof == nil || *pending.SigningProof != *draft.Request.SigningProof || pending.SafetyCode != safety || !pending.ExpiresAt.Equal(draft.Request.RequestExpiresAt) {
		return EnrollmentResult{}, ErrIntegrity
	}
	return enrollmentResultWithRecovery(draft, identity)
}

func enrollmentResultWithRecovery(draft pendingEnrollment, identity config.EnvironmentManagerIdentity) (EnrollmentResult, error) {
	result := enrollmentResultFromDraft(draft, identity)
	if draft.Genesis && identity.RecoveryPrivate != nil {
		recovery, err := environmente2ee.EncodeRecoveryBytes(identity.RecoveryPrivate[:])
		if err != nil {
			return EnrollmentResult{}, ErrIntegrity
		}
		result.Recovery = recovery
	}
	return result, nil
}

func enrollmentResultFromDraft(draft pendingEnrollment, identity config.EnvironmentManagerIdentity) EnrollmentResult {
	return EnrollmentResult{RequestID: draft.RequestID, SafetyCode: draft.SafetyCode, ExpiresAt: draft.Request.RequestExpiresAt, KeyGeneration: identity.KeyGeneration, RecoveryExportConfirmed: identity.RecoveryExportConfirmed}
}

func validatePendingEnrollment(value pendingEnrollment, accountID, subjectID string) error {
	if value.Schema != pendingEnrollmentSchema || value.AccountID != accountID || value.SubjectID != subjectID || value.Canonical == "" || value.Request.Schema != api.EnvironmentKeyEnrollmentSchemaV1 || value.Request.SubjectID != subjectID || value.Request.SubjectKind != "manager_cli" || !operationIDPattern.MatchString(value.Request.OperationID) || (value.RequestID == "") != (value.SafetyCode == "") {
		return ErrIntegrity
	}
	return nil
}
