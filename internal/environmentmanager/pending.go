package environmentmanager

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const pendingMutationSchema = "paperboat.environment-pending-mutation/v1"
const maximumPendingMutationFileBytes = 1_500_000

var (
	ErrPendingMutationReconciled = errors.New("a previous uncertain ENV mutation was reconciled; rerun the requested command")
	ErrPendingMutationSuperseded = errors.New("a previous uncertain ENV mutation was superseded; fetch the scope and retry")
)

type pendingMutation struct {
	Schema          string `json:"schema"`
	AccountID       string `json:"account_id"`
	SubjectID       string `json:"subject_id"`
	Scope           string `json:"scope"`
	MachineID       string `json:"machine_id,omitempty"`
	Name            string `json:"name"`
	Mutation        string `json:"mutation"`
	ExpectedVersion int64  `json:"expected_version"`
	ExpectedETag    string `json:"expected_etag"`
	OperationID     string `json:"operation_id"`
	ManifestID      string `json:"manifest_id"`
	KeyEpoch        int64  `json:"key_epoch"`
	Envelope        string `json:"envelope"`
}

func (manager Manager) pendingPath(machineID string) (string, error) {
	root := filepath.Clean(manager.Store.Path)
	if !filepath.IsAbs(root) || root == "." || root == string(filepath.Separator) {
		return "", errors.New("ENV mutation state directory is invalid")
	}
	directory := filepath.Join(root, "environment-operations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create ENV mutation state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("ENV mutation state directory is not private")
	}
	digest := sha256.Sum256([]byte(manager.AccountID + "\x00" + manager.SubjectID + "\x00" + machineID))
	return filepath.Join(directory, "pending-"+hex.EncodeToString(digest[:16])+".json"), nil
}

func (manager Manager) loadPendingMutation(machineID string) (pendingMutation, bool, error) {
	path, err := manager.pendingPath(machineID)
	if err != nil {
		return pendingMutation{}, false, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return pendingMutation{}, false, nil
	}
	if err != nil {
		return pendingMutation{}, false, fmt.Errorf("open pending ENV mutation: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumPendingMutationFileBytes {
		return pendingMutation{}, false, errors.New("pending ENV mutation file is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPendingMutationFileBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumPendingMutationFileBytes {
		clear(raw)
		return pendingMutation{}, false, errors.New("pending ENV mutation file is invalid")
	}
	defer clear(raw)
	var value pendingMutation
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return pendingMutation{}, false, errors.New("pending ENV mutation file is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytesEqual(canonical, raw) || validatePendingMutation(value, manager.AccountID, manager.SubjectID, machineID) != nil {
		clear(canonical)
		return pendingMutation{}, false, errors.New("pending ENV mutation file is invalid")
	}
	clear(canonical)
	return value, true, nil
}

func (manager Manager) storePendingMutation(value pendingMutation) error {
	if err := validatePendingMutation(value, manager.AccountID, manager.SubjectID, value.MachineID); err != nil {
		return err
	}
	path, err := manager.pendingPath(value.MachineID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maximumPendingMutationFileBytes {
		clear(raw)
		return errors.New("pending ENV mutation is too large")
	}
	defer clear(raw)
	if err := atomicfile.Write(path, raw, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		return fmt.Errorf("store pending ENV mutation: %w", err)
	}
	return nil
}

func (manager Manager) deletePendingMutation(machineID string) error {
	path, err := manager.pendingPath(machineID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete pending ENV mutation: %w", err)
	}
	return syncMutationDirectory(filepath.Dir(path))
}

func (manager Manager) reconcilePendingMutation(ctx context.Context, pending pendingMutation) (MutationResult, error) {
	response, err := manager.Client.PutEnvironmentManifest(ctx, pending.MachineID, api.EnvironmentManifestMutation{Schema: api.EnvironmentManifestMutationSchemaV1, ExpectedVersion: pending.ExpectedVersion, OperationID: pending.OperationID, Envelope: pending.Envelope}, pending.ExpectedETag)
	if err == nil {
		if response.ManifestID != pending.ManifestID || response.Version != pending.ExpectedVersion+1 || response.KeyEpoch != pending.KeyEpoch {
			return MutationResult{}, ErrIntegrity
		}
		if err := manager.deletePendingMutation(pending.MachineID); err != nil {
			return MutationResult{}, err
		}
		return MutationResult{Name: pending.Name, Version: response.Version, KeyEpoch: response.KeyEpoch, ManifestID: response.ManifestID, ETag: response.ETag}, ErrPendingMutationReconciled
	}
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "version_conflict" && apiErr.Code != "precondition_failed" {
		return MutationResult{}, err
	}
	current, currentErr := manager.Client.GetEnvironmentManifest(ctx, pending.MachineID)
	if currentErr != nil {
		return MutationResult{}, err
	}
	if current.ManifestID == pending.ManifestID && current.Version == pending.ExpectedVersion+1 && current.KeyEpoch == pending.KeyEpoch {
		if deleteErr := manager.deletePendingMutation(pending.MachineID); deleteErr != nil {
			return MutationResult{}, deleteErr
		}
		return MutationResult{Name: pending.Name, Version: current.Version, KeyEpoch: current.KeyEpoch, ManifestID: current.ManifestID, ETag: current.ETag}, ErrPendingMutationReconciled
	}
	if current.Version > pending.ExpectedVersion {
		if deleteErr := manager.deletePendingMutation(pending.MachineID); deleteErr != nil {
			return MutationResult{}, deleteErr
		}
		return MutationResult{}, ErrPendingMutationSuperseded
	}
	return MutationResult{}, err
}

func validatePendingMutation(value pendingMutation, accountID, subjectID, machineID string) error {
	if value.Schema != pendingMutationSchema || value.AccountID != accountID || value.SubjectID != subjectID || value.MachineID != machineID || value.ExpectedVersion < 1 || value.KeyEpoch < 1 || !operationIDPattern.MatchString(value.OperationID) || !documentIDPattern.MatchString(value.ManifestID) || value.Envelope == "" {
		return errors.New("pending ENV mutation is invalid")
	}
	wantScope := "global"
	if machineID != "" {
		wantScope = "machine"
	}
	if value.Scope != wantScope || value.Mutation != "set" && value.Mutation != "unset" || validateVariableName(value.Name) != nil {
		return errors.New("pending ENV mutation is invalid")
	}
	if err := apiValidateETag(value.ExpectedETag, machineID, value.ExpectedVersion); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value.Envelope)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 || base64.RawURLEncoding.EncodeToString(raw) != value.Envelope {
		clear(raw)
		return errors.New("pending ENV mutation envelope is invalid")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	if value.ManifestID != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("pending ENV mutation digest is invalid")
	}
	return nil
}

func apiValidateETag(etag, machineID string, version int64) error {
	want := `"environment-global-` + fmt.Sprint(version) + `"`
	if machineID != "" {
		want = `"environment-machine-` + machineID + `-` + fmt.Sprint(version) + `"`
	}
	if etag != want {
		return errors.New("pending ENV mutation ETag is invalid")
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

var operationIDPattern = regexp.MustCompile(`^envop_[0-9a-f]{32}$`)
var documentIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
