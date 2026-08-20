package elevation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SchemaV1 = "paperboat.windows-elevation/v1"

	OperationRuntimeService = "runtime_service"
	OperationOpenSSH        = "openssh"

	ActionInstall          = "install"
	ActionInstallCommit    = "install_commit"
	ActionCommit           = "commit"
	ActionUninstall        = "uninstall"
	ActionUninstallPersist = "uninstall_persisted"
	ActionPurge            = "purge"
	ActionRepair           = "repair"
	ActionCleanupPreviews  = "cleanup_previews"
	ActionInstallPreview   = "install_preview"
	ActionRemovePreview    = "remove_preview"

	ActionOpenSSHSetup   = "setup"
	ActionOpenSSHRepair  = "repair"
	ActionOpenSSHRemove  = "remove"
	RequestFlagName      = "--request-file"
	ResultFlagName       = "--result-file"
	CancelFlagName       = "--cancel-file"
	BridgeCommand        = "bridge"
	MaxRequestBytes      = 128 << 10
	MaxResultBytes       = 16 << 10
	MaxOperationDuration = 5 * time.Minute
)

var (
	// ErrElevationDenied means that Windows did not start the elevated helper,
	// normally because the user denied or canceled the UAC prompt.
	ErrElevationDenied = errors.New("Windows administrator approval was denied")
	// ErrElevationCanceled means the caller canceled before the helper finished.
	ErrElevationCanceled = errors.New("elevated Windows operation canceled")
	// ErrElevationTimedOut means the bounded elevation operation exceeded its
	// deadline. The helper is canceled and terminated when possible.
	ErrElevationTimedOut = errors.New("elevated Windows operation timed out")
	// ErrElevationUnavailable means that the requested executable could not be
	// started as an elevated process.
	ErrElevationUnavailable = errors.New("elevated Windows helper unavailable")
	// ErrElevationProtocol means the helper did not return a valid protected
	// result for the request.
	ErrElevationProtocol = errors.New("invalid elevated Windows helper result")
	// ErrElevatedOperation is the stable wrapper for an operation failure that
	// occurred after UAC consent and was reported by the helper.
	ErrElevatedOperation = errors.New("elevated Windows operation failed")
	// ErrNotElevated is returned by the hidden child entrypoint if it is invoked
	// directly without a full administrator token.
	ErrNotElevated = errors.New("Windows elevated helper is not running as administrator")
	// ErrUnsupported is used by the non-Windows build of this package.
	ErrUnsupported = errors.New("Windows elevation is unavailable on this platform")
)

// Request is the only data persisted for an elevated operation. It contains
// operation metadata and a non-secret payload, never credentials, tokens, or
// private keys. The request and result paths are passed separately as opaque
// protected file names to the elevated child.
type Request struct {
	Schema     string          `json:"schema"`
	RequestID  string          `json:"request_id"`
	OwnerSID   string          `json:"owner_sid"`
	Operation  string          `json:"operation"`
	Action     string          `json:"action"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	CancelPath string          `json:"cancel_path"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

type Result struct {
	Schema       string `json:"schema"`
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

const (
	statusOK        = "ok"
	statusError     = "error"
	statusCanceled  = "canceled"
	statusTimedOut  = "timed_out"
	statusPending   = "pending"
	operationFailed = "operation_failed"
)

// RemoteError preserves a typed elevated-operation boundary while keeping the
// returned message bounded and separate from the UAC launch errors above.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	if e == nil {
		return ErrElevatedOperation.Error()
	}
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "the elevated Windows operation failed"
	}
	if e.Code == "" {
		return fmt.Sprintf("%s: %s", ErrElevatedOperation, message)
	}
	return fmt.Sprintf("%s (%s): %s", ErrElevatedOperation, e.Code, message)
}

func (*RemoteError) Unwrap() error { return ErrElevatedOperation }

func validOperationAction(operation, action string) bool {
	switch operation {
	case OperationRuntimeService:
		switch action {
		case ActionInstall, ActionInstallCommit, ActionCommit, ActionUninstall, ActionUninstallPersist, ActionPurge, ActionRepair, ActionCleanupPreviews, ActionInstallPreview, ActionRemovePreview:
			return true
		}
	case OperationOpenSSH:
		switch action {
		case ActionOpenSSHSetup, ActionOpenSSHRepair, ActionOpenSSHRemove:
			return true
		}
	}
	return false
}

func actionNeedsPayload(operation, action string) bool {
	return operation == OperationRuntimeService && (action == ActionInstall || action == ActionInstallCommit || action == ActionCommit || action == ActionUninstall || action == ActionCleanupPreviews || action == ActionInstallPreview || action == ActionRemovePreview)
}

func validateRequest(request Request) error {
	if request.Schema != SchemaV1 || strings.TrimSpace(request.RequestID) == "" || strings.TrimSpace(request.OwnerSID) == "" ||
		!validOperationAction(request.Operation, request.Action) || request.CancelPath == "" || request.CreatedAt.IsZero() || request.ExpiresAt.IsZero() ||
		!request.ExpiresAt.After(request.CreatedAt) || len(request.Payload) > MaxRequestBytes || (actionNeedsPayload(request.Operation, request.Action) && len(request.Payload) == 0) ||
		(!actionNeedsPayload(request.Operation, request.Action) && len(request.Payload) != 0) {
		return errors.New("invalid Windows elevation request")
	}
	if len(request.Payload) != 0 && !json.Valid(request.Payload) {
		return errors.New("invalid Windows elevation request payload")
	}
	return nil
}
