//go:build windows

package elevation

import (
	"encoding/json"
	"errors"
	"strings"
)

const (
	statusOK        = "ok"
	statusError     = "error"
	statusCanceled  = "canceled"
	statusTimedOut  = "timed_out"
	statusPending   = "pending"
	operationFailed = "operation_failed"
)

func validOperationAction(operation, action string) bool {
	switch operation {
	case OperationRuntimeService:
		switch action {
		case ActionInstall, ActionInstallCommit, ActionCommit, ActionUninstall, ActionUninstallPersist, ActionPurge, ActionRepair, ActionStop:
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
	return operation == OperationRuntimeService && (action == ActionInstall || action == ActionInstallCommit || action == ActionCommit || action == ActionUninstall)
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
