//go:build darwin || linux || windows

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

type ServeRuntimeDescriptor struct {
	SourcePath     string              `json:"source_path"`
	SourceKind     servepkg.SourceKind `json:"source_kind"`
	SourceIdentity string              `json:"source_identity"`
	SPA            bool                `json:"spa"`
	OwnerMode      string              `json:"owner_mode"`
	Visibility     string              `json:"visibility"`
	ListenPort     uint16              `json:"listen_port,omitempty"`
}

type PreviewRuntimeDescriptor struct {
	Schema            string                           `json:"schema"`
	Name              string                           `json:"name"`
	BindAddress       string                           `json:"bind_address,omitempty"`
	Port              uint16                           `json:"port"`
	ServiceGeneration uint64                           `json:"service_generation,omitempty"`
	Indefinite        bool                             `json:"indefinite"`
	ExpiresAt         *time.Time                       `json:"expires_at,omitempty"`
	ServiceDefinition string                           `json:"service_definition"`
	Record            *preview.ControlRecord           `json:"record,omitempty"`
	Failure           *PreviewRuntimeFailure           `json:"failure,omitempty"`
	Serve             *ServeRuntimeDescriptor          `json:"serve,omitempty"`
	PrivateRemote     *PrivatePreviewRuntimeDescriptor `json:"private_remote,omitempty"`
}

type PreviewRuntimeFailure struct {
	Code string `json:"code"`
}

const (
	previewFailureListenerUnavailable = "preview_listener_unavailable"
	previewFailureWorkerStart         = "preview_worker_start_failed"
	previewFailureControlOrigin       = "preview_control_origin_invalid"
	previewFailureServiceDefinition   = "preview_service_definition"
	previewFailureIdentityOpen        = "preview_identity_open"
	previewFailureRegistration        = "preview_registration_read"
	previewFailureMachineControl      = "preview_machine_control_source"
	previewFailureCredentials         = "preview_credential_source"
	previewFailureControlClient       = "preview_control_client"
	previewFailureControlList         = "preview_control_list"
	previewFailureControlRegister     = "preview_control_register"
	previewFailureRegistry            = "preview_registry"
	previewFailureRegistryRegister    = "preview_registry_register"
	previewFailureSender              = "preview_sender"
	previewFailureMonitor             = "preview_monitor"
	previewFailureReporter            = "preview_reporter"
	previewFailureJWKSFetcher         = "preview_jwks_fetcher"
	previewFailureJWKSCache           = "preview_jwks_cache"
	previewFailureJWKSRefresh         = "preview_jwks_refresh"
	previewFailureAdmission           = "preview_admission"
	previewFailureDialer              = "preview_dialer"
	previewFailureManager             = "preview_manager"
	previewFailureSupervisor          = "preview_connector_supervisor"
	previewFailureMonitorStart        = "preview_monitor_start"
	previewFailureReporterStart       = "preview_reporter_start"
	previewFailureConnectorStart      = "preview_connector_start"
	previewFailureTargetProbe         = "preview_target_probe"
	previewFailureObservation         = "preview_observation_delivery"
	previewFailureConnectorReady      = "preview_connector_ready"
	previewFailureReady               = "preview_ready"
	previewFailureDescriptorWrite     = "preview_descriptor_write"
)

func validPreviewRuntimeFailureCode(code string) bool {
	switch code {
	case previewFailureListenerUnavailable, previewFailureWorkerStart,
		previewFailureControlOrigin, previewFailureServiceDefinition, previewFailureIdentityOpen, previewFailureRegistration,
		previewFailureMachineControl, previewFailureCredentials, previewFailureControlClient,
		previewFailureControlList, previewFailureControlRegister, previewFailureRegistry,
		previewFailureRegistryRegister, previewFailureSender, previewFailureMonitor,
		previewFailureReporter, previewFailureJWKSFetcher, previewFailureJWKSCache,
		previewFailureJWKSRefresh, previewFailureAdmission, previewFailureDialer,
		previewFailureManager, previewFailureSupervisor, previewFailureMonitorStart,
		previewFailureReporterStart, previewFailureConnectorStart, previewFailureTargetProbe,
		previewFailureObservation, previewFailureConnectorReady, previewFailureReady,
		previewFailureDescriptorWrite:
		return true
	default:
		return false
	}
}

type PrivatePreviewRuntimeDescriptor struct {
	MachineID         string `json:"machine_id"`
	MachineName       string `json:"machine_name"`
	EnvironmentID     string `json:"environment_id"`
	MachineGeneration uint64 `json:"machine_generation"`
	TargetPort        uint16 `json:"target_port"`
	ListenPort        uint16 `json:"listen_port,omitempty"`
}

// DecodePreviewRuntimeDescriptor strictly decodes one complete preview
// descriptor and validates the schema invariants shared by every local reader.
func DecodePreviewRuntimeDescriptor(data []byte) (PreviewRuntimeDescriptor, error) {
	var descriptor PreviewRuntimeDescriptor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&descriptor) != nil {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	if err := ValidatePreviewRuntimeDescriptor(descriptor); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	return descriptor, nil
}

// ValidatePreviewRuntimeDescriptor validates a decoded descriptor without
// accepting platform-specific omissions or unknown variant combinations.
func ValidatePreviewRuntimeDescriptor(descriptor PreviewRuntimeDescriptor) error {
	validPreview := descriptor.Serve == nil && descriptor.PrivateRemote == nil && descriptor.Port != 0
	validServe := descriptor.PrivateRemote == nil && validServeRuntimeDescriptor(descriptor.Serve) && descriptor.BindAddress == "127.0.0.1" && descriptor.ServiceGeneration > 0
	validRemote := descriptor.Serve == nil && validPrivatePreviewRuntimeDescriptor(descriptor.PrivateRemote) && descriptor.BindAddress == "127.0.0.1" && descriptor.ServiceGeneration > 0
	validVariant := validPreview || validServe || validRemote
	validLifetime := descriptor.Indefinite != (descriptor.ExpiresAt != nil)
	validServiceDefinition := descriptor.ServiceDefinition == "" || filepath.IsAbs(descriptor.ServiceDefinition)
	validFailure := descriptor.Failure == nil
	if descriptor.Failure != nil {
		validFailure = descriptor.Record != nil && descriptor.Record.State == "failed" &&
			validPreviewRuntimeFailureCode(descriptor.Failure.Code)
	}
	if descriptor.Schema != "paperboat.preview-runtime/v1" || !validVariant || descriptor.Name == "" || !validServiceDefinition || !validLifetime || !validFailure {
		return ErrProductionInvalid
	}
	return nil
}

func validPrivatePreviewRuntimeDescriptor(value *PrivatePreviewRuntimeDescriptor) bool {
	return value != nil && value.MachineID != "" && value.MachineName != "" && value.EnvironmentID != "" && value.MachineGeneration > 0 && value.TargetPort > 0
}

func validServeRuntimeDescriptor(value *ServeRuntimeDescriptor) bool {
	return value != nil && filepath.IsAbs(value.SourcePath) && value.SourceIdentity != "" &&
		(value.SourceKind == servepkg.SourceFile || value.SourceKind == servepkg.SourceDirectory) &&
		value.OwnerMode == "detached" && (value.Visibility == "private" || value.Visibility == "public") &&
		(value.Visibility == "private" || value.ListenPort == 0) &&
		(!value.SPA || value.SourceKind == servepkg.SourceDirectory)
}
