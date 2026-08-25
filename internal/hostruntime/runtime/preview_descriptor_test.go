//go:build darwin || linux || windows

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

func TestDecodePreviewRuntimeDescriptorAcceptsProductionVariants(t *testing.T) {
	root := t.TempDir()
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	expired := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	serviceDefinition := filepath.Join(root, "services", "PaperboatPreview-27c0af6a0d919faa.json")
	if runtime.GOOS == "windows" {
		serviceDefinition = `C:\ProgramData\Paperboat\services\PaperboatPreview-27c0af6a0d919faa.json`
	}
	valid := map[string]PreviewRuntimeDescriptor{
		"exact real MSI cleanup descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "msi-cleanup-fixture",
			BindAddress:       "127.0.0.1",
			Port:              38123,
			ServiceGeneration: 1787503345680,
			Indefinite:        true,
			ServiceDefinition: serviceDefinition,
		},
		"finite plain descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "plain",
			Port:              32000,
			ExpiresAt:         &expires,
			ServiceDefinition: filepath.Join(root, "plain.json"),
		},
		"already expired plain descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "expired",
			Port:              32001,
			ExpiresAt:         &expired,
			ServiceDefinition: filepath.Join(root, "expired.json"),
		},
		"private pending descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "remote-pending",
			BindAddress:       "127.0.0.1",
			ServiceGeneration: 6,
			ExpiresAt:         &expires,
			ServiceDefinition: filepath.Join(root, "remote-pending.json"),
			PrivateRemote:     &PrivatePreviewRuntimeDescriptor{MachineID: "machine", MachineName: "Studio", EnvironmentID: "environment", MachineGeneration: 3, TargetPort: 2999},
		},
		"private ready descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "remote-ready",
			BindAddress:       "127.0.0.1",
			ServiceGeneration: 7,
			ExpiresAt:         &expires,
			ServiceDefinition: filepath.Join(root, "remote-ready.json"),
			Record:            &preview.ControlRecord{ID: "record", State: "ready", URL: "http://127.0.0.1:32000"},
			PrivateRemote:     &PrivatePreviewRuntimeDescriptor{MachineID: "machine", MachineName: "Studio", EnvironmentID: "environment", MachineGeneration: 4, TargetPort: 3000},
		},
		"private failed descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "remote-failed",
			BindAddress:       "127.0.0.1",
			ServiceGeneration: 8,
			Indefinite:        true,
			ServiceDefinition: filepath.Join(root, "remote-failed.json"),
			Record:            &preview.ControlRecord{ID: "record", State: "failed"},
			Failure:           &PreviewRuntimeFailure{Code: "preview_worker_start_failed"},
			PrivateRemote:     &PrivatePreviewRuntimeDescriptor{MachineID: "machine", MachineName: "Studio", EnvironmentID: "environment", MachineGeneration: 5, TargetPort: 3001},
		},
		"private serve descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "served",
			BindAddress:       "127.0.0.1",
			Port:              32123,
			ServiceGeneration: 9,
			ExpiresAt:         &expires,
			ServiceDefinition: filepath.Join(root, "served.json"),
			Serve:             &ServeRuntimeDescriptor{SourcePath: filepath.Join(root, "site"), SourceKind: servepkg.SourceDirectory, SourceIdentity: "identity", SPA: true, OwnerMode: "detached", Visibility: "private"},
		},
		"public serve descriptor": {
			Schema:            "paperboat.preview-runtime/v1",
			Name:              "public-served",
			BindAddress:       "127.0.0.1",
			ServiceGeneration: 10,
			Indefinite:        true,
			ServiceDefinition: filepath.Join(root, "public-served.json"),
			Serve:             &ServeRuntimeDescriptor{SourcePath: filepath.Join(root, "index.html"), SourceKind: servepkg.SourceFile, SourceIdentity: "identity", OwnerMode: "detached", Visibility: "public"},
		},
	}
	for name, want := range valid {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodePreviewRuntimeDescriptor(body)
			if err != nil {
				t.Fatalf("DecodePreviewRuntimeDescriptor() error = %v", err)
			}
			if err := ValidatePreviewRuntimeDescriptor(got); err != nil {
				t.Fatalf("ValidatePreviewRuntimeDescriptor() error = %v", err)
			}
			if got.Name != want.Name || got.ServiceDefinition != want.ServiceDefinition || got.Indefinite != want.Indefinite {
				t.Fatalf("decoded descriptor identity changed: got=%+v want=%+v", got, want)
			}
		})
	}
}

func TestDecodePreviewRuntimeDescriptorRejectsMalformedAndDriftedInput(t *testing.T) {
	root := t.TempDir()
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	base := PreviewRuntimeDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              "fixture",
		BindAddress:       "127.0.0.1",
		Port:              38123,
		ServiceGeneration: 1,
		Indefinite:        true,
		ServiceDefinition: filepath.Join(root, "fixture.json"),
	}
	private := &PrivatePreviewRuntimeDescriptor{MachineID: "machine", MachineName: "Studio", EnvironmentID: "environment", MachineGeneration: 1, TargetPort: 3000}
	serve := &ServeRuntimeDescriptor{SourcePath: filepath.Join(root, "site"), SourceKind: servepkg.SourceDirectory, SourceIdentity: "identity", OwnerMode: "detached", Visibility: "private"}
	cases := map[string]func(PreviewRuntimeDescriptor) PreviewRuntimeDescriptor{
		"unknown top-level field": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor { return d },
		"trailing JSON":           func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor { return d },
		"wrong schema": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Schema = "paperboat.preview-runtime/v0"
			return d
		},
		"empty name": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Name = ""
			return d
		},
		"neither lifetime": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Indefinite = false
			return d
		},
		"both lifetime forms": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.ExpiresAt = &expires
			return d
		},
		"plain zero port": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Port = 0
			return d
		},
		"relative service definition": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.ServiceDefinition = "services/fixture.json"
			return d
		},
		"both variants": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Serve = serve
			d.PrivateRemote = private
			return d
		},
		"serve missing loopback generation": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Port = 0
			d.ServiceGeneration = 0
			d.Serve = serve
			return d
		},
		"serve invalid source": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Port = 0
			d.Serve = &ServeRuntimeDescriptor{SourcePath: "relative", SourceKind: servepkg.SourceFile, SourceIdentity: "identity", OwnerMode: "detached", Visibility: "private"}
			return d
		},
		"private missing identity": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Port = 0
			d.PrivateRemote = &PrivatePreviewRuntimeDescriptor{MachineName: "Studio", EnvironmentID: "environment", MachineGeneration: 1, TargetPort: 3000}
			return d
		},
		"failure without failed record": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Failure = &PreviewRuntimeFailure{Code: "preview_worker_start_failed"}
			return d
		},
		"failure on ready record": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Record = &preview.ControlRecord{State: "ready"}
			d.Failure = &PreviewRuntimeFailure{Code: "preview_worker_start_failed"}
			return d
		},
		"unknown failure code": func(d PreviewRuntimeDescriptor) PreviewRuntimeDescriptor {
			d.Record = &preview.ControlRecord{State: "failed"}
			d.Failure = &PreviewRuntimeFailure{Code: "unexpected"}
			return d
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(mutate(base))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown top-level field":
				body = append(withoutObjectClosingBrace(body), []byte(`,"unexpected":true}`)...)
			case "trailing JSON":
				body = append(body, []byte(` {"unexpected":true}`)...)
			}
			if _, err := DecodePreviewRuntimeDescriptor(body); !errors.Is(err, ErrProductionInvalid) {
				t.Fatalf("DecodePreviewRuntimeDescriptor() error = %v, want ErrProductionInvalid", err)
			}
		})
	}

	t.Run("unknown nested field", func(t *testing.T) {
		body, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		body = append(withoutObjectClosingBrace(body), []byte(`,"record":{"unexpected":true}}`)...)
		if _, err := DecodePreviewRuntimeDescriptor(body); !errors.Is(err, ErrProductionInvalid) {
			t.Fatalf("DecodePreviewRuntimeDescriptor() error = %v, want ErrProductionInvalid", err)
		}
	})
}

func TestPreviewRuntimeFailureCodesAreSanitizedAndDurable(t *testing.T) {
	root := t.TempDir()
	base := PreviewRuntimeDescriptor{
		Schema:            "paperboat.preview-runtime/v1",
		Name:              "public-served",
		BindAddress:       "127.0.0.1",
		ServiceGeneration: 1,
		Indefinite:        true,
		ServiceDefinition: filepath.Join(root, "public-served.json"),
		Record:            &preview.ControlRecord{State: "failed"},
		Serve:             &ServeRuntimeDescriptor{SourcePath: filepath.Join(root, "index.html"), SourceKind: servepkg.SourceFile, SourceIdentity: "identity", OwnerMode: "detached", Visibility: "public"},
	}
	codes := []string{
		previewFailureControlOrigin, previewFailureServiceDefinition, previewFailureIdentityOpen,
		previewFailureRegistration, previewFailureMachineControl, previewFailureCredentials,
		previewFailureControlClient, previewFailureControlList, previewFailureControlRegister,
		previewFailureRegistry, previewFailureRegistryRegister, previewFailureSender,
		previewFailureMonitor, previewFailureReporter, previewFailureJWKSFetcher,
		previewFailureJWKSCache, previewFailureJWKSRefresh, previewFailureAdmission,
		previewFailureDialer, previewFailureManager, previewFailureSupervisor,
		previewFailureMonitorStart, previewFailureReporterStart, previewFailureConnectorStart,
		previewFailureTargetProbe, previewFailureObservation, previewFailureConnectorReady,
		previewFailureReady, previewFailureDescriptorWrite,
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			descriptor := base
			descriptor.Failure = &PreviewRuntimeFailure{Code: code}
			body, err := json.Marshal(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePreviewRuntimeDescriptor(body); err != nil {
				t.Fatalf("stage code rejected: %v", err)
			}
		})
	}
}

func withoutObjectClosingBrace(value []byte) []byte {
	value = bytes.TrimSpace(value)
	return value[:len(value)-1]
}
