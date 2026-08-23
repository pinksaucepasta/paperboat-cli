//go:build windows

package hostruntimeentry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
	"github.com/pinksaucepasta/paperboat/internal/windows/previewbroker"
)

// Windows exposes the same worker contracts as macOS and Linux. Architecture
// status is a release-channel decision, never a reduced runtime protocol.
type ConfigWorkerConfig = hostruntime.ProductionConfigWorkerConfig
type PreviewWorkerConfig = hostruntime.ProductionPreviewWorkerConfig
type ServeWorkerConfig = hostruntime.ProductionServeWorkerConfig
type PrivatePreviewRuntimeDescriptor = hostruntime.PrivatePreviewRuntimeDescriptor

type WindowsPreviewMutation struct {
	Kind       string                          `json:"kind"`
	Root       string                          `json:"root"`
	Name       string                          `json:"name"`
	Port       uint16                          `json:"port,omitempty"`
	ExpiresAt  *time.Time                      `json:"expires_at,omitempty"`
	Indefinite bool                            `json:"indefinite"`
	Maximum    int                             `json:"maximum,omitempty"`
	Remote     PrivatePreviewRuntimeDescriptor `json:"remote,omitempty"`
	SourcePath string                          `json:"source_path,omitempty"`
	SourceKind servepkg.SourceKind             `json:"source_kind,omitempty"`
	SourceID   string                          `json:"source_identity,omitempty"`
	SPA        bool                            `json:"spa,omitempty"`
	Public     bool                            `json:"public,omitempty"`
	Now        time.Time                       `json:"now,omitempty"`
}

var ErrPreviewServiceMissing = hostruntime.ErrPreviewServiceMissing
var ErrPreviewServiceFailed = hostruntime.ErrPreviewServiceFailed

var (
	loadWindowsPreviewRuntimeConfig = hostinstall.LoadWindowsRuntimeConfig
	evalWindowsPreviewExecutable    = filepath.EvalSymlinks
)

func RunConfigWorker(ctx context.Context, config ConfigWorkerConfig) error {
	return hostruntime.RunProductionConfigWorker(ctx, config)
}
func RunPreviewWorker(ctx context.Context, config PreviewWorkerConfig) error {
	return hostruntime.RunProductionPreviewWorker(ctx, config)
}
func RunServeWorker(ctx context.Context, config ServeWorkerConfig) error {
	return hostruntime.RunProductionServeWorker(ctx, config)
}
func InstallPreviewService(ctx context.Context, executable, root, name string, port uint16, expires *time.Time, indefinite bool) error {
	return applyOrElevatePreviewMutation(ctx, executable, WindowsPreviewMutation{Kind: "preview", Root: root, Name: name, Port: port, ExpiresAt: expires, Indefinite: indefinite})
}
func InstallPrivatePreviewService(ctx context.Context, executable, root, name string, remote PrivatePreviewRuntimeDescriptor, expires *time.Time, indefinite bool, maximum int) error {
	return applyOrElevatePreviewMutation(ctx, executable, WindowsPreviewMutation{Kind: "private", Root: root, Name: name, Remote: remote, ExpiresAt: expires, Indefinite: indefinite, Maximum: maximum})
}
func ReadPrivatePreviewService(root, name string) (PrivatePreviewRuntimeDescriptor, error) {
	return hostruntime.ReadPrivatePreviewService(root, name)
}
func MarkPrivatePreviewServiceReady(root, name, raw string) error {
	return hostruntime.MarkPrivatePreviewServiceReady(root, name, raw)
}
func MarkPrivatePreviewServiceFailed(root, name string, cause error) error {
	return hostruntime.MarkPrivatePreviewServiceFailed(root, name, cause)
}
func BeginPrivatePreviewService(root, name string) error {
	return hostruntime.BeginPrivatePreviewService(root, name)
}
func CompletePrivatePreviewService(ctx context.Context, root, name string) error {
	return hostruntime.CompletePrivatePreviewService(ctx, root, name)
}
func InstallServeService(ctx context.Context, executable, root, name string, source servepkg.Source, spa bool, expires *time.Time, indefinite, public bool, listenPort uint16) error {
	identity, err := source.Identity()
	if err != nil {
		return err
	}
	return applyOrElevatePreviewMutation(ctx, executable, WindowsPreviewMutation{Kind: "serve", Root: root, Name: name, SourcePath: source.Path, SourceKind: source.Kind, SourceID: identity, SPA: spa, ExpiresAt: expires, Indefinite: indefinite, Public: public, Port: listenPort})
}
func WaitPreviewServiceReady(ctx context.Context, root, name string) (preview.ControlRecord, error) {
	return hostruntime.WaitPreviewServiceReady(ctx, root, name)
}
func RemovePreviewService(ctx context.Context, root, name string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return applyOrElevatePreviewMutation(ctx, executable, WindowsPreviewMutation{Kind: "remove", Root: root, Name: name})
}
func RemoveAllPreviewServices(ctx context.Context, root string) error {
	if !elevation.IsCurrentProcessElevated() {
		return requestWindowsPreviewBroker(ctx, WindowsPreviewMutation{Kind: "remove_all", Root: root, Name: "remove-all"})
	}
	return hostruntime.RemoveAllPreviewServices(ctx, root)
}
func ReconcileExpiredPreviewServices(ctx context.Context, root string, now time.Time) error {
	if _, err := os.Stat(filepath.Join(root, "previews", "active")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return applyOrElevatePreviewMutation(ctx, executable, WindowsPreviewMutation{Kind: "reconcile", Root: root, Name: "reconcile-expired", Now: now})
}

func applyOrElevatePreviewMutation(ctx context.Context, executable string, request WindowsPreviewMutation) error {
	if !elevation.IsCurrentProcessElevated() {
		return requestWindowsPreviewBroker(ctx, request)
	}
	return ApplyWindowsPreviewMutation(ctx, request)
}

func requestWindowsPreviewBroker(ctx context.Context, request WindowsPreviewMutation) error {
	install, err := hostinstall.LoadWindowsRuntimeConfig()
	if err != nil {
		return errors.Join(previewbroker.ErrUnavailable, err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	token, err := os.ReadFile(install.TokenFile)
	if err != nil {
		return errors.Join(previewbroker.ErrUnavailable, err)
	}
	return previewbroker.Request(ctx, install.OwnerSID, previewbroker.DeriveToken(token), payload)
}

func ApplyEncodedWindowsPreviewMutation(ctx context.Context, payload []byte) error {
	var request WindowsPreviewMutation
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&request) != nil || !errors.Is(decoder.Decode(&extra), io.EOF) {
		return errors.New("invalid Windows preview mutation")
	}
	return ApplyWindowsPreviewMutation(ctx, request)
}

func ApplyWindowsPreviewMutation(ctx context.Context, request WindowsPreviewMutation) error {
	if !validWindowsPreviewMutationShape(request) {
		return errors.New("invalid elevated Windows preview mutation")
	}
	install, err := loadWindowsPreviewRuntimeConfig()
	if err != nil || request.Root != install.StateRoot {
		return errors.New("Windows preview mutation does not match the enrolled runtime")
	}
	var executable string
	switch request.Kind {
	case "preview":
		layout, layoutErr := hostservice.DefaultLayout("windows")
		if layoutErr != nil {
			return layoutErr
		}
		executable, err = evalWindowsPreviewExecutable(layout.RuntimeCurrent)
		if err != nil {
			return err
		}
		_, err = hostruntime.InstallPreviewService(ctx, executable, request.Root, request.Name, request.Port, request.ExpiresAt, request.Indefinite)
	case "private":
		layout, layoutErr := hostservice.DefaultLayout("windows")
		if layoutErr != nil {
			return layoutErr
		}
		executable, err = evalWindowsPreviewExecutable(layout.RuntimeCurrent)
		if err != nil {
			return err
		}
		_, err = hostruntime.InstallPrivatePreviewService(ctx, executable, request.Root, request.Name, request.Remote, request.ExpiresAt, request.Indefinite, request.Maximum)
	case "serve":
		layout, layoutErr := hostservice.DefaultLayout("windows")
		if layoutErr != nil {
			return layoutErr
		}
		executable, err = evalWindowsPreviewExecutable(layout.RuntimeCurrent)
		if err != nil {
			return err
		}
		var source servepkg.Source
		source, err = servepkg.ResolvePinnedSource(request.SourcePath, request.SourceKind, request.SourceID)
		if err == nil {
			_, err = hostruntime.InstallServeService(ctx, executable, request.Root, request.Name, source, request.SPA, request.ExpiresAt, request.Indefinite, request.Public, request.Port)
		}
	case "remove":
		err = hostruntime.RemovePreviewService(ctx, request.Root, request.Name)
	case "reconcile":
		if request.Now.IsZero() {
			err = errors.New("invalid elevated Windows preview reconciliation")
		} else {
			err = hostruntime.ReconcileExpiredPreviewServices(ctx, request.Root, request.Now.UTC())
		}
	case "remove_all":
		err = hostruntime.RemoveAllPreviewServices(ctx, request.Root)
	default:
		err = errors.New("invalid elevated Windows preview mutation")
	}
	return err
}

func validWindowsPreviewMutationShape(request WindowsPreviewMutation) bool {
	return filepath.IsAbs(request.Root) && filepath.Clean(request.Root) == request.Root && request.Name != "" &&
		(request.Kind == "remove" || request.Kind == "remove_all" || request.Kind == "reconcile" || request.Indefinite != (request.ExpiresAt != nil))
}
