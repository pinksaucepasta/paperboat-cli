//go:build darwin || linux

package hostruntimeentry

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

type ConfigWorkerConfig = hostruntime.ProductionConfigWorkerConfig
type PreviewWorkerConfig = hostruntime.ProductionPreviewWorkerConfig
type ServeWorkerConfig = hostruntime.ProductionServeWorkerConfig
type PrivatePreviewRuntimeDescriptor = hostruntime.PrivatePreviewRuntimeDescriptor

var ErrPreviewServiceMissing = hostruntime.ErrPreviewServiceMissing
var ErrPreviewServiceFailed = hostruntime.ErrPreviewServiceFailed

func RunConfigWorker(ctx context.Context, config ConfigWorkerConfig) error {
	return hostruntime.RunProductionConfigWorker(ctx, config)
}

func RunPreviewWorker(ctx context.Context, config PreviewWorkerConfig) error {
	return hostruntime.RunProductionPreviewWorker(ctx, config)
}

func RunServeWorker(ctx context.Context, config ServeWorkerConfig) error {
	return hostruntime.RunProductionServeWorker(ctx, config)
}

func InstallPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool) error {
	_, err := hostruntime.InstallPreviewService(ctx, executable, stateRoot, name, port, expiresAt, indefinite)
	return err
}

func InstallPrivatePreviewService(ctx context.Context, executable, stateRoot, name string, remote PrivatePreviewRuntimeDescriptor, expiresAt *time.Time, indefinite bool, maximumPrivate int) error {
	_, err := hostruntime.InstallPrivatePreviewService(ctx, executable, stateRoot, name, remote, expiresAt, indefinite, maximumPrivate)
	return err
}

func ReadPrivatePreviewService(stateRoot, name string) (PrivatePreviewRuntimeDescriptor, error) {
	return hostruntime.ReadPrivatePreviewService(stateRoot, name)
}

func MarkPrivatePreviewServiceReady(stateRoot, name, rawURL string) error {
	return hostruntime.MarkPrivatePreviewServiceReady(stateRoot, name, rawURL)
}

func BeginPrivatePreviewService(stateRoot, name string) error {
	return hostruntime.BeginPrivatePreviewService(stateRoot, name)
}

func CompletePrivatePreviewService(ctx context.Context, stateRoot, name string) error {
	return hostruntime.CompletePrivatePreviewService(ctx, stateRoot, name)
}

func InstallServeService(ctx context.Context, executable, stateRoot, name string, source servepkg.Source, spa bool, expiresAt *time.Time, indefinite, public bool, listenPort uint16) error {
	_, err := hostruntime.InstallServeService(ctx, executable, stateRoot, name, source, spa, expiresAt, indefinite, public, listenPort)
	return err
}

func WaitPreviewServiceReady(ctx context.Context, stateRoot, name string) (preview.ControlRecord, error) {
	return hostruntime.WaitPreviewServiceReady(ctx, stateRoot, name)
}

func RemovePreviewService(ctx context.Context, stateRoot, name string) error {
	return hostruntime.RemovePreviewService(ctx, stateRoot, name)
}

func RemoveAllPreviewServices(ctx context.Context, stateRoot string) error {
	return hostruntime.RemoveAllPreviewServices(ctx, stateRoot)
}

func ReconcileExpiredPreviewServices(ctx context.Context, stateRoot string, now time.Time) error {
	return hostruntime.ReconcileExpiredPreviewServices(ctx, stateRoot, now)
}
