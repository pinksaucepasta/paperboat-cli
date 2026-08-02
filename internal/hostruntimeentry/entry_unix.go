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

func InstallServeService(ctx context.Context, executable, stateRoot, name string, source servepkg.Source, spa bool, expiresAt *time.Time, indefinite bool) error {
	_, err := hostruntime.InstallServeService(ctx, executable, stateRoot, name, source, spa, expiresAt, indefinite)
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
