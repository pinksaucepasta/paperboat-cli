//go:build darwin || linux

package hostruntimeentry

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
)

type ConfigWorkerConfig = hostruntime.ProductionConfigWorkerConfig
type PreviewWorkerConfig = hostruntime.ProductionPreviewWorkerConfig

func RunConfigWorker(ctx context.Context, config ConfigWorkerConfig) error {
	return hostruntime.RunProductionConfigWorker(ctx, config)
}

func RunPreviewWorker(ctx context.Context, config PreviewWorkerConfig) error {
	return hostruntime.RunProductionPreviewWorker(ctx, config)
}

func InstallPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool) error {
	_, err := hostruntime.InstallPreviewService(ctx, executable, stateRoot, name, port, expiresAt, indefinite)
	return err
}

func WaitPreviewServiceReady(ctx context.Context, stateRoot, name string) (preview.ControlRecord, error) {
	return hostruntime.WaitPreviewServiceReady(ctx, stateRoot, name)
}
