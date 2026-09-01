//go:build windows

package hostruntimeentry

import (
	"context"

	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
)

type ConfigWorkerConfig = hostruntime.ProductionConfigWorkerConfig

func RunConfigWorker(ctx context.Context, config ConfigWorkerConfig) error {
	return hostruntime.RunProductionConfigWorker(ctx, config)
}
