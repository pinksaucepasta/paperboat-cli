//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
)

func runProduction(ctx context.Context, output io.Writer) error {
	host, err := runtime.NewProductionHost(ctx, buildinfo.Version, os.Getenv)
	if err != nil {
		return err
	}
	if err := host.Start(ctx); err != nil {
		return err
	}
	fmt.Fprintln(output, "pb host runtime ready")
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return host.Shutdown(shutdownCtx)
}
