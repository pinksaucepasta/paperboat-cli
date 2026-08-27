//go:build windows

package runtime

import (
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
)

func newProductionUpdaterClient() (*updated.Client, error) {
	return updated.NewClient(`\\.\pipe\PaperboatUpdatedControl`, 2*time.Second)
}
