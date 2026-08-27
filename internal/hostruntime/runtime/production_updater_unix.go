//go:build darwin || linux

package runtime

import (
	stdRuntime "runtime"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
)

func newProductionUpdaterClient() (*updated.Client, error) {
	socket := "/run/paperboat-updated/control.sock"
	if stdRuntime.GOOS == "darwin" {
		socket = "/var/run/paperboat-updated/control.sock"
	}
	return updated.NewClient(socket, 2*time.Second)
}
