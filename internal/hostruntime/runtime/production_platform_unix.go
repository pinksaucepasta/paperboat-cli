//go:build darwin || linux

package runtime

import (
	"context"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/availability"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

func productionManagedSSH(ctx context.Context, controlURL string, transport http.RoundTripper, registration runtimeidentity.Registration, identity managedSSHIdentitySource, generation uint64) (*managedssh.Host, Service, error) {
	return productionManagedSSHUnix(ctx, controlURL, transport, registration, identity, generation)
}

func validatedBYODShell(path string) (string, error) { return validatedBYODShellUnix(path) }
func validateBYODWorkspace(path string) error        { return validateBYODWorkspaceUnix(path) }

func newProductionAvailabilityHostClient(timeout time.Duration) (*availability.HostClient, error) {
	return availability.NewHostClient("/var/run/paperboat/host-service.sock", timeout)
}
