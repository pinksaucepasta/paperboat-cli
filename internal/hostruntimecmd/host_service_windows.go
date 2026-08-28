//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
)

// ExecuteHostService runs the legacy privileged availability endpoint as a
// native named-pipe server. New installations use hostd, but keeping this
// entry real is required for idempotent repair of existing installations.
func ExecuteHostService(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("pb __runtime-host-service", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pb: invalid host-service invocation")
		return 2
	}
	config, err := hostinstall.LoadWindowsRuntimeConfig()
	if err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	applier := hostservice.NewPlatformApplier(filepath.Join(hostinstall.WindowsProgramDataRoot(), "power-baseline.json"))
	authorizedKeys, err := hostservice.NewWindowsAuthorizedKeys()
	if err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	server, err := hostservice.New(hostservice.Config{SocketPath: hostservice.DefaultSocketPath(), StatePath: filepath.Join(hostinstall.WindowsProgramDataRoot(), "availability-policy.json"), SID: config.OwnerSID, Applier: applier, Version: buildinfo.Version, AuthorizedKeys: authorizedKeys})
	if err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	return 0
}
