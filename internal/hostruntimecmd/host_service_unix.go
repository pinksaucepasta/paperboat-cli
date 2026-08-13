//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func ExecuteHostService(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("pb __runtime-host-service", flag.ContinueOnError)
	flags.SetOutput(stderr)
	uid := flags.Int("uid", -1, "enrolled user ID")
	gid := flags.Int("gid", -1, "enrolled group ID")
	listenAddress := flags.String("listen-address", "", "runtime loopback health address")
	// Retained for service-definition compatibility. Artifact trust is
	// enforced by the runtime update manager and is not supplied on this
	// privileged control-socket invocation.
	_ = flags.String("artifact-public-key", "", "legacy artifact trust flag")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 || *uid < 0 || *gid < 0 || !validHostServiceAddress(*listenAddress) {
		fmt.Fprintln(stderr, "pb: invalid host-service invocation")
		return 2
	}
	notifier, err := service.NewProcessNotifier()
	if err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	if err := notifier.Starting(); err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	stateRoot, installRoot := "/var/lib/paperboat", "/usr/local/libexec/paperboat"
	if runtime.GOOS == "darwin" {
		stateRoot, installRoot = "/Library/Application Support/Paperboat", "/Library/PrivilegedHelperTools/Paperboat"
	}
	// Host runtime state is owned by the enrolled user. Keep privileged update
	// journals and rollback metadata in a root-owned child directory instead of
	// widening the updater's trust to the shared user-owned state root.
	updateStateRoot := filepath.Join(stateRoot, "privileged-updates")
	if err := os.MkdirAll(updateStateRoot, 0o700); err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	if err := os.Chmod(updateStateRoot, 0o700); err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	if err := os.Chown(updateStateRoot, 0, 0); err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	applier := hostservice.NewPlatformApplier(filepath.Join(stateRoot, "power-baseline.json"))
	updates, err := hostservice.NewUpdateManager(hostservice.UpdateConfig{
		StateRoot: updateStateRoot, BinaryPath: filepath.Join(installRoot, "pb"),
		CurrentVersion: buildinfo.Version, ListenAddress: *listenAddress,
	})
	if err != nil {
		_ = notifier.Degraded("update manager initialization failed")
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	server, err := hostservice.New(hostservice.Config{
		SocketPath: "/var/run/paperboat/host-service.sock", StatePath: filepath.Join(stateRoot, "availability-policy.json"),
		UID: *uid, GID: *gid, Applier: applier, Version: buildinfo.Version, Updates: updates,
		Ready: notifier.Ready, Heartbeat: notifier.Watchdog, HeartbeatInterval: notifier.WatchdogInterval(),
	})
	if err != nil {
		_ = notifier.Degraded("host service initialization failed")
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	runErr := server.Run(ctx)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		_ = notifier.Degraded("host service failed")
		fmt.Fprintln(stderr, "pb:", runErr)
		_ = notifier.Stopping()
		return 1
	}
	if err := notifier.Stopping(); err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	return 0
}

func validHostServiceAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	return err == nil && port != "" && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}
