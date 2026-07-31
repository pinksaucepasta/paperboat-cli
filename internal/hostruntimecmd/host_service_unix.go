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
)

func ExecuteHostService(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("pb __runtime-host-service", flag.ContinueOnError)
	flags.SetOutput(stderr)
	uid := flags.Int("uid", -1, "enrolled user ID")
	gid := flags.Int("gid", -1, "enrolled group ID")
	publicKey := flags.String("artifact-public-key", "", "trusted release artifact public key")
	listenAddress := flags.String("listen-address", "", "runtime loopback health address")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 || *uid < 0 || *gid < 0 || *publicKey == "" || !validHostServiceAddress(*listenAddress) {
		fmt.Fprintln(stderr, "pb: invalid host-service invocation")
		return 2
	}
	stateRoot, installRoot := "/var/lib/paperboat", "/usr/local/libexec/paperboat"
	if runtime.GOOS == "darwin" {
		stateRoot, installRoot = "/Library/Application Support/Paperboat", "/Library/PrivilegedHelperTools/Paperboat"
	}
	applier := hostservice.NewPlatformApplier(filepath.Join(stateRoot, "power-baseline.json"))
	updates, err := hostservice.NewUpdateManager(hostservice.UpdateConfig{
		StateRoot: stateRoot, BinaryPath: filepath.Join(installRoot, "pb"), PublicKey: *publicKey,
		CurrentVersion: buildinfo.Version, ListenAddress: *listenAddress,
	})
	if err != nil {
		fmt.Fprintln(stderr, "pb:", err)
		return 1
	}
	server, err := hostservice.New(hostservice.Config{
		SocketPath: "/var/run/paperboat/host-service.sock", StatePath: filepath.Join(stateRoot, "availability-policy.json"),
		UID: *uid, GID: *gid, Applier: applier, Version: buildinfo.Version, Updates: updates,
	})
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

func validHostServiceAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	return err == nil && port != "" && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}
