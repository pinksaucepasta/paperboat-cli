//go:build darwin || linux

package hostruntimecmd

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	gort "runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

// runHostd starts hostd-owned workloads first, then launches the active
// runtime artifact as a separately fenced child. No coordination runtime is
// started in-process here.
func runHostd(ctx context.Context, output io.Writer) error {
	socket, tokenPath, executable := os.Getenv("PAPERBOAT_HOSTD_SOCKET"), os.Getenv("PAPERBOAT_HOSTD_TOKEN_FILE"), os.Getenv("PAPERBOAT_RUNTIME_CURRENT")
	if !filepath.IsAbs(socket) || !filepath.IsAbs(tokenPath) || !filepath.IsAbs(executable) {
		return errors.New("hostd requires fixed socket, token, and active runtime paths")
	}
	token, err := readWorkerToken(tokenPath)
	if err != nil {
		return err
	}
	notifier, err := service.NewProcessNotifier()
	if err != nil {
		return err
	}
	if err := notifier.Starting(); err != nil {
		return err
	}
	host, err := hostruntime.NewProductionHost(ctx, buildinfo.Version, os.Getenv)
	if err != nil {
		_ = notifier.Degraded("hostd initialization failed")
		return err
	}
	if err := host.StartStable(ctx); err != nil {
		_ = notifier.Degraded("hostd startup failed")
		return err
	}
	server, err := hostdproto.NewServer(hostdproto.SocketConfig{SocketPath: socket, StatePath: filepath.Join(filepath.Dir(socket), "fence.json"), UID: os.Geteuid(), GID: os.Getegid(), Token: token, APIMin: 1, APIMax: 1, Workloads: host.WorkloadStatus})
	if err != nil {
		shutdownStableHost(host)
		return err
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	if err := waitForHostdSocket(ctx, socket, serverDone); err != nil {
		stopServer()
		shutdownStableHost(host)
		return err
	}
	worker, err := workerupdate.ExecStarter{}.Start(ctx, workerupdate.StartRequest{Executable: executable, Release: workerupdate.Release{Version: buildinfo.Version, Platform: gort.GOOS, Architecture: gort.GOARCH, HostdAPIMin: 1, HostdAPIMax: 1}, WorkerID: "runtime-" + strings.ReplaceAll(buildinfo.Version, " ", "-"), UID: os.Geteuid(), GID: os.Getegid(), HostdEndpoint: socket, Capability: token, MutationsDisabled: true})
	if err == nil {
		_, err = worker.Ready(ctx)
	}
	if err == nil {
		_, err = worker.Activate(ctx)
	}
	if err != nil {
		stopServer()
		shutdownStableHost(host)
		return err
	}
	if err := notifier.Ready(); err != nil {
		_ = worker.Stop(context.Background())
		stopServer()
		shutdownStableHost(host)
		return err
	}
	fmt.Fprintln(output, "pb hostd ready")
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stopErr := worker.Stop(shutdownCtx)
	stopServer()
	serverErr := <-serverDone
	return errors.Join(notifier.Draining(), stopErr, serverErr, notifier.Stopping(), host.ShutdownStable(shutdownCtx))
}

func waitForHostdSocket(ctx context.Context, socket string, done <-chan error) error {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("hostd lifecycle socket did not become ready")
		case <-tick.C:
		}
	}
}
func shutdownStableHost(host *hostruntime.Host) {
	if host != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = host.ShutdownStable(ctx)
	}
}

func runWorker(ctx context.Context, args []string, input io.Reader, output, stderr io.Writer) error {
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "", "hostd lifecycle socket")
	tokenPath := flags.String("token-file", "", "hostd capability token")
	tokenFD := flags.Int("token-fd", -1, "hostd capability token descriptor")
	workerID := flags.String("worker-id", "", "runtime worker identity")
	version := flags.String("version", buildinfo.Version, "runtime version")
	apiMin := flags.Uint("api-min", 1, "minimum hostd API")
	apiMax := flags.Uint("api-max", 1, "maximum hostd API")
	heartbeat := flags.Duration("heartbeat", 5*time.Second, "hostd heartbeat interval")
	waitActivation := flags.Bool("wait-activation", false, "wait for private supervisor activation")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !filepath.IsAbs(*socket) || (*tokenPath == "" && *tokenFD < 0) || (*tokenPath != "" && *tokenFD >= 0) || (*tokenPath != "" && !filepath.IsAbs(*tokenPath)) || *workerID == "" || *version == "" || *apiMin == 0 || *apiMin > 1024 || *apiMax < *apiMin || *apiMax > 1024 || *heartbeat < time.Second || *heartbeat > time.Minute {
		return errors.New("invalid worker invocation")
	}
	var token []byte
	var err error
	if *tokenPath != "" {
		token, err = readWorkerToken(*tokenPath)
	} else {
		token, err = readWorkerTokenFD(*tokenFD)
	}
	if err != nil {
		return err
	}
	client, err := hostdproto.NewClient(*socket, token, 5*time.Second)
	if err != nil {
		return err
	}
	candidate, err := hostdproto.NewCandidate(client, *workerID, *version, uint16(*apiMin), uint16(*apiMax))
	if err != nil {
		return err
	}
	ready, err := candidate.Ready(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "ready %d %d\n", ready.Epoch, ready.APIVersion)
	if *waitActivation {
		activation := make(chan error, 1)
		go func() {
			line, readErr := bufio.NewReader(io.LimitReader(input, 64)).ReadString('\n')
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				activation <- readErr
				return
			}
			if line != "activate\n" {
				activation <- errors.New("invalid worker activation")
				return
			}
			activation <- nil
		}()
		select {
		case <-ctx.Done():
			return nil
		case err := <-activation:
			if err != nil {
				return err
			}
		}
	}
	active, err := candidate.Activate(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "active %d %d\n", active.Epoch, active.APIVersion)
	ticker := time.NewTicker(*heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := candidate.Heartbeat(ctx); err != nil {
				return fmt.Errorf("hostd worker heartbeat: %w", err)
			}
		}
	}
}

func readWorkerTokenFD(descriptor int) ([]byte, error) {
	if descriptor < 3 || descriptor > 16 {
		return nil, errors.New("invalid worker token descriptor")
	}
	file := os.NewFile(uintptr(descriptor), "worker-token")
	if file == nil {
		return nil, errors.New("invalid worker token descriptor")
	}
	defer file.Close()
	token, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(token) != 32 {
		return nil, errors.New("invalid worker token descriptor")
	}
	return token, nil
}

func readWorkerToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("invalid worker token file")
	}
	token, err := os.ReadFile(path)
	if err != nil || len(token) != 32 {
		return nil, errors.New("invalid worker token file")
	}
	return token, nil
}
