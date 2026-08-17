//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

// runHostd is the stable supervisor entry point. NewHost performs the same
// ownership split in-process during the development migration; worker
// processes use runWorker and the hostd lifecycle socket for fenced cutover.
func runHostd(ctx context.Context, output io.Writer) error { return runProduction(ctx, output) }

func runWorker(ctx context.Context, args []string, output, stderr io.Writer) error {
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "", "hostd lifecycle socket")
	tokenPath := flags.String("token-file", "", "hostd capability token")
	workerID := flags.String("worker-id", "", "runtime worker identity")
	version := flags.String("version", buildinfo.Version, "runtime version")
	apiMin := flags.Uint("api-min", 1, "minimum hostd API")
	apiMax := flags.Uint("api-max", 1, "maximum hostd API")
	heartbeat := flags.Duration("heartbeat", 5*time.Second, "hostd heartbeat interval")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !filepath.IsAbs(*socket) || !filepath.IsAbs(*tokenPath) || *workerID == "" || *version == "" || *apiMin == 0 || *apiMin > 1024 || *apiMax < *apiMin || *apiMax > 1024 || *heartbeat < time.Second || *heartbeat > time.Minute {
		return errors.New("invalid worker invocation")
	}
	token, err := readWorkerToken(*tokenPath)
	if err != nil {
		return err
	}
	client, err := hostdproto.NewClient(*socket, token, 5*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Request(ctx, hostdproto.Hello{WorkerID: *workerID, Version: *version, APIMin: uint16(*apiMin), APIMax: uint16(*apiMax)})
	if err != nil {
		return err
	}
	welcome, ok := response.(*hostdproto.Welcome)
	if !ok {
		return errors.New("hostd returned invalid worker lease")
	}
	ready := hostdproto.Ready{WorkerID: welcome.WorkerID, APIVersion: welcome.APIVersion, Epoch: welcome.Epoch, Lease: welcome.Lease}
	if _, err := client.Request(ctx, ready); err != nil {
		return err
	}
	activate := hostdproto.Activate{WorkerID: welcome.WorkerID, APIVersion: welcome.APIVersion, Epoch: welcome.Epoch, Lease: welcome.Lease}
	if _, err := client.Request(ctx, activate); err != nil {
		return err
	}
	fmt.Fprintln(output, "pb runtime worker ready")
	ticker := time.NewTicker(*heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_, err := client.Request(ctx, hostdproto.Heartbeat{WorkerID: welcome.WorkerID, APIVersion: welcome.APIVersion, Epoch: welcome.Epoch, Lease: welcome.Lease})
			if err != nil {
				return fmt.Errorf("hostd worker heartbeat: %w", err)
			}
		}
	}
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
