//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
)

type ClientInstallConfig struct {
	StateRoot, WorkspaceRoot, ControlURL, MachineID, ListenAddress string
	Artifact                                                       bootstrap.ArtifactTarget
}

func InstallClient(ctx context.Context, config ClientInstallConfig, stdin io.Reader, stdout, stderr io.Writer) error {
	account, err := user.Current()
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return err
	}
	shell, err := resolveUserShell("", os.Getenv)
	if err != nil {
		return err
	}
	artifactPath, err := bootstrap.FetchVerifiedArtifact(ctx, config.Artifact, filepath.Join(config.StateRoot, "tuf"), artifactHTTPClient())
	if err != nil {
		return err
	}
	// Darwin release artifacts are signed PKGs, not executable runtime images.
	// Materialize them through installer(8) before handing the executable path
	// to the privileged service installer. Linux artifacts are already native
	// executables and pass through unchanged.
	artifactPath, err = materializeBootstrapArtifact(ctx, artifactPath)
	if err != nil {
		return err
	}
	servicePath := os.Getenv("PATH")
	commandDirectory := filepath.Join(account.HomeDir, ".local", "bin")
	if !pathListContains(servicePath, commandDirectory) {
		servicePath = commandDirectory + string(os.PathListSeparator) + servicePath
	}
	request := hostinstall.Request{
		Schema: hostinstall.SchemaV1, Platform: runtime.GOOS, User: account.Username, UID: uid, Group: group.Name, GID: gid,
		Executable: artifactPath, Artifact: config.Artifact,
		Home: account.HomeDir, Path: servicePath, StateRoot: config.StateRoot, WorkspaceRoot: config.WorkspaceRoot,
		ControlURL: config.ControlURL, UserMachineID: config.MachineID, Shell: shell,
		HelperListenAddress: config.ListenAddress, SetupMode: "client",
	}
	previousGeneration := workerGeneration(config.StateRoot)
	fmt.Fprintln(stderr, "Administrator approval is required to install the Client service.")
	installCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := authorizeServiceInstall(installCtx, artifactPath, request, stdin, stdout, stderr); err != nil {
		return err
	}
	workerCommand, err := installWorkerCommand(commandDirectory, systemWorkerExecutable())
	if err != nil {
		return errors.Join(err, authorizeServiceOperation(ctx, artifactPath, "uninstall", request, stdout, stderr))
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 45*time.Second)
	defer readyCancel()
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		requestHTTP, _ := http.NewRequestWithContext(readyCtx, http.MethodGet, "http://"+config.ListenAddress+"/healthz", nil)
		response, requestErr := client.Do(requestHTTP)
		if requestErr == nil && bootstrapWorkerReady(readyCtx, response, config.StateRoot, config.Artifact.Version, previousGeneration, false) {
			if err := authorizeServiceOperation(ctx, artifactPath, "commit", request, stdout, stderr); err != nil {
				return errors.Join(err, authorizeServiceOperation(ctx, artifactPath, "uninstall", request, stdout, stderr), workerCommand.Rollback())
			}
			if err := workerCommand.Commit(); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "Paperboat Client service is ready.")
			return nil
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		select {
		case <-readyCtx.Done():
			return errors.Join(errors.New("Client service did not become ready"), authorizeServiceOperation(ctx, artifactPath, "uninstall", request, stdout, stderr), workerCommand.Rollback())
		case <-time.After(time.Second):
		}
	}
}
