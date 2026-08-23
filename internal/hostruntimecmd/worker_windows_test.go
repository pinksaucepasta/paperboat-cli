//go:build windows

package hostruntimecmd

import (
	"context"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestWindowsWorkerRejectsNonPipeEndpoint(t *testing.T) {
	err := runWorker(context.Background(), []string{
		"--socket", `C:\\unsafe.sock`, "--token-file", `C:\\token`, "--worker-id", "runtime-test",
	}, strings.NewReader(""), nilWriter{}, nilWriter{})
	if err == nil || !strings.Contains(err.Error(), "invalid worker invocation") {
		t.Fatalf("err = %v, want invalid Windows worker invocation", err)
	}
}

func TestWindowsHostdWorkerEnvironmentCarriesInstalledRole(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"host", "client"} {
		install := hostinstall.WindowsRuntimeConfig{SetupMode: role, OwnerSID: "S-1-5-21-1", TokenFile: hostinstall.WindowsHostdTokenPath(), StateRoot: `C:\State`, Workspace: `C:\Workspace`, ControlURL: "https://api.pprbt.dev", ListenAddress: "127.0.0.1:8080", MachineID: "machine"}
		environment := windowsHostdWorkerEnvironment(install, layout, `C:\Program Files\Paperboat\runtime.exe`)
		if environment["PAPERBOAT_SETUP_MODE"] != role {
			t.Fatalf("role=%q environment=%q", role, environment["PAPERBOAT_SETUP_MODE"])
		}
	}
}

func TestParseWindowsWorkerStatus(t *testing.T) {
	status, err := parseWindowsWorkerStatus("active 7 1\n", "active", "runtime-test")
	if err != nil {
		t.Fatal(err)
	}
	if status != (hostdproto.Status{State: hostdproto.StateActive, WorkerID: "runtime-test", Epoch: 7, APIVersion: 1}) {
		t.Fatalf("status = %+v", status)
	}
	if _, err := parseWindowsWorkerStatus("active 0 1\n", "active", "runtime-test"); err == nil {
		t.Fatal("zero lifecycle epoch was accepted")
	}
}

type nilWriter struct{}

func (nilWriter) Write(value []byte) (int, error) { return len(value), nil }
