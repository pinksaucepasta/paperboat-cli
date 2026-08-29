//go:build windows

package hostruntimecmd

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestWindowsUpdaterUsesRunningBinaryVersionDuringActivation(t *testing.T) {
	layout, err := service.DefaultLayout("windows")
	if err != nil {
		t.Fatal(err)
	}
	install := hostinstall.WindowsRuntimeConfig{
		OwnerSID:      "S-1-5-21-1-2-3-1001",
		MachineID:     "machine",
		ListenAddress: "127.0.0.1:8080",
		TokenFile:     hostinstall.WindowsHostdTokenPath(),
		SetupMode:     "host",
		StateRoot:     `C:\Users\Pujan\AppData\Local\Paperboat\runtime`,
		Artifact: bootstrap.ArtifactTarget{
			Version:       "2026.08.27.61",
			Architecture:  "amd64",
			RepositoryURL: "https://get.pprbt.dev/tuf",
		},
	}
	config := windowsUpdatedConfigFor(install, layout, "2026.08.27.62")
	if config.ActiveVersion != "2026.08.27.62" {
		t.Fatalf("active version = %q, want running candidate version", config.ActiveVersion)
	}
	if config.ActiveVersion == install.Artifact.Version {
		t.Fatal("candidate updater inherited the uncommitted persisted version")
	}
	if config.RuntimeStateRoot != install.StateRoot {
		t.Fatalf("runtime state root = %q, want persisted owner root %q", config.RuntimeStateRoot, install.StateRoot)
	}
}
