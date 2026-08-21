package hostruntimecmd

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

func TestShouldInstallBootstrapCLI(t *testing.T) {
	session := &bootstrap.ClientSession{Schema: "paperboat.cli-session/v1"}
	if shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "host", ClientSession: session}) {
		t.Fatal("host-only enrollment must not require local CLI identity bootstrap")
	}
	if !shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "client", ClientSession: session}) {
		t.Fatal("client enrollment must bootstrap the local CLI identity")
	}
	if shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "client"}) {
		t.Fatal("enrollment without a CLI session must not bootstrap one")
	}
}
