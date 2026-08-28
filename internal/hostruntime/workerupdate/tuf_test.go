package workerupdate

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

func TestActiveVersionPermittedEnforcesSignedRevocations(t *testing.T) {
	index := releaseindex.Index{Version: "2026.08.27.56"}
	if !activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("unrevoked previous release was rejected")
	}
	index.RevokedVersions = []string{"2026.08.27.55"}
	if activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("explicitly revoked release was accepted")
	}
	index.RevokedVersions = nil
	index.MinimumVersion = "2026.08.27.56"
	if activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("release below signed minimum was accepted")
	}
	index.MinimumVersion = ""
	index.Revoked = true
	if activeVersionPermitted(index, index.Version) {
		t.Fatal("revoked current release was accepted")
	}
}
