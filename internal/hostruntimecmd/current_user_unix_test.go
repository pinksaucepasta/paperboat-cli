//go:build darwin || linux

package hostruntimecmd

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestCurrentUnixUserIgnoresEnvironmentAliases(t *testing.T) {
	want, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("USER", "incorrect-environment-user")
	t.Setenv("LOGNAME", "incorrect-environment-user")
	got, err := currentUnixUser()
	if err != nil {
		t.Fatal(err)
	}
	if got.Uid != want.Uid || got.Gid != want.Gid || got.Username != want.Username || got.HomeDir != want.HomeDir {
		t.Fatalf("currentUnixUser()=%+v want UID account %+v", got, want)
	}
}
