//go:build windows

package managedssh

import (
	"os"
	"testing"
)

func TestValidWindowsProfileRootStateAllowsOnlyUserOrSystemDirectory(t *testing.T) {
	const userSID = "S-1-5-21-1000"
	for _, test := range []struct {
		name    string
		mode    os.FileMode
		reparse bool
		owner   string
		want    bool
	}{
		{name: "current user", mode: os.ModeDir, owner: userSID, want: true},
		{name: "system", mode: os.ModeDir, owner: windowsSystemSID, want: true},
		{name: "administrators", mode: os.ModeDir, owner: "S-1-5-32-544"},
		{name: "foreign user", mode: os.ModeDir, owner: "S-1-5-21-2000"},
		{name: "reparse directory", mode: os.ModeDir, reparse: true, owner: userSID},
		{name: "symlink", mode: os.ModeSymlink, owner: userSID},
		{name: "regular file", mode: 0, owner: userSID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validWindowsProfileRootState(test.mode, test.reparse, test.owner, userSID); got != test.want {
				t.Fatalf("validWindowsProfileRootState() = %t, want %t", got, test.want)
			}
		})
	}
}
