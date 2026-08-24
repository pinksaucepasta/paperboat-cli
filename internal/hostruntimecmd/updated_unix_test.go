//go:build darwin || linux

package hostruntimecmd

import "testing"

func TestValidRuntimeIdentitySupportsOnlyExactPairs(t *testing.T) {
	for _, test := range []struct {
		uid, gid int
		want     bool
	}{
		{uid: 1000, gid: 1000, want: true},
		{uid: 0, gid: 0, want: true},
		{uid: 0, gid: 1000},
		{uid: 1000, gid: 0},
		{uid: -1, gid: -1},
	} {
		if got := validRuntimeIdentity(test.uid, test.gid); got != test.want {
			t.Fatalf("validRuntimeIdentity(%d, %d)=%v want %v", test.uid, test.gid, got, test.want)
		}
	}
}
