//go:build darwin && cgo

package httptransport

import "testing"

func TestNormalizeNativeExceptions(t *testing.T) {
	if got := normalizeNativeExceptions(" *.internal.test,localhost,<local>,10.0.0.0/8 "); got != ".internal.test,localhost,10.0.0.0/8" {
		t.Fatalf("exceptions=%q", got)
	}
}
