//go:build windows

package releaseeligibility

import "testing"

// Generic FileStore tests use t.TempDir, whose inherited owner/DACL is not the
// protected LocalSystem state directory required by production. Run those
// assertions only when the test host explicitly provides an equivalent path;
// the Windows security tests cover rejection of ordinary temporary paths.
func requireUsableStoreTestPath(t *testing.T, store FileStore) {
	t.Helper()
	if err := validateParentDirectory(store.Path); err != nil {
		t.Skipf("requires a protected LocalSystem eligibility directory: %v", err)
	}
}
