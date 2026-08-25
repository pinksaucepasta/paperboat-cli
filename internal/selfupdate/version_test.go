package selfupdate

import "testing"

func TestCompareVersionsNewDayAfterHighRevision(t *testing.T) {
	comparison, err := CompareVersions("2026.08.25.0", "2026.08.24.903")
	if err != nil || comparison != 1 {
		t.Fatalf("comparison=%d error=%v, want 1, nil", comparison, err)
	}
}
