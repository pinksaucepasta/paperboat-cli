//go:build windows

package store

import "testing"

func TestSQLiteURIPathKeepsWindowsVolumeInPath(t *testing.T) {
	path := `C:\ProgramData\Paperboat\runtime\state.db`
	if got, want := sqliteURIPath(path), "/C:/ProgramData/Paperboat/runtime/state.db"; got != want {
		t.Fatalf("sqlite URI path = %q, want %q", got, want)
	}
}
