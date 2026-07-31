//go:build darwin || linux

package hostinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackFilesHandlesEveryActivationBoundary(t *testing.T) {
	for _, test := range []struct {
		name, current, rollback, want string
		hadWorker                     bool
	}{
		{name: "prepared only", hadWorker: true, current: "old", want: "old"},
		{name: "activated", hadWorker: true, current: "new", rollback: "old", want: "old"},
		{name: "fresh activation", current: "new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			paths := installPaths{worker: filepath.Join(root, "pb"), workerRollback: filepath.Join(root, "pb.rollback"), workerNext: filepath.Join(root, "pb.next"), journal: filepath.Join(root, "journal")}
			for path, value := range map[string]string{paths.worker: test.current, paths.workerRollback: test.rollback} {
				if value != "" {
					if err := os.WriteFile(path, []byte(value), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := rollbackFiles(paths, installJournal{HadWorker: test.hadWorker}); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(paths.worker)
			if test.want == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("worker remains: %q err=%v", body, err)
				}
			} else if err != nil || string(body) != test.want {
				t.Fatalf("worker=%q err=%v want=%q", body, err, test.want)
			}
		})
	}
}
