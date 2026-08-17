//go:build linux || darwin

package hostdproto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestActivationPersistsFenceBeforePublishingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.json")
	persist := NewFenceStatePersister(path, os.Geteuid(), os.Getegid())
	controller, err := NewController(ControllerConfig{
		APIMin: 1, APIMax: 2, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 32)),
		InitialEpoch: 41, PersistActivation: persist,
	})
	if err != nil {
		t.Fatal(err)
	}
	welcome, err := controller.Negotiate(Hello{WorkerID: "runtime", Version: "2026.08.18.3", APIMin: 1, APIMax: 2})
	if err != nil || welcome.Epoch != 42 {
		t.Fatalf("welcome=%+v err=%v", welcome, err)
	}
	if err := controller.MarkReady(readyFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(welcome)); err != nil {
		t.Fatal(err)
	}
	state, err := LoadFenceState(path)
	if err != nil || state.Epoch != 42 || state.WorkerID != "runtime" {
		t.Fatalf("state=%+v err=%v", state, err)
	}

	restarted, err := NewController(ControllerConfig{APIMin: 1, APIMax: 2, InitialEpoch: state.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	next, err := restarted.Negotiate(Hello{WorkerID: "runtime-next", Version: "2026.08.19.0", APIMin: 1, APIMax: 2})
	if err != nil || next.Epoch != 43 {
		t.Fatalf("next=%+v err=%v", next, err)
	}
}

func TestFailedFencePersistenceDoesNotActivateCandidate(t *testing.T) {
	controller, err := NewController(ControllerConfig{
		APIMin: 1, APIMax: 1, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 32)),
		PersistActivation: func(Status) error { return errors.New("disk full") },
	})
	if err != nil {
		t.Fatal(err)
	}
	welcome, err := controller.Negotiate(Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.MarkReady(readyFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(welcome)); err == nil {
		t.Fatal("activation unexpectedly succeeded")
	}
	if got := controller.Status(); got.State != StateCandidate {
		t.Fatalf("status=%+v", got)
	}
}

func TestLoadFenceStateRejectsContradictoryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.json")
	if err := os.WriteFile(path, []byte(`{"schema":"paperboat.hostd-fence/v1","worker_id":"runtime","api_version":1,"epoch":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFenceState(path); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("error=%v", err)
	}
}
