package connect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeChild struct {
	wait    chan error
	stopped chan struct{}
	once    sync.Once
}

func (c *fakeChild) Wait() error { return <-c.wait }
func (c *fakeChild) Stop() error { c.once.Do(func() { close(c.stopped) }); return nil }

type fakeRunner struct{ children []*fakeChild }

func (r *fakeRunner) Start(_ context.Context, _ RuntimeProcess) (Child, error) {
	c := r.children[0]
	r.children = r.children[1:]
	return c, nil
}

func TestSupervisorStopsPeersWhenOneRuntimeExits(t *testing.T) {
	first, second := &fakeChild{wait: make(chan error, 1), stopped: make(chan struct{})}, &fakeChild{wait: make(chan error), stopped: make(chan struct{})}
	runner := &fakeRunner{children: []*fakeChild{first, second}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	supervisor := Supervisor{Processes: []RuntimeProcess{{Name: "papercode", Executable: "/tmp/papercode"}, {Name: "agentunnel", Executable: "/tmp/agentunnel"}}, Runner: runner, RestartBackoff: time.Hour}
	done := make(chan error, 1)
	go func() { done <- supervisor.runOnce(ctx) }()
	first.wait <- errors.New("papercode exited")
	select {
	case <-second.stopped:
	case <-time.After(time.Second):
		t.Fatal("peer was not stopped")
	}
	if err := <-done; err == nil {
		t.Fatal("expected runtime exit error")
	}
}

func TestSupervisorRejectsRelativeRuntime(t *testing.T) {
	err := (Supervisor{Processes: []RuntimeProcess{{Name: "bad", Executable: "papercode"}}, Runner: &fakeRunner{}}).validate()
	if !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("error = %v", err)
	}
}
