package hostd

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
)

type testService struct {
	mu        sync.Mutex
	starts    int
	shutdowns int
}

func (s *testService) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	return nil
}
func (s *testService) Shutdown(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdowns++
	return nil
}

type sessionOwner struct{ sessions *session.Manager }

func (sessionOwner) Start(context.Context) error          { return nil }
func (s sessionOwner) Shutdown(ctx context.Context) error { return s.sessions.Shutdown(ctx) }

type tunnelWorkloadsStub struct{ testService }

func (*tunnelWorkloadsStub) ResourceCounts() map[string]uint64 {
	return map[string]uint64{"tunnels": 1}
}

type failingStartService struct {
	testService
	startErr    error
	shutdownErr error
}

func (s *failingStartService) Start(context.Context) error {
	s.mu.Lock()
	s.starts++
	s.mu.Unlock()
	return s.startErr
}

func (s *failingStartService) Shutdown(context.Context) error {
	s.mu.Lock()
	s.shutdowns++
	s.mu.Unlock()
	return s.shutdownErr
}

type testPTY struct {
	mu         sync.Mutex
	terminated bool
	reader     *io.PipeReader
	writer     *io.PipeWriter
}

func newTestPTY() *testPTY                                    { r, w := io.Pipe(); return &testPTY{reader: r, writer: w} }
func (p *testPTY) Read(buffer []byte) (int, error)            { return p.reader.Read(buffer) }
func (p *testPTY) Write(data []byte) (int, error)             { return len(data), nil }
func (*testPTY) Resize(pty.Dimensions) error                  { return nil }
func (*testPTY) Signal(pty.Signal) error                      { return nil }
func (*testPTY) Wait(context.Context) (pty.ExitResult, error) { return pty.ExitResult{}, nil }
func (p *testPTY) Terminate(context.Context, time.Duration) (pty.ExitResult, error) {
	p.mu.Lock()
	p.terminated = true
	p.mu.Unlock()
	return pty.ExitResult{}, nil
}
func (p *testPTY) CloseIO() error      { _ = p.writer.Close(); return p.reader.Close() }
func (p *testPTY) wasTerminated() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.terminated }

func TestWorkerReplacementDoesNotTerminateHostdOwnedPTY(t *testing.T) {
	process := newTestPTY()
	sessions, err := session.NewManager(session.ManagerConfig{
		Launch:       func(pty.Command) (session.PTYProcess, error) { return process, nil },
		HistoryBytes: 1024, AttachmentBytes: 1024, MaxSessions: 1, MaxAttachments: 1, MaxInputDecisions: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Create(context.Background(), session.CreateRequest{Name: "shell", Command: pty.Command{Path: "/bin/sh", CWD: "/"}}); err != nil {
		t.Fatal(err)
	}

	// The other workload fields are non-nil test sentinels. They are not used
	// by worker replacement and cannot be reached through WorkerController.
	tunnels := &tunnelWorkloadsStub{}
	d, err := New(Config{Workloads: Workloads{Sessions: sessions, Executions: &execprocess.Manager{}, Transfers: &filetransfer.Service{}, Tunnels: tunnels}, Components: []Component{{Name: "sessions", Required: true, Service: sessionOwner{sessions: sessions}}, {Name: "tunnels", Required: true, Service: tunnels}, {Name: "ingress", Required: true, Service: &testService{}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	controller, err := NewWorkerController(d)
	if err != nil {
		t.Fatal(err)
	}
	first, candidate := &testService{}, &testService{}
	if err := controller.Start(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := controller.Replace(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if process.wasTerminated() {
		t.Fatal("worker replacement terminated hostd-owned PTY")
	}
	if tunnels.shutdowns != 0 || d.Workloads().Tunnels != tunnels || d.Workloads().Tunnels.ResourceCounts()["tunnels"] != 1 {
		t.Fatalf("worker replacement changed stable tunnel ownership: shutdowns=%d workloads=%#v", tunnels.shutdowns, d.Workloads().Tunnels)
	}
	if snapshots := sessions.List(); len(snapshots) != 1 || snapshots[0].State != session.Running {
		t.Fatalf("sessions=%#v", snapshots)
	}
	if err := controller.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if process.wasTerminated() {
		t.Fatal("worker shutdown terminated hostd-owned PTY")
	}
	if tunnels.shutdowns != 0 {
		t.Fatalf("worker shutdown stopped tunnel manager %d times", tunnels.shutdowns)
	}
	if err := d.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !process.wasTerminated() {
		t.Fatal("hostd shutdown did not terminate owned PTY")
	}
	if tunnels.shutdowns != 1 {
		t.Fatalf("hostd shutdown stopped tunnel manager %d times", tunnels.shutdowns)
	}
}

func TestClientWorkloadsAllowTransfersWithoutCommandExecution(t *testing.T) {
	d, err := New(Config{
		Workloads:  Workloads{Transfers: &filetransfer.Service{}},
		Components: []Component{{Name: "ingress", Required: true, Service: &testService{}}},
	})
	if err != nil {
		t.Fatalf("new Client hostd: %v", err)
	}
	if d.Workloads().Sessions != nil || d.Workloads().Executions != nil || d.Workloads().Transfers == nil {
		t.Fatalf("Client workloads = %#v", d.Workloads())
	}
}

func TestHostWorkloadsRejectPartialCommandOwnership(t *testing.T) {
	_, err := New(Config{
		Workloads:  Workloads{Sessions: &session.Manager{}, Transfers: &filetransfer.Service{}},
		Components: []Component{{Name: "ingress", Required: true, Service: &testService{}}},
	})
	if err != ErrInvalidConfig {
		t.Fatalf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestStartCleansPartiallyStartedRequiredComponent(t *testing.T) {
	prior := &testService{}
	startErr := errors.New("partial start")
	failed := &failingStartService{startErr: startErr}
	d, err := New(Config{
		Workloads: Workloads{Transfers: &filetransfer.Service{}},
		Components: []Component{
			{Name: "prior", Required: true, Service: prior},
			{Name: "tunnels", Required: true, Service: failed},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); !errors.Is(err, startErr) {
		t.Fatalf("start error=%v", err)
	}
	if failed.shutdowns != 1 || prior.shutdowns != 1 {
		t.Fatalf("cleanup failed component=%d prior=%d", failed.shutdowns, prior.shutdowns)
	}
}

func TestOptionalStartFailureIsCleanedBeforeContinuing(t *testing.T) {
	failed := &failingStartService{startErr: errors.New("optional unavailable")}
	required := &testService{}
	d, err := New(Config{
		Workloads: Workloads{Transfers: &filetransfer.Service{}},
		Components: []Component{
			{Name: "optional", Required: false, Service: failed},
			{Name: "required", Required: true, Service: required},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if failed.shutdowns != 1 || required.starts != 1 {
		t.Fatalf("optional cleanup=%d required starts=%d", failed.shutdowns, required.starts)
	}
	if err := d.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if failed.shutdowns != 1 || required.shutdowns != 1 {
		t.Fatalf("shutdown optional=%d required=%d", failed.shutdowns, required.shutdowns)
	}
}

func TestWorkerReplacementReportsCommittedCandidateWhenPreviousCleanupFails(t *testing.T) {
	d, err := New(Config{
		Workloads:  Workloads{Transfers: &filetransfer.Service{}},
		Components: []Component{{Name: "stable", Required: true, Service: &testService{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	controller, err := NewWorkerController(d)
	if err != nil {
		t.Fatal(err)
	}
	stopErr := errors.New("previous cleanup failed")
	previous := &failingStartService{shutdownErr: stopErr}
	if err := controller.Start(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	candidate := &testService{}
	err = controller.Replace(context.Background(), candidate)
	var committed *ReplacementCommittedError
	if !errors.As(err, &committed) || !errors.Is(err, stopErr) {
		t.Fatalf("replace error=%v", err)
	}
	if controller.active != candidate || !controller.running || candidate.starts != 1 {
		t.Fatalf("candidate was not committed active=%#v running=%t starts=%d", controller.active, controller.running, candidate.starts)
	}
	if err := controller.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if candidate.shutdowns != 1 {
		t.Fatalf("candidate shutdowns=%d", candidate.shutdowns)
	}
	if err := d.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
