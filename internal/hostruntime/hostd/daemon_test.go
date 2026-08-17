package hostd

import (
	"context"
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
	d, err := New(Config{Workloads: Workloads{Sessions: sessions, Executions: &execprocess.Manager{}, Transfers: &filetransfer.Service{}}, Components: []Component{{Name: "sessions", Required: true, Service: sessionOwner{sessions: sessions}}, {Name: "ingress", Required: true, Service: &testService{}}}})
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
	if snapshots := sessions.List(); len(snapshots) != 1 || snapshots[0].State != session.Running {
		t.Fatalf("sessions=%#v", snapshots)
	}
	if err := controller.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if process.wasTerminated() {
		t.Fatal("worker shutdown terminated hostd-owned PTY")
	}
	if err := d.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !process.wasTerminated() {
		t.Fatal("hostd shutdown did not terminate owned PTY")
	}
}
