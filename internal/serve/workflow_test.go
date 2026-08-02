package serve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
)

func TestForegroundWaitsForReadinessAndCleansUp(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := ResolveSource(file)
	ctx, cancel := context.WithCancel(context.Background())
	runnerStopped := make(chan struct{})
	foreground, err := StartForeground(ctx, ForegroundConfig{
		Source: source, Name: "docs", Duration: time.Hour,
		Preview: func(ctx context.Context, config PreviewRunConfig) error {
			connection, dialErr := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", fmtUint(config.Port)))
			if dialErr != nil {
				return dialErr
			}
			connection.Close()
			if err := config.Ready(preview.ControlRecord{URL: "https://docs.test", State: "ready"}); err != nil {
				return err
			}
			<-ctx.Done()
			close(runnerStopped)
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if foreground.Record.URL != "https://docs.test" {
		t.Fatalf("record = %#v", foreground.Record)
	}
	response, err := http.Get("http://127.0.0.1:" + fmtUint(foreground.server.Port()))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	cancel()
	if err := foreground.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runnerStopped:
	default:
		t.Fatal("preview runner was not stopped")
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmtUint(foreground.server.Port())), 100*time.Millisecond); err == nil {
		t.Fatal("static listener remains active")
	}
}

func TestForegroundReadinessFailureStopsListener(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	_ = os.WriteFile(file, []byte("ready"), 0o600)
	source, _ := ResolveSource(file)
	var port uint16
	_, err := StartForeground(context.Background(), ForegroundConfig{
		Source: source, Name: "docs", Duration: time.Hour, DrainTimeout: 100 * time.Millisecond,
		Preview: func(_ context.Context, config PreviewRunConfig) error {
			port = config.Port
			return errors.New("launch failed")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "launch failed") {
		t.Fatalf("error = %v", err)
	}
	if _, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmtUint(port)), 100*time.Millisecond); dialErr == nil {
		t.Fatal("static listener remains active")
	}
}

func TestForegroundStopsAtAbsolutePreviewExpiry(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	_ = os.WriteFile(file, []byte("ready"), 0o600)
	source, _ := ResolveSource(file)
	expires := time.Now().UTC().Add(150 * time.Millisecond)
	foreground, err := StartForeground(context.Background(), ForegroundConfig{
		Source: source, Name: "docs", Duration: time.Hour,
		Preview: func(ctx context.Context, config PreviewRunConfig) error {
			if err := config.Ready(preview.ControlRecord{URL: "https://docs.test", State: "ready", ExpiresAt: &expires}); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := foreground.Wait(); err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(expires.Add(-20 * time.Millisecond)) {
		t.Fatal("foreground stopped before absolute expiry")
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmtUint(foreground.server.Port())), 100*time.Millisecond); err == nil {
		t.Fatal("listener remains active after expiry")
	}
}

type failingManagementLease struct {
	lost     chan struct{}
	released chan struct{}
}

func (l *failingManagementLease) Run(ctx context.Context) error {
	select {
	case <-l.lost:
		return errors.New("renewal rejected")
	case <-ctx.Done():
		return nil
	}
}

func (l *failingManagementLease) Release(context.Context) error {
	select {
	case <-l.released:
	default:
		close(l.released)
	}
	return nil
}

func TestForegroundLeaseLossStopsListenerAndPreview(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	_ = os.WriteFile(file, []byte("ready"), 0o600)
	source, _ := ResolveSource(file)
	lease := &failingManagementLease{lost: make(chan struct{}), released: make(chan struct{})}
	runnerStopped := make(chan struct{})
	foreground, err := StartForeground(context.Background(), ForegroundConfig{
		Source: source, Name: "docs", Duration: time.Hour, Lease: lease,
		Preview: func(ctx context.Context, config PreviewRunConfig) error {
			if err := config.Ready(preview.ControlRecord{URL: "https://docs.test", State: "ready"}); err != nil {
				return err
			}
			<-ctx.Done()
			close(runnerStopped)
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	port := foreground.server.Port()
	close(lease.lost)
	if err := foreground.Wait(); err == nil || !strings.Contains(err.Error(), "management lease lost") {
		t.Fatalf("lease loss error=%v", err)
	}
	select {
	case <-runnerStopped:
	default:
		t.Fatal("preview runner remains active after lease loss")
	}
	select {
	case <-lease.released:
	default:
		t.Fatal("management lease was not released")
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmtUint(port)), 100*time.Millisecond); err == nil {
		t.Fatal("listener remains active after lease loss")
	}
}

func fmtUint(value uint16) string { return strconv.FormatUint(uint64(value), 10) }
