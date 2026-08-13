package localdaemon

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

func TestDialWithInvalidationRetry(t *testing.T) {
	calls := 0
	connection, err := dialWithInvalidationRetry(context.Background(), func() (tunnel.Conn, error) {
		calls++
		if calls == 1 {
			return nil, errors.Join(errors.New("carrier fenced"), transportmanager.ErrInvalid)
		}
		return nil, nil
	})
	if err != nil || connection != nil || calls != 2 {
		t.Fatalf("connection=%v err=%v calls=%d", connection, err, calls)
	}
}

func TestDialWithInvalidationRetryPreservesAutoPath(t *testing.T) {
	path := "a"
	calls := 0
	_, err := dialWithInvalidationRetry(context.Background(), func() (tunnel.Conn, error) {
		calls++
		if path != "a" {
			t.Fatalf("retry changed path to %q", path)
		}
		if calls == 1 {
			return nil, transportmanager.ErrInvalid
		}
		return nil, nil
	})
	if err != nil || calls != 2 || path != "a" {
		t.Fatalf("err=%v calls=%d path=%q", err, calls, path)
	}
}

func TestRetryablePeerProbeRetriesTransportButNotAuthorityFailures(t *testing.T) {
	if !retryablePeerProbe(context.Background(), errors.New("remote application close")) {
		t.Fatal("transport close was not retryable")
	}
	for _, class := range []connectionmanager.FailureClass{connectionmanager.FailureAuthentication, connectionmanager.FailureAuthorization, connectionmanager.FailureCertificate, connectionmanager.FailureProtocol, connectionmanager.FailureRevoked, connectionmanager.FailureGeneration} {
		if retryablePeerProbe(context.Background(), &connectionmanager.Failure{Class: class, Cause: errors.New("authority failure")}) {
			t.Fatalf("authority class %d became retryable", class)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if retryablePeerProbe(ctx, errors.New("transport close")) {
		t.Fatal("caller cancellation became retryable")
	}
}

func TestDialWithInvalidationRetryReopensAfterTransportEOF(t *testing.T) {
	calls := 0
	_, err := dialWithInvalidationRetry(context.Background(), func() (tunnel.Conn, error) {
		calls++
		if calls == 1 {
			return nil, io.EOF
		}
		return nil, errors.New("second carrier failed")
	})
	if err == nil || !errors.Is(err, io.EOF) || err.Error() != "initial peer dial: EOF\nfresh peer dial retry: second carrier failed" || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDialWithInvalidationRetryReopensAfterAuthorityFenceCancellation(t *testing.T) {
	calls := 0
	_, err := dialWithInvalidationRetry(context.Background(), func() (tunnel.Conn, error) {
		calls++
		if calls == 1 {
			return nil, context.Canceled
		}
		return nil, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDialWithInvalidationRetryDoesNotRetryOtherFailures(t *testing.T) {
	want := errors.New("dial failed")
	calls := 0
	_, err := dialWithInvalidationRetry(context.Background(), func() (tunnel.Conn, error) {
		calls++
		return nil, want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDialWithInvalidationRetryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := dialWithInvalidationRetry(ctx, func() (tunnel.Conn, error) {
		calls++
		cancel()
		return nil, transportmanager.ErrInvalid
	})
	if !errors.Is(err, transportmanager.ErrInvalid) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
