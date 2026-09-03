package runtime

import (
	"context"
	"errors"
	"testing"
)

type failingPreviewPrivateAccess struct {
	starts int
	err    error
}

func (s *failingPreviewPrivateAccess) Start(context.Context) error {
	s.starts++
	return s.err
}

func TestStartPreviewPrivateAccessIsolatesWindowsUserPACFailure(t *testing.T) {
	want := errors.New("interactive user registry unavailable")
	service := &failingPreviewPrivateAccess{err: want}
	if err := startPreviewPrivateAccess(context.Background(), service, true); err != nil {
		t.Fatalf("isolated optional PAC start: %v", err)
	}
	if service.starts != 1 {
		t.Fatalf("starts=%d, want 1", service.starts)
	}
}

func TestStartPreviewPrivateAccessPreservesRequiredFailure(t *testing.T) {
	want := errors.New("PAC start failed")
	service := &failingPreviewPrivateAccess{err: want}
	if err := startPreviewPrivateAccess(context.Background(), service, false); !errors.Is(err, want) {
		t.Fatalf("start error=%v, want %v", err, want)
	}
}
