//go:build windows

package previewbroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeBrokerAuthenticatesAndBoundsOperations(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal("current SID unavailable")
	}
	token := DeriveToken(bytes.Repeat([]byte{7}, tokenBytes))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	pipeName := fmt.Sprintf(`\\.\pipe\PaperboatPreviewBroker-Test-%d`, os.Getpid())
	go func() {
		done <- (Server{OwnerSID: user.User.Sid.String(), Token: token, Ready: ready, PipeName: pipeName, Handle: func(_ context.Context, body []byte) error {
			if string(body) == `{"fail":true}` {
				return errors.New("fixture rejected")
			}
			return nil
		}}).Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("broker shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("broker did not stop")
		}
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("broker readiness was not reported")
	}
	err = requestPipe(context.Background(), pipeName, user.User.Sid.String(), token, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatalf("broker request: %v", err)
	}
	if err := requestPipe(context.Background(), pipeName, user.User.Sid.String(), token, []byte(`{"fail":true}`)); !errors.Is(err, ErrRejected) {
		t.Fatalf("rejection = %v", err)
	}
	wrong := append([]byte(nil), token...)
	wrong[0] ^= 0xff
	if err := requestPipe(context.Background(), pipeName, user.User.Sid.String(), wrong, []byte(`{}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong token = %v", err)
	}
}

func TestDeriveTokenIsDomainSeparated(t *testing.T) {
	installation := bytes.Repeat([]byte{3}, tokenBytes)
	derived := DeriveToken(installation)
	if len(derived) != tokenBytes || bytes.Equal(derived, installation) {
		t.Fatal("broker token was not domain separated")
	}
	if DeriveToken(installation[:tokenBytes-1]) != nil {
		t.Fatal("accepted invalid installation token")
	}
}
