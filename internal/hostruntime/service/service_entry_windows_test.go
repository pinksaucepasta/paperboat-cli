//go:build windows

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestSystemServiceEntryDoesNotReportRunningBeforeReadiness(t *testing.T) {
	runStarted := make(chan struct{})
	allowReady := make(chan struct{})
	result := make(chan struct {
		failed bool
		code   uint32
	}, 1)
	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status, 8)
	entry := &systemServiceEntry{
		waitReady: true,
		run: func(ctx context.Context, ready func() error) error {
			close(runStarted)
			select {
			case <-allowReady:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := ready(); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}
	go func() {
		failed, code := entry.Execute(nil, requests, statuses)
		result <- struct {
			failed bool
			code   uint32
		}{failed: failed, code: code}
	}()

	if status := <-statuses; status.State != svc.StartPending {
		t.Fatalf("initial service state=%d want start pending", status.State)
	}
	<-runStarted
	select {
	case status := <-statuses:
		t.Fatalf("service reported state=%d before readiness", status.State)
	default:
	}

	close(allowReady)
	if status := <-statuses; status.State != svc.Running {
		t.Fatalf("ready service state=%d want running", status.State)
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if status := <-statuses; status.State != svc.StopPending {
		t.Fatalf("stop service state=%d want stop pending", status.State)
	}
	if status := <-statuses; status.State != svc.Stopped || status.Win32ExitCode != 0 {
		t.Fatalf("final service status=%+v want clean stop", status)
	}
	select {
	case outcome := <-result:
		if outcome.failed || outcome.code != 0 {
			t.Fatalf("service outcome failed=%v code=%d", outcome.failed, outcome.code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service entry did not stop")
	}
}

func TestSystemServiceEntryFailsIfRunExitsBeforeReadiness(t *testing.T) {
	statuses := make(chan svc.Status, 8)
	requests := make(chan svc.ChangeRequest)
	entry := &systemServiceEntry{
		waitReady: true,
		run: func(context.Context, func() error) error {
			return errors.New("control listener failed")
		},
	}
	failed, code := entry.Execute(nil, requests, statuses)
	if !failed || code != 1 {
		t.Fatalf("service outcome failed=%v code=%d want failure", failed, code)
	}
	if status := <-statuses; status.State != svc.StartPending {
		t.Fatalf("initial service state=%d want start pending", status.State)
	}
	if status := <-statuses; status.State != svc.Stopped || status.Win32ExitCode != 1 {
		t.Fatalf("failed service status=%+v", status)
	}
}

func TestOnlyContextCanceledDoesNotHideJoinedFailure(t *testing.T) {
	if !onlyContextCanceled(context.Canceled) || !onlyContextCanceled(errors.Join(context.Canceled, context.Canceled)) {
		t.Fatal("cancellation-only result was not recognized")
	}
	if onlyContextCanceled(nil) || onlyContextCanceled(errors.Join(context.Canceled, errors.New("sidecar failed"))) {
		t.Fatal("real sidecar failure was hidden by joined cancellation")
	}
}

func TestSessionPriority(t *testing.T) {
	cases := []struct {
		state uint32
		want  int
	}{
		{windows.WTSActive, 0},
		{windows.WTSConnected, 1},
		{windows.WTSDisconnected, 2},
		{windows.WTSIdle, 3},
	}
	for _, test := range cases {
		if got := sessionPriority(test.state); got != test.want {
			t.Errorf("sessionPriority(%d) = %d, want %d", test.state, got, test.want)
		}
	}
}

func TestSessionChangeForRequiresValidMatchingNotification(t *testing.T) {
	notification := windows.WTSSESSION_NOTIFICATION{Size: uint32(unsafe.Sizeof(windows.WTSSESSION_NOTIFICATION{})), SessionID: 42}
	request := svc.ChangeRequest{EventData: uintptr(unsafe.Pointer(&notification))}
	if !sessionChangeFor(request, 42) {
		t.Fatal("matching session notification was rejected")
	}
	if sessionChangeFor(request, 43) {
		t.Fatal("other session notification was accepted")
	}
	if sessionChangeFor(svc.ChangeRequest{}, 42) {
		t.Fatal("empty session notification was accepted")
	}
}

func TestOwnerSessionLifecycleRetainsLockUnlockAndFastUserSwitch(t *testing.T) {
	notification := windows.WTSSESSION_NOTIFICATION{Size: uint32(unsafe.Sizeof(windows.WTSSESSION_NOTIFICATION{})), SessionID: 42}
	request := svc.ChangeRequest{EventData: uintptr(unsafe.Pointer(&notification))}
	for _, event := range []uint32{windows.WTS_SESSION_LOCK, windows.WTS_SESSION_UNLOCK, windows.WTS_CONSOLE_DISCONNECT, windows.WTS_CONSOLE_CONNECT, windows.WTS_REMOTE_DISCONNECT, windows.WTS_REMOTE_CONNECT} {
		request.EventType = event
		if shouldTerminateForSessionChange(request, 42) {
			t.Fatalf("session event %d terminated the enrolled workload", event)
		}
	}
	for _, event := range []uint32{windows.WTS_SESSION_LOGOFF, windows.WTS_SESSION_TERMINATE} {
		request.EventType = event
		if !shouldTerminateForSessionChange(request, 42) {
			t.Fatalf("session event %d retained a logged-off workload", event)
		}
	}
	request.EventType = windows.WTS_SESSION_LOGOFF
	if shouldTerminateForSessionChange(request, 43) {
		t.Fatal("another user's logoff terminated the enrolled workload")
	}
}

func TestLocalS4URequestUsesTheLocalAuthenticationSubmitType(t *testing.T) {
	pointer, length, keepAlive, err := localS4URequest("paperboat")
	if err != nil {
		t.Fatal(err)
	}
	if length <= uint32(unsafe.Sizeof(msvS4ULogonRequest{})) {
		t.Fatalf("request length = %d, want complete buffer larger than %d", length, unsafe.Sizeof(msvS4ULogonRequest{}))
	}
	request := (*msvS4ULogonRequest)(pointer)
	if request.MessageType != msvS4ULogon || windows.UTF16PtrToString(request.UserPrincipalName.Buffer) != "paperboat" || windows.UTF16PtrToString(request.DomainName.Buffer) != "." {
		t.Fatalf("unexpected local S4U request: %#v", request)
	}
	if keepAlive == nil {
		t.Fatal("S4U request backing storage is not retained")
	}
	start := uintptr(pointer)
	end := start + uintptr(length)
	for _, field := range []*uint16{request.UserPrincipalName.Buffer, request.DomainName.Buffer} {
		if field == nil || uintptr(unsafe.Pointer(field)) < start || uintptr(unsafe.Pointer(field)) >= end {
			t.Fatalf("S4U string pointer %p is outside request buffer [%#x, %#x)", field, start, end)
		}
	}
}

func TestOwnerEnvironmentIsCreateProcessCompatible(t *testing.T) {
	block, err := ownerEnvironment(windows.GetCurrentProcessToken(), map[string]string{
		"PAPERBOAT_TEST":                  "1",
		"PAPERBOAT_CONTROL_URL":           "https://api.example.test",
		"PAPERBOAT_RUNTIME_SERVICE_SCOPE": "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("owner environment is not double-NUL terminated: %#v", block)
	}
	if !strings.Contains(windows.UTF16ToString(block), "PAPERBOAT_CONTROL_URL=https://api.example.test") {
		t.Fatal("owner environment dropped the control URL required by the S4U workload")
	}
}

func TestEnrolledOwnerExistenceDistinguishesResolvedAndDeletedSIDs(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current token SID: %v", err)
	}
	exists, err := enrolledOwnerExists(user.User.Sid.String())
	if err != nil || !exists {
		t.Fatalf("current owner exists=%v error=%v", exists, err)
	}
	exists, err = enrolledOwnerExists("S-1-5-21-4294967294-4294967294-4294967294-4294967294")
	if err != nil || exists {
		t.Fatalf("unmapped owner exists=%v error=%v", exists, err)
	}
	if _, err := enrolledOwnerExists("not-a-sid"); err == nil {
		t.Fatal("malformed owner SID was accepted")
	}
}
