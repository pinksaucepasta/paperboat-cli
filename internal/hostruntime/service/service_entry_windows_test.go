//go:build windows

package service

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

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
	block, err := ownerEnvironment(windows.GetCurrentProcessToken(), map[string]string{"PAPERBOAT_TEST": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("owner environment is not double-NUL terminated: %#v", block)
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
