//go:build windows

package service

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestSystemServiceEntryTreatsHandoffDuringStopAsCleanStop(t *testing.T) {
	runStarted := make(chan struct{})
	release := make(chan struct{})
	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status, 8)
	entry := &systemServiceEntry{
		waitReady: true,
		run: func(context.Context, func() error) error {
			close(runStarted)
			<-release
			return ErrWindowsServiceHandoff
		},
	}
	type result struct {
		failed bool
		code   uint32
	}
	done := make(chan result, 1)
	go func() {
		failed, code := entry.Execute(nil, requests, statuses)
		done <- result{failed: failed, code: code}
	}()

	if status := <-statuses; status.State != svc.StartPending {
		t.Fatalf("initial service state=%d want start pending", status.State)
	}
	<-runStarted
	go func() { requests <- svc.ChangeRequest{Cmd: svc.Stop} }()
	if status := <-statuses; status.State != svc.StopPending {
		t.Fatalf("stop service state=%d want stop pending", status.State)
	}
	close(release)

	select {
	case outcome := <-done:
		if outcome.failed || outcome.code != 0 {
			t.Fatalf("service outcome failed=%v code=%d want clean handoff", outcome.failed, outcome.code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service entry did not stop")
	}
	if status := <-statuses; status.State != svc.Stopped || status.Win32ExitCode != 0 {
		t.Fatalf("handoff service status=%+v want clean stop", status)
	}
}
