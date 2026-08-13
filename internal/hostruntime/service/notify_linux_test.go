package service

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessNotifierLifecycleAndWatchdog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "2000000")
	t.Setenv("WATCHDOG_PID", "")

	notifier, err := NewProcessNotifier()
	if err != nil {
		t.Fatal(err)
	}
	if notifier.WatchdogInterval() != time.Second {
		t.Fatalf("watchdog interval=%s", notifier.WatchdogInterval())
	}
	operations := []struct {
		call func() error
		want string
	}{
		{notifier.Starting, "STATUS=starting"},
		{notifier.Ready, "READY=1\nSTATUS=ready"},
		{notifier.Watchdog, "WATCHDOG=1"},
		{notifier.Draining, "STATUS=draining"},
		{notifier.Stopping, "STOPPING=1\nSTATUS=stopping"},
	}
	buffer := make([]byte, 512)
	for _, operation := range operations {
		if err := operation.call(); err != nil {
			t.Fatal(err)
		}
		if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		count, _, err := listener.ReadFromUnix(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buffer[:count]); got != operation.want {
			t.Fatalf("notification=%q want=%q", got, operation.want)
		}
	}
	if err := notifier.Degraded("bad\nstatus"); err == nil {
		t.Fatal("accepted unsafe status")
	}
}

func TestProcessNotifierRejectsInvalidWatchdogConfiguration(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "invalid")
	t.Setenv("WATCHDOG_PID", os.Getenv("WATCHDOG_PID"))
	if _, err := NewProcessNotifier(); err == nil {
		t.Fatal("accepted invalid watchdog configuration")
	}
}
