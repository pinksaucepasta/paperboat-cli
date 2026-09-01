//go:build linux

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

const nativeLinuxHealthURL = "http://127.0.0.1:18083/healthz"

func TestNativeSystemdServiceProcess(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_CHILD") != "1" {
		t.Skip("native service child only")
	}
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_ROLE") == "updater" {
		notifyNativeServiceReady()
		awaitNativeServiceTermination()
		return
	}
	server := &http.Server{Addr: "127.0.0.1:18083", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"live":true}`))
	})}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	notifyNativeServiceReady()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

func awaitNativeServiceTermination() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	waitForNativeServiceTermination(signals)
}

func waitForNativeServiceTermination(signals <-chan os.Signal) {
	<-signals
}

func notifyNativeServiceReady() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + strings.TrimPrefix(socket, "@")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return
	}
	defer connection.Close()
	_, _ = connection.Write([]byte("READY=1\nSTATUS=Paperboat native test ready\n"))
}

func TestWaitForNativeServiceTerminationReturnsOnSignal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		waitForNativeServiceTermination(signals)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("termination wait returned before a signal")
	case signals <- syscall.SIGTERM:
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("termination wait did not return after SIGTERM")
	}
}

func TestNativeSystemdInstallUpgradeAndUninstall(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 on a host with user systemd")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable = installNativeServiceTestExecutable(t, executable)
	definitionPath := "/etc/systemd/system/paperboat-runtime-host.service"
	if _, err := os.Lstat(definitionPath); err == nil {
		t.Fatalf("refusing to replace existing service definition %s", definitionPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	installer, err := New(Config{
		Platform: "linux", ConfigRoot: "/", Executable: executable, User: os.Getenv("USER"), Group: os.Getenv("USER"),
		Arguments:   []string{"-test.run=^TestNativeSystemdServiceProcess$", "-test.v"},
		Environment: map[string]string{"PAPERBOAT_NATIVE_SERVICE_CHILD": "1"},
		Controller:  SystemdController{Runner: ExecRunner{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanupNeeded := true
	t.Cleanup(func() {
		if cleanupNeeded {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			_ = installer.Uninstall(ctx)
		}
	})
	if err := nativeSystemdOperation(installer.Install); err != nil {
		definition, _ := os.ReadFile(installer.DefinitionPath())
		t.Fatalf("install: %v\ndefinition:\n%s", err, definition)
	}
	waitForNativeSystemdHealth(t, true)
	if err := nativeSystemdOperation(installer.Install); err != nil {
		t.Fatal(err)
	}
	waitForNativeSystemdHealth(t, true)
	if err := nativeSystemdOperation(installer.Uninstall); err != nil {
		t.Fatal(err)
	}
	cleanupNeeded = false
	waitForNativeSystemdHealth(t, false)
}

func nativeSystemdOperation(operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return operation(ctx)
}

func waitForNativeSystemdHealth(t *testing.T, wantReady bool) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(nativeLinuxHealthURL)
		ready := err == nil && response.StatusCode == http.StatusOK
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
		}
		if ready == wantReady {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health ready=%v want=%v err=%v", ready, wantReady, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
