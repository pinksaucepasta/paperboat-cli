//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

const nativeDarwinHealthPortEnv = "PAPERBOAT_NATIVE_SERVICE_HEALTH_PORT"

func reserveNativeDarwinHealthPort(t *testing.T) (string, func() error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve native Darwin health port: %v", err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port < 1 || address.Port > 65535 {
		_ = listener.Close()
		t.Fatalf("reserve native Darwin health port returned invalid address %v", listener.Addr())
	}
	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() { releaseErr = listener.Close() })
		return releaseErr
	}
	t.Cleanup(func() { _ = release() })
	return strconv.Itoa(address.Port), release
}

func nativeDarwinHealthAddress(port string) (string, error) {
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid native Darwin health port %q", port)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(portNumber)), nil
}

func nativeDarwinHealthURL(port string) string {
	return "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz"
}

func refuseExistingNativeLaunchdService(t *testing.T, label, definitionPath string) {
	t.Helper()
	if _, err := os.Lstat(definitionPath); err == nil {
		t.Fatalf("refusing to replace existing service definition %s", definitionPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	service := "system/" + label
	if err := (ExecRunner{}).Run(ctx, "launchctl", "print", service); err == nil {
		t.Fatalf("refusing to replace loaded launchd service %s", service)
	} else if !launchdServiceAbsent(err) {
		t.Fatalf("check loaded launchd service %s: %v", service, err)
	}
}

func cleanupNativeLaunchdService(label, definitionPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	controller := LaunchdController{Runner: ExecRunner{}, UID: os.Getuid(), Label: label}
	var cleanupErr error
	if err := controller.Disable(ctx, definitionPath); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	if err := os.Remove(definitionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	return cleanupErr
}

func TestNativeLaunchdServiceProcess(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_CHILD") != "1" {
		t.Skip("native service child only")
	}
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_ROLE") == "updater" {
		select {}
	}
	address, err := nativeDarwinHealthAddress(os.Getenv(nativeDarwinHealthPortEnv))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"live":true}`))
	})}
	listener, err := net.Listen("tcp4", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

func TestNativeLaunchdInstallUpgradeAndUninstall(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 in a logged-in macOS user session")
	}
	// A copied Go test executable is rejected by macOS launchd/AMFI even when
	// the real ad-hoc-signed Paperboat package is accepted. Running this test
	// with that fixture produces a packaging false negative, so native macOS
	// acceptance is performed with the installed package instead.
	t.Skip("raw Go test binaries cannot represent installed macOS package provenance; run package acceptance")
	definitionPath := filepath.Join("/Library", "LaunchDaemons", Label+".plist")
	refuseExistingNativeLaunchdService(t, Label, definitionPath)
	healthPort, releaseHealthPort := reserveNativeDarwinHealthPort(t)
	healthURL := nativeDarwinHealthURL(healthPort)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable = installNativeServiceTestExecutable(t, executable)
	installer, err := New(Config{
		Platform: "darwin", ConfigRoot: "/", Executable: executable, User: os.Getenv("USER"), Group: "staff",
		Arguments: []string{"-test.run=^TestNativeLaunchdServiceProcess$", "-test.v"},
		Environment: map[string]string{
			"PAPERBOAT_NATIVE_SERVICE_CHILD": "1",
			nativeDarwinHealthPortEnv:        healthPort,
		},
		Controller: LaunchdController{Runner: ExecRunner{}, UID: os.Getuid()},
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanupNeeded := true
	t.Cleanup(func() {
		if cleanupNeeded {
			if err := cleanupNativeLaunchdService(Label, definitionPath); err != nil {
				t.Errorf("cleanup launchd service %s: %v", Label, err)
			}
		}
	})
	if err := releaseHealthPort(); err != nil {
		t.Fatalf("release native Darwin health port: %v", err)
	}
	if err := nativeLaunchdOperation(installer.Install); err != nil {
		definition, _ := os.ReadFile(installer.DefinitionPath())
		t.Fatalf("install: %v\ndefinition:\n%s", err, definition)
	}
	waitForNativeLaunchdHealth(t, healthURL, true)
	if err := nativeLaunchdOperation(installer.Install); err != nil {
		t.Fatal(err)
	}
	waitForNativeLaunchdHealth(t, healthURL, true)
	if err := nativeLaunchdOperation(installer.Uninstall); err != nil {
		t.Fatal(err)
	}
	cleanupNeeded = false
	waitForNativeLaunchdHealth(t, healthURL, false)
}

func nativeLaunchdOperation(operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return operation(ctx)
}

func waitForNativeLaunchdHealth(t *testing.T, endpoint string, wantReady bool) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(endpoint)
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
