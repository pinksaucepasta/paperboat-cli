//go:build windows && paperboat_native_e2e

package pty

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const stillActive = 259

type nativeOutput struct {
	mu   sync.Mutex
	body bytes.Buffer
	done chan struct{}
}

func collectNativeOutput(process *Process) *nativeOutput {
	output := &nativeOutput{done: make(chan struct{})}
	go func() {
		defer close(output.done)
		buffer := make([]byte, 4096)
		for {
			count, err := process.Read(buffer)
			if count > 0 {
				output.mu.Lock()
				_, _ = output.body.Write(buffer[:count])
				output.mu.Unlock()
			}
			if err != nil {
				if err != io.EOF && !strings.Contains(strings.ToLower(err.Error()), "closed") {
					output.mu.Lock()
					_, _ = fmt.Fprintf(&output.body, "\n[reader error: %v]", err)
					output.mu.Unlock()
				}
				return
			}
		}
	}()
	return output
}

func (o *nativeOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.body.String()
}

func (o *nativeOutput) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(o.String(), text) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in ConPTY output %q", text, o.String())
}

func nativeAdapter(t *testing.T) (*Adapter, string) {
	t.Helper()
	root := t.TempDir()
	adapter, err := NewAdapter(root)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, root
}

func startNativePTY(t *testing.T, path string, args []string) (*Process, *nativeOutput) {
	t.Helper()
	adapter, root := nativeAdapter(t)
	process, err := adapter.Start(Command{Path: path, Args: args, CWD: root, Dimensions: Dimensions{Columns: 80, Rows: 25}})
	if err != nil {
		t.Fatalf("start native PTY: %v", err)
	}
	return process, collectNativeOutput(process)
}

func nativePowerShell(t *testing.T) string {
	t.Helper()
	path := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeConPTYCtrlCInterruptsForegroundAndPreservesShell(t *testing.T) {
	commandShell := os.Getenv("ComSpec")
	if commandShell == "" {
		commandShell = filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")
	}
	process, output := startNativePTY(t, commandShell, []string{"/d", "/q"})
	defer process.CloseIO()
	if _, err := process.Write([]byte("echo paperboat-shell-ready\r\n")); err != nil {
		t.Fatal(err)
	}
	output.waitFor(t, "paperboat-shell-ready")
	if _, err := process.Write([]byte("ping -t 127.0.0.1\r\n")); err != nil {
		t.Fatal(err)
	}
	output.waitFor(t, "Reply from")
	if err := process.Signal(Interrupt); err != nil {
		t.Fatalf("send Ctrl+C: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := process.Write([]byte("echo paperboat-after-ctrl-c\r\nexit /b 7\r\n")); err != nil {
		t.Fatalf("shell did not survive Ctrl+C: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := process.Wait(ctx)
	if err != nil {
		t.Fatalf("wait after Ctrl+C: %v; output=%q", err, output.String())
	}
	output.waitFor(t, "paperboat-after-ctrl-c")
	if result.Code != 7 {
		t.Fatalf("exit code=%d, want 7; output=%q", result.Code, output.String())
	}
}

func TestNativeConPTYResizeAndUTF8VT(t *testing.T) {
	process, output := startNativePTY(t, nativePowerShell(t), []string{"-NoLogo", "-NoProfile"})
	if err := process.Resize(Dimensions{Columns: 101, Rows: 37}); err != nil {
		t.Fatal(err)
	}
	command := "[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); Write-Output ('SIZE={0}x{1}' -f $Host.UI.RawUI.WindowSize.Width,$Host.UI.RawUI.WindowSize.Height); Write-Output ([char]27+'[32m紙船-✓'+[char]27+'[0m'); exit 0\r\n"
	if _, err := process.Write([]byte(command)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := process.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	_ = process.CloseIO()
	<-output.done
	if result.Code != 0 {
		t.Fatalf("exit code=%d output=%q", result.Code, output.String())
	}
	body := output.String()
	if !strings.Contains(body, "SIZE=101x37") || !strings.Contains(body, "紙船-✓") || !strings.Contains(body, "\x1b[32m") {
		t.Fatalf("resize/UTF-8/VT contract missing from %q", body)
	}
}

func TestNativeConPTYJobCloseKillsDescendant(t *testing.T) {
	script := "$p=Start-Process powershell.exe -ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep -Seconds 120' -PassThru; Write-Output ('CHILD='+$p.Id)"
	process, output := startNativePTY(t, nativePowerShell(t), []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if result, err := process.Wait(ctx); err != nil || result.Code != 0 {
		t.Fatalf("parent result=%+v err=%v output=%q", result, err, output.String())
	}
	output.waitFor(t, "CHILD=")
	match := regexp.MustCompile(`CHILD=(\d+)`).FindStringSubmatch(output.String())
	if len(match) != 2 {
		t.Fatalf("child PID missing from %q", output.String())
	}
	pid, _ := strconv.ParseUint(match[1], 10, 32)
	if err := process.CloseIO(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return
		}
		var code uint32
		err = windows.GetExitCodeProcess(handle, &code)
		windows.CloseHandle(handle)
		if err != nil || code != stillActive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("descendant PID %d remained active after closing the kill-on-close PTY job", pid)
}
