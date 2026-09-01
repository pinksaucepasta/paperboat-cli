package serve

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLocalServesOnlyOnLoopbackAndStopsOnCancellation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := ResolveSource(file)
	ctx, cancel := context.WithCancel(context.Background())
	local, err := StartLocal(ctx, LocalConfig{Source: source, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(local.URL, "http://127.0.0.1:") {
		t.Fatalf("URL = %q", local.URL)
	}
	response, err := http.Get(local.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "private" {
		t.Fatalf("body = %q", body)
	}
	cancel()
	if err := local.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRequestedPortAndConflict(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := ResolveSource(file)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	local, err := StartLocal(ctx, LocalConfig{Source: source, Duration: time.Hour, ListenPort: port})
	if err != nil {
		t.Fatal(err)
	}
	if local.server.Port() != port {
		t.Fatalf("port = %d, want %d", local.server.Port(), port)
	}
	if _, err := StartLocal(context.Background(), LocalConfig{Source: source, Duration: time.Hour, ListenPort: port}); err == nil {
		t.Fatal("conflicting requested port was accepted")
	}
	cancel()
	if err := local.Wait(); err != nil {
		t.Fatal(err)
	}
}

func fmtUint(value uint16) string { return strconv.FormatUint(uint64(value), 10) }
