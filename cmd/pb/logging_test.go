package main

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestConfigureProcessLoggingSuppressesInteractiveTransportLogs(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	configureProcessLogging([]string{"victus"})
	slog.Info("peer transport detail")
	if output.Len() != 0 {
		t.Fatalf("interactive transport log reached process output: %q", output.String())
	}
}

func TestConfigureProcessLoggingKeepsRuntimeDiagnostics(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	configureProcessLogging([]string{"__runtime-host"})
	slog.Info("runtime diagnostic")
	if output.Len() == 0 {
		t.Fatal("runtime diagnostic was suppressed")
	}
}
