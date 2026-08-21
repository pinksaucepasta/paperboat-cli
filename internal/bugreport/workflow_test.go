package bugreport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

type localStub struct {
	bundle  diagnostics.Bundle
	markers []string
	endErr  error
}

func (s *localStub) RecordBugreportMarker(_ context.Context, phase string) error {
	s.markers = append(s.markers, phase)
	if phase == "end" {
		return s.endErr
	}
	return nil
}
func (s *localStub) CreateBugreport(context.Context) (diagnostics.Bundle, error) {
	return s.bundle, nil
}

type serverStub struct {
	uploaded []byte
	fail     error
}

func (s *serverStub) CreateDiagnosticUploadIntent(_ context.Context, _ string, request api.DiagnosticUploadIntentRequest) (api.DiagnosticUploadIntent, error) {
	if s.fail != nil {
		return api.DiagnosticUploadIntent{}, s.fail
	}
	return api.DiagnosticUploadIntent{Schema: api.DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: request.CorrelationID, State: "pending", ExpiresAt: time.Now().UTC().Add(time.Minute), UploadMethod: "PUT", UploadURL: "https://objects.example.test/upload", UploadHeaders: map[string]string{"Content-Type": "application/zip"}}, nil
}
func (s *serverStub) UploadDiagnosticBundle(_ context.Context, _ api.DiagnosticUploadIntent, reader io.Reader, bytes int64) error {
	if s.fail != nil {
		return s.fail
	}
	s.uploaded, _ = io.ReadAll(reader)
	if int64(len(s.uploaded)) != bytes {
		return errors.New("wrong byte count")
	}
	return nil
}
func (s *serverStub) CompleteDiagnosticUploadIntent(_ context.Context, _ string) (api.DiagnosticUploadIntent, error) {
	if s.fail != nil {
		return api.DiagnosticUploadIntent{}, s.fail
	}
	return api.DiagnosticUploadIntent{Schema: api.DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "uploaded", ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
}

func TestWorkflowRecordsAndUploadsExactBundle(t *testing.T) {
	content := []byte("PK exact bundle")
	local := &localStub{bundle: testBundle(t, content)}
	server := &serverStub{}
	var prompt bytes.Buffer
	var shown Result
	result, err := Run(context.Background(), Options{Record: true, Upload: true, Input: bytes.NewBufferString("\n"), Prompt: &prompt, Local: local, Server: server, BeforeUpload: func(result Result) error { shown = result; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Validate() != nil || !result.Recorded || !result.Uploaded || result.ServerCorrelationID != result.CorrelationID || !slices.Equal(local.markers, []string{"start", "end"}) || !bytes.Equal(server.uploaded, content) || shown.SHA256 == "" || prompt.Len() == 0 {
		t.Fatalf("result=%#v markers=%v uploaded=%q shown=%#v prompt=%q", result, local.markers, server.uploaded, shown, prompt.String())
	}
}

func TestWorkflowPreservesBundleOnUploadFailure(t *testing.T) {
	local := &localStub{bundle: testBundle(t, []byte("PK bundle"))}
	want := errors.New("storage unavailable")
	result, err := Run(context.Background(), Options{Upload: true, Input: bytes.NewReader(nil), Prompt: io.Discard, Local: local, Server: &serverStub{fail: want}})
	var stage *StageError
	if !errors.As(err, &stage) || !errors.Is(err, want) || result.BundlePath == "" || result.Uploaded {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if _, statErr := os.Stat(result.BundlePath); statErr != nil {
		t.Fatalf("bundle not preserved: %v", statErr)
	}
}

func TestWorkflowCreatesBundleButReportsEndMarkerFailure(t *testing.T) {
	local := &localStub{bundle: testBundle(t, []byte("PK bundle")), endErr: errors.New("marker failed")}
	result, err := Run(context.Background(), Options{Record: true, Input: bytes.NewBufferString("\n"), Prompt: io.Discard, Local: local})
	var stage *StageError
	if !errors.As(err, &stage) || stage.Stage != "finish reproduction recording" || result.BundlePath == "" || result.Recorded {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func testBundle(t *testing.T, content []byte) diagnostics.Bundle {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bugreport-pb-0123456789abcdef0123456789abcdef.zip")
	if err := writeTestBundle(path, content); err != nil {
		t.Fatal(err)
	}
	return diagnostics.Bundle{Schema: diagnostics.BundleSchemaV1, Correlation: "pb-0123456789abcdef0123456789abcdef", CreatedAt: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), Path: path, Bytes: int64(len(content)), Categories: []string{"manifest", "recent_events", "redacted_events", "status"}}
}
