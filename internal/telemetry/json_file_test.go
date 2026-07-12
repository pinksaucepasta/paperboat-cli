package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestJSONFileSinkWritesValidatedMetadataWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "telemetry.jsonl")
	sink, err := NewJSONFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	sink.Record(Event{Name: "connect.result", At: time.Unix(10, 0), ProjectID: "prj_1", Outcome: "success", LatencyMS: 12})
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if event.ProjectID != "prj_1" || event.LatencyMS != 12 {
		t.Fatalf("event = %+v", event)
	}
}

func TestJSONFileSinkDropsInvalidContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	sink.Record(Event{Name: "upload.result", Stage: "/private/image.png"})
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("invalid event was written: %q", data)
	}
}

func TestJSONFileSinkRecordAndCloseConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				sink.Record(Event{Name: "terminal.reconnect", At: time.Now(), ProjectID: "prj_1", Outcome: "success"})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = sink.Close()
	}()
	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONFileSinkBoundsFileSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSinkWithLimit(path, 300)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		sink.Record(Event{Name: "connect.result", At: time.Now(), ProjectID: "prj_1", EnvironmentID: "env_1", Outcome: "success", LatencyMS: 12})
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 0 || info.Size() > 300 {
		t.Fatalf("size = %d", info.Size())
	}
}
