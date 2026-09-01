package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if !telemetryFilePrivate(path, info) {
		t.Fatalf("telemetry event log is not private: mode=%o", info.Mode().Perm())
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

func TestJSONFileSinkQueueSaturationIsNonblockingAndObservable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSinkWithQueueLimit(path, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the worker at the file boundary so the one-slot queue remains full
	// while producers exercise the nonblocking path deterministically.
	sink.stateMu.Lock()
	for range 32 {
		if err := sink.RecordEvent(Event{Name: "queue.event", At: time.Now(), Outcome: "accepted"}); err != nil {
			t.Fatal(err)
		}
	}
	dropped := sink.DroppedEvents()
	sink.stateMu.Unlock()
	if dropped == 0 {
		t.Fatal("queue saturation was not recorded")
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONFileSinkFlushAndCloseSurfaceStableWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	sink.stateMu.Lock()
	if sink.file == nil {
		sink.stateMu.Unlock()
		t.Fatal("sink file unexpectedly nil")
	}
	if err := sink.file.Close(); err != nil {
		sink.stateMu.Unlock()
		t.Fatal(err)
	}
	sink.stateMu.Unlock()
	if err := sink.RecordEvent(Event{Name: "write.failure", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(context.Background()); !errors.Is(err, ErrJSONFileSinkWrite) {
		t.Fatalf("flush error = %v", err)
	}
	if err := sink.Close(); !errors.Is(err, ErrJSONFileSinkWrite) {
		t.Fatalf("close error = %v", err)
	}
	if strings.Contains(errString(sink.LastError()), path) {
		t.Fatal("write error leaked local path")
	}
}

func TestJSONFileSinkRotatesWithBoundedBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.jsonl")
	sink, err := NewJSONFileSinkWithOptions(path, JSONFileSinkOptions{MaxBytes: 180, QueueCapacity: 8, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 20; index++ {
		sink.Record(Event{Name: "rotation.event", At: time.Unix(int64(index), 0), ProjectID: "prj_01", Outcome: "accepted"})
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 180 || !telemetryFilePrivate(candidate, info) {
			t.Fatalf("rotated file %q size=%d mode=%o", candidate, info.Size(), info.Mode().Perm())
		}
	}
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unbounded backup exists: err=%v", err)
	}
}

func TestJSONFileSinkRejectsInvalidOptionsWithoutPathInError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-event-log.jsonl")
	for _, options := range []JSONFileSinkOptions{{MaxBytes: 0, QueueCapacity: 1, MaxBackups: 0}, {MaxBytes: 10, QueueCapacity: 0, MaxBackups: 0}, {MaxBytes: 10, QueueCapacity: 1, MaxBackups: 9}} {
		_, err := NewJSONFileSinkWithOptions(path, options)
		if err == nil || strings.Contains(err.Error(), path) {
			t.Fatalf("options=%+v err=%v", options, err)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
