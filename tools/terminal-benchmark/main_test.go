package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStreamMatcherFindsFragmentedMarker(t *testing.T) {
	chunks := make(chan []byte, 3)
	done := make(chan error, 1)
	chunks <- []byte("discard-PB")
	chunks <- []byte("RTT0000")
	chunks <- []byte("0001Q-tail")
	matcher := newStreamMatcher(chunks, done)
	if err := matcher.wait(context.Background(), "PBRTT00000001Q"); err != nil {
		t.Fatal(err)
	}
}

func TestOutputIntervalsSummarizeBoundedArrivalTiming(t *testing.T) {
	intervals := &outputIntervals{}
	start := time.Unix(1, 0)
	for _, offset := range []time.Duration{0, time.Millisecond, 3 * time.Millisecond, 7 * time.Millisecond} {
		intervals.observe(start.Add(offset))
	}
	count, p50, p95, p99, mean := intervals.summarize()
	if count != 3 || p50 != 2 || p95 != 4 || p99 != 4 || mean != 2.333333 {
		t.Fatalf("summary = count:%d p50:%v p95:%v p99:%v mean:%v", count, p50, p95, p99, mean)
	}
}

func TestStreamMatcherFindsCursorAddressedMarker(t *testing.T) {
	chunks := make(chan []byte, 2)
	done := make(chan error, 1)
	chunks <- []byte("noise\x1b[2;1HPB\x1b[2;3H12")
	chunks <- []byte("\x1b[2;5H34Q\x1b[3;1H")
	matcher := newStreamMatcher(chunks, done)
	if err := matcher.wait(context.Background(), "PB1234Q"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamMatcherFindsMarkerOverwrittenInSameChunk(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	chunks <- []byte("PB1234Q\x1b[1;1HXX")
	matcher := newStreamMatcher(chunks, done)
	if err := matcher.wait(context.Background(), "PB1234Q"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamMatcherDoesNotJoinRows(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	chunks <- []byte("PB12\r\n34Q")
	done <- io.EOF
	matcher := newStreamMatcher(chunks, done)
	if err := matcher.wait(context.Background(), "PB1234Q"); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
}

func TestStreamMatcherFindsMarkerWrappedAtScreenEdge(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	chunks <- []byte("\x1b[1;77HPB1234Q")
	matcher := newStreamMatcher(chunks, done)
	if err := matcher.wait(context.Background(), "PB1234Q"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamMatcherReportsClosedOutput(t *testing.T) {
	chunks := make(chan []byte)
	done := make(chan error, 1)
	done <- io.EOF
	close(chunks)
	if err := newStreamMatcher(chunks, done).wait(context.Background(), "missing"); err != io.EOF {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamMatcherTimeoutDiagnosticsExcludeScreenContents(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	chunks <- []byte("PB12-secret-terminal-content")
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := newStreamMatcher(chunks, done).wait(ctx, "PB1234Q")
	if err == nil || !strings.Contains(err.Error(), "marker_prefix=4") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunPrefixPreventsDurableReplayMarkerReuse(t *testing.T) {
	first, err := randomRunPrefix(bytes.NewReader(bytes.Repeat([]byte{0x11}, 4)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomRunPrefix(bytes.NewReader(bytes.Repeat([]byte{0x22}, 4)))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first != "11111111" || second != "22222222" {
		t.Fatalf("prefixes = %q, %q", first, second)
	}
}

func TestWaitUntilReadyDoesNotQueueDuplicateCommands(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	var writes bytes.Buffer
	go func() {
		time.Sleep(15 * time.Millisecond)
		chunks <- []byte("PBRABCQ")
	}()
	attempts, err := waitUntilReady(context.Background(), &writes, newStreamMatcher(chunks, done), "ABC", time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(writes.Bytes(), []byte("printf 'PBR%sQ")); got != 1 || attempts != 1 {
		t.Fatalf("readiness writes = %d attempts = %d", got, attempts)
	}
}

func TestRunProbeRetriesWithFreshMarkerAfterUncertainTimeout(t *testing.T) {
	chunks := make(chan []byte, 1)
	done := make(chan error, 1)
	var writes bytes.Buffer
	go func() {
		time.Sleep(15 * time.Millisecond)
		chunks <- []byte("PBABC0000Q")
	}()
	latency, attempts, err := runProbe(context.Background(), &writes, newStreamMatcher(chunks, done), "ABC", 0, 3, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || latency < 10*time.Millisecond || bytes.Count(writes.Bytes(), []byte("ABC0000")) != 2 {
		t.Fatalf("attempts=%d latency=%s writes=%q", attempts, latency, writes.String())
	}
}

func TestPercentileUsesNearestRank(t *testing.T) {
	values := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond}
	if got := percentile(values, 50); got != 3*time.Millisecond {
		t.Fatalf("p50 = %s", got)
	}
	if got := percentile(values, 99); got != 5*time.Millisecond {
		t.Fatalf("p99 = %s", got)
	}
}

func TestLabelsAreBoundedMetadata(t *testing.T) {
	for _, value := range []string{"quic", "tcp_dedicated", "download_and_upload", "rtt.20"} {
		if !validLabel(value) {
			t.Fatalf("valid label rejected: %q", value)
		}
	}
	for _, value := range []string{"", "Has Caps", "secret/path", "x@y"} {
		if validLabel(value) {
			t.Fatalf("invalid label accepted: %q", value)
		}
	}
}

func TestRunMeasuresEchoingSubprocess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	command := []string{"sh"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd.exe", "/d", "/s", "/c"}
	}
	err := run(context.Background(), append([]string{"-samples=3", "-warmup=1", "-startup-delay=0", "-interval=0", "-probe-timeout=1s", "-mode=quic", "--"}, command...), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%q", err, stderr.String())
	}
	var got result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "paperboat.terminal-benchmark/v1" || got.Mode != "quic" || got.Samples != 3 || got.ProbeAttempts != 3 || got.P99MS < got.P50MS {
		t.Fatalf("result = %+v", got)
	}
}

func TestRunStartsUnrecordedLoadBeforeProbes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	load := "printf load-started"
	command := []string{"sh"}
	if runtime.GOOS == "windows" {
		load = "Write-Output load-started"
		command = []string{"cmd.exe", "/d", "/s", "/c"}
	}
	err := run(context.Background(), append([]string{"-samples=1", "-warmup=0", "-startup-delay=0", "-load-warmup=0", "-load-command=" + load, "-interval=0", "-probe-timeout=1s", "-mode=quic", "--"}, command...), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%q", err, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("load-started")) || bytes.Contains(stdout.Bytes(), []byte("printf")) {
		t.Fatalf("result exposed load command or output: %s", stdout.Bytes())
	}
}
