package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/telemetry"
)

type tunnelEventSink struct{ events []telemetry.Event }

func (s *tunnelEventSink) Record(e telemetry.Event) { s.events = append(s.events, e) }

type closeTrackingConn struct {
	*reconnectTestConn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error { c.closed.Store(true); return nil }

type reconnectTestConn struct {
	*bytes.Reader
	code   int
	err    error
	writes bytes.Buffer
}

type compressionTestConn struct {
	*reconnectTestConn
	compression TerminalCompressionTelemetry
}

func (c *compressionTestConn) TerminalCompressionTelemetry() TerminalCompressionTelemetry {
	return c.compression
}

func (c *reconnectTestConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (*reconnectTestConn) Close() error                  { return nil }
func (*reconnectTestConn) Resize(uint16, uint16) error   { return nil }
func (c *reconnectTestConn) Wait() (int, error)          { return c.code, c.err }

func TestReconnectingConnReattachesWithoutReplayingInput(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader([]byte("before")), err: ErrTransportLost}
	second := &reconnectTestConn{Reader: bytes.NewReader([]byte("after")), code: 7}
	reconnects := 0
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) { reconnects++; return second, nil })
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	code, err := c.Wait()
	if err != nil || code != 7 || string(got) != "beforeafter" || reconnects != 1 {
		t.Fatalf("code=%d err=%v output=%q reconnects=%d", code, err, got, reconnects)
	}
	if first.writes.Len() != 0 || second.writes.Len() != 0 {
		t.Fatal("reconnect replayed terminal input")
	}
}

func TestReconnectingConnRecordsReconnectAndLifetime(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	second := &reconnectTestConn{Reader: bytes.NewReader(nil)}
	sink := &tunnelEventSink{}
	n := int64(0)
	now := func() time.Time { n++; return time.Unix(0, n*int64(time.Millisecond)) }
	c := NewObservedReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) { return second, nil }, sink, now, TelemetryContext{ProjectID: "prj_1", EnvironmentID: "env_1"})
	_, _ = io.ReadAll(c)
	_, _ = c.Wait()
	if len(sink.events) != 3 {
		t.Fatalf("events = %+v", sink.events)
	}
	if sink.events[0].Name != "terminal.reconnect" || sink.events[0].Outcome != "success" {
		t.Fatalf("reconnect event = %+v", sink.events[0])
	}
	if sink.events[0].ProjectID != "prj_1" || sink.events[0].EnvironmentID != "env_1" || sink.events[2].ProjectID != "prj_1" || sink.events[2].EnvironmentID != "env_1" {
		t.Fatalf("missing correlation: %+v", sink.events)
	}
	if sink.events[1].Name != "terminal.output" || sink.events[1].Outcome != "success" {
		t.Fatalf("output event = %+v", sink.events[1])
	}
	if sink.events[2].Name != "terminal.lifetime" || sink.events[2].Outcome != "success" {
		t.Fatalf("lifetime event = %+v", sink.events[2])
	}
}

func TestReconnectingConnRecordsOutputPerformance(t *testing.T) {
	sink := &tunnelEventSink{}
	c := &ReconnectingConn{telemetry: sink, now: time.Now}
	c.ObserveLocalWrite(6, 12*time.Millisecond)
	c.maxQueueChunks.Store(4)
	c.recordOutputPerformance("success")
	if len(sink.events) != 3 {
		t.Fatalf("events = %+v", sink.events)
	}
	output := sink.events[0]
	if output.Name != "terminal.output" || output.SizeBytes != 6 || output.LatencyMS != 12 || output.Count != 4 {
		t.Fatalf("output event = %+v", output)
	}
	stage := sink.events[1]
	if stage.Name != "terminal.stage" || stage.Stage != "socket_read_to_stdout" || stage.SizeBytes != 6 || stage.LatencyMS != 12 || stage.Count != 1 {
		t.Fatalf("output stage = %+v", stage)
	}
	if queue := sink.events[2]; queue.Stage != "socket_read_to_queue" || queue.SizeBytes != 6 || queue.Count != 1 {
		t.Fatalf("queue stage = %+v", queue)
	}
}

func TestReconnectingConnRecordsCompressionWithoutContentOrIdentity(t *testing.T) {
	conn := &compressionTestConn{reconnectTestConn: &reconnectTestConn{Reader: bytes.NewReader(nil)}, compression: TerminalCompressionTelemetry{RawFrames: 2, ZstdFrames: 3, DecodedBytes: 4096, EncodedBytes: 1024, DecodeNanos: 9000, DecodeFailures: 1}}
	sink := &tunnelEventSink{}
	c := NewObservedReconnectingConn(context.Background(), conn, 0, 0, nil, sink, time.Now, TelemetryContext{ProjectID: "prj_private", EnvironmentID: "env_private"})
	_, _ = io.ReadAll(c)
	_, _ = c.Wait()
	compressionEvents := 0
	for _, event := range sink.events {
		if event.Name != "terminal.compression" {
			continue
		}
		compressionEvents++
		if event.ProjectID != "" || event.EnvironmentID != "" || event.SessionID != "" || event.RequestID != "" {
			t.Fatalf("compression event contains identity: %+v", event)
		}
	}
	if compressionEvents != 6 {
		t.Fatalf("compression events=%d all=%+v", compressionEvents, sink.events)
	}
}

func TestCompressionTelemetryCountersSaturate(t *testing.T) {
	if got := telemetryInt64(math.MaxUint64); got != math.MaxInt64 {
		t.Fatalf("counter=%d", got)
	}
	if got := telemetryInt64SaturatingAdd(math.MaxInt64, 1); got != math.MaxInt64 {
		t.Fatalf("sum=%d", got)
	}
}

func TestReconnectingConnRecordsInputAndEchoStages(t *testing.T) {
	sink := &tunnelEventSink{}
	c := &ReconnectingConn{telemetry: sink, now: time.Now}
	c.ObserveInputWrite(4, 70*time.Millisecond)
	c.ObserveLocalWrite(4, 3*time.Millisecond)
	c.recordOutputPerformance("success")
	if len(sink.events) != 6 {
		t.Fatalf("events = %+v", sink.events)
	}
	if input := sink.events[1]; input.Name != "terminal.stage" || input.Stage != "stdin_to_socket" || input.SizeBytes != 4 || input.LatencyMS != 70 || input.Count != 1 {
		t.Fatalf("input stage = %+v", input)
	}
	if stall := sink.events[4]; stall.Stage != "flow_control_stall" || stall.LatencyMS != 70 || stall.Count != 1 {
		t.Fatalf("flow-control stage = %+v", stall)
	}
	if echo := sink.events[5]; echo.Name != "terminal.stage" || echo.Stage != "input_to_next_output" || echo.SizeBytes != 0 || echo.Count != 1 {
		t.Fatalf("echo stage = %+v", echo)
	}
}

func TestReconnectingConnBoundsFailures(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	c := NewReconnectingConn(context.Background(), first, 1, time.Millisecond, func(context.Context) (Conn, error) { return nil, errors.New("still offline") })
	_, _ = io.ReadAll(c)
	code, err := c.Wait()
	if err == nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestReconnectingConnStopsOnAuthoritativeFailure(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	attempts := 0
	c := NewReconnectingConn(context.Background(), first, 6, 0, func(context.Context) (Conn, error) {
		attempts++
		return nil, StopReconnect(errors.New("access revoked"))
	})
	_, err := c.Wait()
	if err == nil || attempts != 1 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
}

func TestReconnectingConnDoesNotRetryTerminalFailure(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: errors.New("remote command failed")}
	reconnects := 0
	c := NewReconnectingConn(context.Background(), first, 2, 0, func(context.Context) (Conn, error) {
		reconnects++
		return nil, errors.New("should not reconnect")
	})
	_, err := c.Wait()
	if err == nil || err.Error() != "remote command failed" || reconnects != 0 {
		t.Fatalf("err=%v reconnects=%d", err, reconnects)
	}
}

func TestReconnectingConnRejectsLateReconnectAfterClose(t *testing.T) {
	first := &reconnectTestConn{Reader: bytes.NewReader(nil), err: ErrTransportLost}
	replacement := &closeTrackingConn{reconnectTestConn: &reconnectTestConn{Reader: bytes.NewReader(nil)}}
	started := make(chan struct{})
	release := make(chan struct{})
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) {
		close(started)
		<-release
		return replacement, nil
	})
	<-started
	_ = c.Close()
	close(release)
	done := make(chan struct{})
	go func() { _, _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait hung after a late reconnect")
	}
	if !replacement.closed.Load() {
		t.Fatal("late reconnect result was not closed")
	}
}

type writeRaceConn struct{ wait chan error }

func (*writeRaceConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *writeRaceConn) Write([]byte) (int, error) {
	return 0, ErrTransportLost
}
func (c *writeRaceConn) Close() error {
	select {
	case c.wait <- nil:
	default:
	}
	return nil
}
func (c *writeRaceConn) MarkTransportLost(error) {
	select {
	case c.wait <- ErrTransportLost:
	default:
	}
}
func (*writeRaceConn) Resize(uint16, uint16) error { return nil }
func (c *writeRaceConn) Wait() (int, error)        { return 1, <-c.wait }

func TestReconnectingConnCoordinatesWriteFailureWithReconnect(t *testing.T) {
	first := &writeRaceConn{wait: make(chan error, 1)}
	second := &reconnectTestConn{Reader: bytes.NewReader(nil)}
	c := NewReconnectingConn(context.Background(), first, 1, 0, func(context.Context) (Conn, error) { return second, nil })
	if _, err := c.Write([]byte("uncertain")); !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("err=%v", err)
	}
	if _, err := c.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if second.writes.String() != "next" {
		t.Fatalf("replayed writes=%q", second.writes.String())
	}
	_ = c.Close()
}
