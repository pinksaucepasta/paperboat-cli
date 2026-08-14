package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/resumablestream"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/quic-go/quic-go/http3"
)

func TestPeerAttemptTrackerReleasesFailedDescriptorExactlyOnce(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/peer-attempts/psi_failed/7" || r.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"intent_id":"psi_failed"}}`)
	}))
	defer server.Close()
	tracker := &peerAttemptTracker{client: api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), attempts: make(map[string]directpath.AttemptDescriptor)}
	descriptor := directpath.AttemptDescriptor{IntentID: "psi_failed", AttemptGeneration: 7}
	tracker.Track(descriptor)
	if err := tracker.Release(descriptor); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Release(descriptor); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Revoke(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("revoke calls=%d", calls.Load())
	}
}

func TestAuthorizedApplicationStreamOutlivesAttachmentContext(t *testing.T) {
	header := streamauth.Header{OperationID: "operation_1", Consumer: "ssh", StreamID: "0123456789abcdef0123456789abcdef"}
	for name, create := range map[string]func(context.Context) (*resumablestream.Conn, error){
		"direct": func(lifetime context.Context) (*resumablestream.Conn, error) {
			return resumablestream.New(lifetime, resumablestream.Config{WindowBytes: 512 << 10, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: "endpoint", OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
		},
		"relay": func(lifetime context.Context) (*resumablestream.Conn, error) {
			return resumablestream.New(lifetime, resumablestream.Config{WindowBytes: 512 << 10, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: "endpoint", OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			setup, cancelSetup := context.WithCancel(context.Background())
			stream, err := create(lifetime)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			cancelSetup()
			select {
			case <-stream.Done():
				t.Fatal("attachment-context cancellation closed the application stream")
			case <-time.After(20 * time.Millisecond):
			}
			if setup.Err() == nil {
				t.Fatal("setup context was not canceled")
			}
			cancelLifetime()
			select {
			case <-stream.Done():
			case <-time.After(time.Second):
				t.Fatal("carrier-lifetime cancellation did not close the application stream")
			}
		})
	}
}

func TestPeerRecoveryAttemptContextUsesDescriptorDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	descriptor := directpath.AttemptDescriptor{ExpiresAt: now.Add(time.Minute)}
	descriptor.Document.Policy.RelayDeadlineMS = 750
	ctx, cancel, err := peerRecoveryAttemptContext(context.Background(), descriptor, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(now.Add(750*time.Millisecond)) {
		t.Fatalf("deadline=%v ok=%v", deadline, ok)
	}
}

func TestPeerRecoveryAttemptContextClampsToDescriptorExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	descriptor := directpath.AttemptDescriptor{ExpiresAt: now.Add(250 * time.Millisecond)}
	descriptor.Document.Policy.RelayDeadlineMS = 5_000
	ctx, cancel, err := peerRecoveryAttemptContext(context.Background(), descriptor, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(descriptor.ExpiresAt) {
		t.Fatalf("deadline=%v ok=%v", deadline, ok)
	}
}

func TestPeerRecoveryAttemptContextRejectsExpiredDescriptor(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	descriptor := directpath.AttemptDescriptor{ExpiresAt: now}
	descriptor.Document.Policy.RelayDeadlineMS = 5_000
	if _, _, err := peerRecoveryAttemptContext(context.Background(), descriptor, now); !errors.Is(err, ErrPeerCarrierExpired) {
		t.Fatalf("error=%v", err)
	}
}

/*
	Obsolete candidate-wide promotion tests retained temporarily for historical

comparison while the per-stream coordinator tests below cover the v2 contract.

	func legacyTestCandidateFailureReattachesLogicalStreamToStandby(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10, Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		server, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		defer server.Close()
		attach := func(left, right *resumablestream.Conn) net.Conn {
			a, b := net.Pipe()
			result := make(chan error, 2)
			go func() { result <- left.Attach(a) }()
			go func() { result <- right.Attach(b) }()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			return a
		}
		first := attach(client, server)
		header, err := streamauth.New("operation", "ssh", "stream", "credential", time.Now().Add(time.Hour), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		header.Resumable = true
		source := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header)}
		target := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header)}
		var opens atomic.Int64
		target.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
			opens.Add(1)
			a, b := net.Pipe()
			go func() { _ = server.Attach(b) }()
			return a, nil
		}
		source.setPromotion(func(context.Context) (*terminalPathCandidate, error) { return target, nil })
		source.SetStandby(target)
		source.trackStream(header, client)
		deadline := time.Now().Add(time.Second)
		for {
			source.streamsMu.Lock()
			ready := source.standbyReady[client].candidate == target
			source.streamsMu.Unlock()
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("logical stream standby was not ready before failure")
			}
			time.Sleep(time.Millisecond)
		}
		if opens.Load() != 1 {
			t.Fatalf("standby opens before failure=%d", opens.Load())
		}
		_ = first.Close()
		deadline = time.Now().Add(time.Second)
		for {
			target.streamsMu.Lock()
			migrated := len(target.streams) == 1
			target.streamsMu.Unlock()
			if migrated {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("logical stream was not migrated")
			}
			time.Sleep(time.Millisecond)
		}
		if opens.Load() != 1 {
			t.Fatalf("promotion reopened ready standby: opens=%d", opens.Load())
		}
		request := []byte{0, 0xff, 1, 0x80}
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, request) {
			t.Fatalf("migrated bytes=%x", got)
		}
	}

	func legacyTestCandidateKeepsReadyStandbyUntilReplacementAuthenticates(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10, Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		server, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		defer server.Close()
		attach := func(standby bool) net.Conn {
			left, right := net.Pipe()
			result := make(chan error, 2)
			if standby {
				go func() { result <- client.AttachStandby(left) }()
			} else {
				go func() { result <- client.Attach(left) }()
			}
			go func() { result <- server.Attach(right) }()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			return left
		}
		primary := attach(false)
		attach(true)
		header, err := streamauth.New("operation-replace", "exec", "stream-replace", "credential", time.Now().Add(time.Hour), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		header.Resumable = true
		oldStandby := &terminalPathCandidate{}
		replacement := &terminalPathCandidate{}
		replacementStarted := make(chan struct{})
		releaseReplacement := make(chan struct{})
		replacement.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
			close(replacementStarted)
			<-releaseReplacement
			return nil, errors.New("replacement unavailable")
		}
		source := &terminalPathCandidate{
			streams:      map[*resumablestream.Conn]streamauth.Header{client: header},
			standby:      oldStandby,
			standbyReady: map[*resumablestream.Conn]terminalStandbyBinding{client: {candidate: oldStandby}},
		}
		source.SetStandby(replacement)
		select {
		case <-replacementStarted:
		case <-time.After(time.Second):
			t.Fatal("replacement authentication did not start")
		}
		if err := primary.Close(); err != nil {
			t.Fatal(err)
		}
		payload := []byte("old-standby-preserves-continuity")
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("standby payload=%q err=%v", got, err)
		}
		close(releaseReplacement)
	}

	type closeNotifyConn struct {
		net.Conn
		once    sync.Once
		closing func()
	}

	func (c *closeNotifyConn) Close() error {
		c.once.Do(c.closing)
		return c.Conn.Close()
	}

	func legacyTestCandidateUpgradePreparesDemotedPrimaryBeforeReplacingCarrier(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10, Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		server, err := resumablestream.New(ctx, resumablestream.Config{WindowBytes: 64 << 10})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		defer server.Close()
		attachPeer := func(left net.Conn, right net.Conn, standby bool) {
			result := make(chan error, 2)
			if standby {
				go func() { result <- client.AttachStandby(left) }()
			} else {
				go func() { result <- client.Attach(left) }()
			}
			go func() { result <- server.Attach(right) }()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		}
		primaryAlive := atomic.Bool{}
		primaryAlive.Store(true)
		primaryLocal, primaryRemote := net.Pipe()
		attachPeer(&closeNotifyConn{Conn: primaryLocal, closing: func() { primaryAlive.Store(false) }}, primaryRemote, false)
		header, err := streamauth.New("operation-upgrade", "exec", "stream-upgrade", "credential", time.Now().Add(time.Hour), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		header.Resumable = true
		source := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header), standbyReady: make(map[*resumablestream.Conn]terminalStandbyBinding)}
		target := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header), standbyReady: make(map[*resumablestream.Conn]terminalStandbyBinding)}
		var sourceOpens atomic.Int64
		source.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
			if !primaryAlive.Load() {
				return nil, errors.New("demoted primary already detached")
			}
			sourceOpens.Add(1)
			local, remote := net.Pipe()
			go func() { _ = server.Attach(remote) }()
			return local, nil
		}
		target.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
			local, remote := net.Pipe()
			go func() { _ = server.Attach(remote) }()
			return local, nil
		}
		target.SetStandby(source)
		source.setPromotion(func(context.Context) (*terminalPathCandidate, error) { return target, nil })
		source.trackStream(header, client)
		source.PromoteStreams()
		if sourceOpens.Load() != 1 {
			t.Fatalf("demoted standby opens=%d", sourceOpens.Load())
		}
		target.streamsMu.Lock()
		ready := target.standbyReady[client].candidate == source
		target.streamsMu.Unlock()
		if !ready {
			t.Fatal("demoted primary was not retained as ready standby")
		}
		payload := []byte("upgrade-continues")
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("promoted payload=%q err=%v", got, err)
		}
	}

	func legacyTestCandidateRepeatedPromotionsPreserveBinaryStream(t *testing.T) {
		client, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 256 << 10, Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		server, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 256 << 10})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		defer server.Close()

		attach := func(standby bool) {
			left, right := net.Pipe()
			attached := make(chan error, 2)
			if standby {
				go func() { attached <- client.AttachStandby(left) }()
			} else {
				go func() { attached <- client.Attach(left) }()
			}
			go func() { attached <- server.Attach(right) }()
			for range 2 {
				if err := <-attached; err != nil {
					t.Fatal(err)
				}
			}
		}
		attach(false)
		header, err := streamauth.New("operation-cycle", "ssh", "stream-cycle", "credential", time.Now().Add(time.Hour), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		header.Resumable = true

		candidates := make([]*terminalPathCandidate, 7)
		for index := range candidates {
			candidate := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header), standbyReady: make(map[*resumablestream.Conn]terminalStandbyBinding)}
			candidate.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
				left, right := net.Pipe()
				go func() { _ = server.Attach(right) }()
				return left, nil
			}
			candidates[index] = candidate
		}
		candidates[0].trackStream(header, client)
		paths := []string{"direct", "wss", "relay-quic", "direct", "wss", "relay-quic", "direct"}
		for index := 1; index < len(candidates); index++ {
			current, next := candidates[index-1], candidates[index]
			current.SetStandby(next)
			deadline := time.Now().Add(time.Second)
			for {
				current.streamsMu.Lock()
				ready := current.standbyReady[client].candidate == next
				current.streamsMu.Unlock()
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s standby did not become ready", paths[index])
				}
				time.Sleep(time.Millisecond)
			}
			current.setPromotion(func(context.Context) (*terminalPathCandidate, error) { return next, nil })
			if err := current.PromoteStreamsChecked(); err != nil {
				t.Fatalf("promote to %s: %v", paths[index], err)
			}
			payload := []byte{byte(index), 0, 0xff, 0x80, byte(index + 17)}
			if _, err := client.Write(payload); err != nil {
				t.Fatalf("write after %s: %v", paths[index], err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("read after %s: got=%x err=%v", paths[index], got, err)
			}
		}
	}

	func legacyTestCandidateCheckedPromotionRejectsLostReadyStandby(t *testing.T) {
		client, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10, Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		server, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		defer server.Close()
		left, right := net.Pipe()
		attached := make(chan error, 2)
		go func() { attached <- client.Attach(left) }()
		go func() { attached <- server.Attach(right) }()
		for range 2 {
			if err := <-attached; err != nil {
				t.Fatal(err)
			}
		}
		header, err := streamauth.New("operation-lost-standby", "ssh", "stream-lost-standby", "credential", time.Now().Add(time.Hour), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		header.Resumable = true
		target := &terminalPathCandidate{openAuthorized: func(context.Context, streamauth.Header) (net.Conn, error) {
			return nil, errors.New("must not reopen a standby recorded as ready")
		}}
		source := &terminalPathCandidate{
			streams:      map[*resumablestream.Conn]streamauth.Header{client: header},
			standby:      target,
			standbyReady: map[*resumablestream.Conn]terminalStandbyBinding{client: {candidate: target, generation: math.MaxUint64}},
		}
		source.setPromotion(func(context.Context) (*terminalPathCandidate, error) { return target, nil })

		if err := source.PromoteStreamsChecked(); !errors.Is(err, ErrPeerStreamPromotion) {
			t.Fatalf("promotion error=%v", err)
		}
		source.streamsMu.Lock()
		_, sourceOwns := source.streams[client]
		source.streamsMu.Unlock()
		target.streamsMu.Lock()
		_, targetOwns := target.streams[client]
		target.streamsMu.Unlock()
		if !sourceOwns || targetOwns {
			t.Fatalf("source owns=%t target owns=%t", sourceOwns, targetOwns)
		}
	}

	func legacyTestCandidateConcurrentPromotionCallersShareFailure(t *testing.T) {
		source := &terminalPathCandidate{}
		started := make(chan struct{})
		release := make(chan struct{})
		want := errors.New("candidate stream migration failed")
		source.setPromotion(func(context.Context) (*terminalPathCandidate, error) {
			close(started)
			<-release
			return nil, want
		})
		results := make(chan error, 2)
		go func() { results <- source.PromoteStreamsChecked() }()
		<-started
		go func() { results <- source.PromoteStreamsChecked() }()
		close(release)
		for range 2 {
			if err := <-results; !errors.Is(err, want) {
				t.Fatalf("promotion error=%v", err)
			}
		}
	}

	func legacyTestCandidateCheckedPromotionRollsBackPartiallyMigratedStreams(t *testing.T) {
		type streamPair struct {
			client *resumablestream.Conn
			server *resumablestream.Conn
		}
		pairs := make([]streamPair, 2)
		for index := range pairs {
			client, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10, Initiator: true})
			if err != nil {
				t.Fatal(err)
			}
			server, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			left, right := net.Pipe()
			attached := make(chan error, 2)
			go func() { attached <- client.Attach(left) }()
			go func() { attached <- server.Attach(right) }()
			for range 2 {
				if err := <-attached; err != nil {
					t.Fatal(err)
				}
			}
			pairs[index] = streamPair{client: client, server: server}
		}
		source := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header), standbyReady: make(map[*resumablestream.Conn]terminalStandbyBinding)}
		target := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]streamauth.Header), standbyReady: make(map[*resumablestream.Conn]terminalStandbyBinding)}
		servers := map[string]*resumablestream.Conn{"stream-0": pairs[0].server, "stream-1": pairs[1].server}
		var targetOpens atomic.Int64
		source.openAuthorized = func(_ context.Context, header streamauth.Header) (net.Conn, error) {
			left, right := net.Pipe()
			go func() { _ = servers[header.StreamID].Attach(right) }()
			return left, nil
		}
		target.openAuthorized = func(_ context.Context, header streamauth.Header) (net.Conn, error) {
			if targetOpens.Add(1) == 2 {
				return nil, errors.New("second target stream unavailable")
			}
			left, right := net.Pipe()
			go func() { _ = servers[header.StreamID].Attach(right) }()
			return left, nil
		}
		target.SetStandby(source)
		for index, pair := range pairs {
			header, err := streamauth.New("operation-partial", "ssh", fmt.Sprintf("stream-%d", index), "credential", time.Now().Add(time.Hour), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			header.Resumable = true
			source.trackStream(header, pair.client)
		}
		source.setPromotion(func(context.Context) (*terminalPathCandidate, error) { return target, nil })
		if err := source.PromoteStreamsChecked(); err == nil {
			t.Fatal("partial migration reported success")
		}
		source.streamsMu.Lock()
		sourceOwned := len(source.streams)
		source.streamsMu.Unlock()
		target.streamsMu.Lock()
		targetOwned := len(target.streams)
		target.streamsMu.Unlock()
		if sourceOwned != len(pairs) || targetOwned != 0 {
			t.Fatalf("split ownership after rollback: source=%d target=%d", sourceOwned, targetOwned)
		}
		for index, pair := range pairs {
			payload := []byte{byte(index), 0, 0xff, 0x80}
			if _, err := pair.client.Write(payload); err != nil {
				t.Fatalf("stream %d write after rollback: %v", index, err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(pair.server, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("stream %d after rollback: got=%x err=%v", index, got, err)
			}
		}
	}
*/
func TestCandidateAuthorityInvalidationAbortsTrackedLogicalStream(t *testing.T) {
	stream, err := resumablestream.New(context.Background(), resumablestream.Config{WindowBytes: 64 << 10, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: "endpoint", OperationID: "operation", Consumer: "exec", StreamID: "0123456789abcdef0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	candidate := &terminalPathCandidate{streams: make(map[*resumablestream.Conn]*streamCoordinator)}
	candidate.streams[stream] = nil
	candidate.AbortApplications(connectionmanager.ErrPoolInvalidated)
	select {
	case <-stream.Done():
	case <-time.After(time.Second):
		t.Fatal("authority invalidation did not abort logical stream")
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, connectionmanager.ErrPoolInvalidated) {
		t.Fatalf("stream error=%v", err)
	}
}

func TestCoordinatorInheritsFallbackPublishedBeforeRegistration(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	old := coordinatorTestCandidate()
	next := coordinatorTestCandidate()
	fallback := coordinatorTestCandidate()
	var opens atomic.Int32
	fallback.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		opens.Add(1)
		left, right := net.Pipe()
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	revision := terminalPublicationRevision.Add(1)
	next.standby, next.standbyRevision = fallback, revision
	coordinator := coordinatorTestStream(client, old)
	old.streams[client] = coordinator
	coordinator.commitSource(next)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		coordinator.mu.Lock()
		prepared := coordinator.prepared == fallback
		coordinator.mu.Unlock()
		if prepared {
			break
		}
		time.Sleep(time.Millisecond)
	}
	coordinator.mu.Lock()
	prepared := coordinator.prepared
	coordinator.mu.Unlock()
	if prepared != fallback || opens.Load() != 1 {
		t.Fatalf("prepared=%p fallback=%p opens=%d", prepared, fallback, opens.Load())
	}
	coordinator.close()
}

func TestCoordinatorFallbackInheritanceCannotOverwriteNewerPreference(t *testing.T) {
	client, _ := coordinatorStreamPair(t)
	old := coordinatorTestCandidate()
	next := coordinatorTestCandidate()
	fallback := coordinatorTestCandidate()
	preferred := coordinatorTestCandidate()
	var fallbackOpens atomic.Int32
	fallback.openAuthorized = func(context.Context, streamauth.Header) (net.Conn, error) {
		fallbackOpens.Add(1)
		return nil, errors.New("unexpected fallback open")
	}
	baseRevision := terminalPublicationRevision.Add(1)
	next.standby, next.standbyRevision = fallback, baseRevision
	coordinator := coordinatorTestStream(client, old)
	old.streams[client] = coordinator
	coordinator.setDesiredRevision(preferred, true, baseRevision+1)
	coordinator.commitSource(next)
	coordinator.mu.Lock()
	desired, promote, revision := coordinator.desired, coordinator.promoteDesired, coordinator.desiredRevision
	coordinator.mu.Unlock()
	if desired != preferred || !promote || revision != baseRevision+1 || fallbackOpens.Load() != 0 {
		t.Fatalf("desired=%p preferred=%p promote=%t revision=%d fallback_opens=%d", desired, preferred, promote, revision, fallbackOpens.Load())
	}
	coordinator.close()
}

func TestCoordinatorNewPreferenceSupersedesPreparedFallback(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	current := coordinatorTestCandidate()
	fallback := coordinatorTestCandidate()
	preferred := coordinatorTestCandidate()
	open := func(counter *atomic.Int32) func(context.Context, streamauth.Header) (net.Conn, error) {
		return func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
			counter.Add(1)
			left, right := net.Pipe()
			go func() { _ = server.AcceptCarrier(ctx, right) }()
			return left, nil
		}
	}
	var fallbackOpens, preferredOpens atomic.Int32
	fallback.openAuthorized = open(&fallbackOpens)
	preferred.openAuthorized = open(&preferredOpens)
	coordinator := coordinatorTestStream(client, current)
	current.streams[client] = coordinator
	coordinator.setDesiredRevision(fallback, false, terminalPublicationRevision.Add(1))
	waitCoordinatorSource(t, coordinator, fallback, false)
	coordinator.setDesiredRevision(preferred, true, terminalPublicationRevision.Add(1))
	waitCoordinatorSource(t, coordinator, preferred, true)
	if fallbackOpens.Load() != 1 || preferredOpens.Load() != 1 {
		t.Fatalf("fallback opens=%d preferred opens=%d", fallbackOpens.Load(), preferredOpens.Load())
	}
	coordinator.close()
}

func TestCoordinatorPreparedFallbackPromotesWhenItBecomesPreferred(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	current := coordinatorTestCandidate()
	fallback := coordinatorTestCandidate()
	var opens atomic.Int32
	fallback.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		opens.Add(1)
		left, right := net.Pipe()
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	coordinator := coordinatorTestStream(client, current)
	current.streams[client] = coordinator
	coordinator.setDesiredRevision(fallback, false, terminalPublicationRevision.Add(1))
	waitCoordinatorSource(t, coordinator, fallback, false)
	coordinator.setDesiredRevision(fallback, true, terminalPublicationRevision.Add(1))
	waitCoordinatorSource(t, coordinator, fallback, true)
	if opens.Load() != 1 {
		t.Fatalf("fallback opens=%d want=1", opens.Load())
	}
	payload := []byte("promoted-prepared-fallback")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	coordinator.close()
}

type commitAckBarrierConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *commitAckBarrierConn) Write(value []byte) (int, error) {
	// Resumable v2 COMMIT_ACK is frame 7. Hello messages have a different
	// fixed shape and kind, so only the transition acknowledgement is held.
	if len(value) == 13 && value[0] == 7 {
		c.once.Do(func() { close(c.started) })
		select {
		case <-c.release:
		case <-time.After(time.Second):
			return 0, context.DeadlineExceeded
		}
	}
	return c.Conn.Write(value)
}

func TestCoordinatorSerializesNewSnapshotBehindCommit(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, direct, wss := coordinatorTestCandidate(), coordinatorTestCandidate(), coordinatorTestCandidate()
	commitStarted, releaseCommit := make(chan struct{}), make(chan struct{})
	direct.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		barrier := &commitAckBarrierConn{Conn: right, started: commitStarted, release: releaseCommit}
		go func() { _ = server.AcceptCarrier(ctx, barrier) }()
		return left, nil
	}
	open := func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	relay.openAuthorized, wss.openAuthorized = open, open
	inbox := make(chan connectionmanager.AvailabilitySnapshot, 2)
	coordinator := coordinatorTestStream(client, relay)
	coordinator.availability = inbox
	relay.streams[client] = coordinator
	go coordinator.run()
	inbox <- coordinatorSnapshot(1, direct, direct, relay, wss)
	select {
	case <-commitStarted:
	case <-time.After(time.Second):
		t.Fatal("direct COMMIT did not start")
	}
	inbox <- coordinatorSnapshot(2, relay, relay, wss)
	close(releaseCommit)
	waitCoordinatorSettled(t, coordinator, 2, relay, wss)
	payload := []byte("serialized-commit")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	_ = client.Close()
}

func TestCoordinatorPromotesPreparedWSSAfterDirectAndRelayFailures(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, direct, wss := coordinatorTestCandidate(), coordinatorTestCandidate(), coordinatorTestCandidate()
	type openedCarrier struct {
		source *terminalPathCandidate
		peer   net.Conn
	}
	opened := make(chan openedCarrier, 3)
	configure := func(source *terminalPathCandidate) {
		source.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
			left, right := net.Pipe()
			opened <- openedCarrier{source: source, peer: right}
			go func() { _ = server.AcceptCarrier(ctx, right) }()
			return left, nil
		}
	}
	configure(relay)
	configure(direct)
	configure(wss)
	inbox := make(chan connectionmanager.AvailabilitySnapshot, 3)
	coordinator := coordinatorTestStream(client, relay)
	coordinator.availability = inbox
	relay.streams[client] = coordinator
	go coordinator.run()

	inbox <- coordinatorSnapshot(1, direct, direct, relay, wss)
	waitCoordinatorSettled(t, coordinator, 1, direct, relay)
	inbox <- coordinatorSnapshot(2, relay, relay, wss)
	waitCoordinatorSettled(t, coordinator, 2, relay, wss)

	var relayPeer net.Conn
	for range 3 {
		carrier := <-opened
		if carrier.source == relay {
			relayPeer = carrier.peer
		}
	}
	if relayPeer == nil {
		t.Fatal("relay carrier was not opened")
	}
	if err := relayPeer.Close(); err != nil {
		t.Fatal(err)
	}
	waitCoordinatorSource(t, coordinator, wss, true)

	payload := []byte("prepared-wss-failover")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	_ = client.Close()
}

func TestCoordinatorSourceReleaseDoesNotWaitForPhysicalCleanup(t *testing.T) {
	candidate := coordinatorTestCandidate()
	candidate.health = &candidateHealth{}
	releaseStarted := make(chan struct{})
	release := make(chan struct{})
	candidate.sourceRefs = 1
	candidate.closePending = true
	candidate.releaseLease = func(context.Context) error {
		close(releaseStarted)
		<-release
		return nil
	}
	done := make(chan struct{})
	go func() {
		candidate.releaseSource()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("source release waited for physical cleanup")
	}
	select {
	case <-releaseStarted:
	case <-time.After(time.Second):
		t.Fatal("physical cleanup did not start")
	}
	close(release)
}

func TestRetainedRelayLifetimeReleasesLeaseBeforeCarrierCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	carrier, cancelCarrier := context.WithCancel(context.Background())
	health := &candidateHealth{}
	released := make(chan struct{})
	var releasedAfterCancel atomic.Bool
	candidate := &terminalPathCandidate{health: health, streams: make(map[*resumablestream.Conn]*streamCoordinator), sourceRefs: 1}
	candidate.releaseLease = func(context.Context) error {
		select {
		case <-carrier.Done():
			releasedAfterCancel.Store(true)
		default:
		}
		close(released)
		return nil
	}
	candidate.bindRetainedCarrierLifetime(parent, carrier, cancelCarrier)

	cancelParent()
	deadline := time.Now().Add(time.Second)
	for {
		candidate.mu.Lock()
		pending := candidate.closePending
		candidate.mu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent cancellation did not begin candidate close")
		}
		runtime.Gosched()
	}
	select {
	case <-carrier.Done():
		t.Fatal("carrier canceled while logical source remained attached")
	default:
	}

	candidate.releaseSource()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("lease release did not run after source drained")
	}
	if releasedAfterCancel.Load() {
		t.Fatal("carrier canceled before lease release")
	}
	select {
	case <-carrier.Done():
	case <-time.After(time.Second):
		t.Fatal("carrier lifetime was not canceled after lease release")
	}
	if !health.closed.Load() {
		t.Fatal("carrier health was not closed")
	}
}

func TestCoordinatorReconcilesNewSnapshotAfterPreferredOpenFails(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, direct, wss := coordinatorTestCandidate(), coordinatorTestCandidate(), coordinatorTestCandidate()
	openStarted, releaseOpen := make(chan struct{}), make(chan struct{})
	direct.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		close(openStarted)
		select {
		case <-releaseOpen:
			return nil, errors.New("direct source invalidated during open")
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	wss.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	inbox := make(chan connectionmanager.AvailabilitySnapshot, 2)
	coordinator := coordinatorTestStream(client, relay)
	coordinator.availability = inbox
	relay.streams[client] = coordinator
	go coordinator.run()
	inbox <- coordinatorSnapshot(1, direct, direct, relay, wss)
	select {
	case <-openStarted:
	case <-time.After(time.Second):
		t.Fatal("direct carrier open did not start")
	}
	inbox <- coordinatorSnapshot(2, relay, relay, wss)
	close(releaseOpen)
	waitCoordinatorSettled(t, coordinator, 2, relay, wss)
	payload := []byte("relay-survived-open-failure")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	_ = client.Close()
}

func TestCoordinatorDetachedFromPoolPreferredPromotesAvailableFallback(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, wss := coordinatorTestCandidate(), coordinatorTestCandidate()
	open := func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	relay.openAuthorized, wss.openAuthorized = open, open
	coordinator := coordinatorTestStream(client, relay)
	coordinator.detached = time.Now()
	go coordinator.reconcileSnapshot(coordinatorSnapshot(1, relay, relay, wss))
	waitCoordinatorSettled(t, coordinator, 1, wss, relay)
	coordinator.close()
}

func TestCoordinatorClearsFailedPreparedCarrierHandle(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, wss := coordinatorTestCandidate(), coordinatorTestCandidate()
	var preparedPeer net.Conn
	wss.openAuthorized = func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		preparedPeer = right
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	coordinator := coordinatorTestStream(client, relay)
	coordinator.availability = make(chan connectionmanager.AvailabilitySnapshot)
	relay.streams[client] = coordinator
	go coordinator.run()
	coordinator.reconcileSnapshot(coordinatorSnapshot(1, relay, relay, wss))
	waitCoordinatorSettled(t, coordinator, 1, relay, wss)
	_ = preparedPeer.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		coordinator.mu.Lock()
		cleared := coordinator.prepared == nil && coordinator.handle == (resumablestream.CarrierHandle{})
		coordinator.mu.Unlock()
		if cleared {
			_ = client.Close()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("failed prepared carrier remained cached by coordinator")
}

func TestCoordinatorRetriesUnsettledSnapshotAfterPreparedFailureArrives(t *testing.T) {
	client, server := coordinatorStreamPair(t)
	relay, staleWSS, freshWSS := coordinatorTestCandidate(), coordinatorTestCandidate(), coordinatorTestCandidate()
	peers := make(chan net.Conn, 3)
	open := func(ctx context.Context, _ streamauth.Header) (net.Conn, error) {
		left, right := net.Pipe()
		peers <- right
		go func() { _ = server.AcceptCarrier(ctx, right) }()
		return left, nil
	}
	relay.openAuthorized, staleWSS.openAuthorized, freshWSS.openAuthorized = open, open, open
	coordinator := coordinatorTestStream(client, relay)
	coordinator.availability = make(chan connectionmanager.AvailabilitySnapshot)

	coordinator.reconcileSnapshot(coordinatorSnapshot(1, relay, relay, staleWSS))
	waitCoordinatorSettled(t, coordinator, 1, relay, staleWSS)
	coordinator.mu.Lock()
	failedID := coordinator.handle.ID
	coordinator.mu.Unlock()
	_ = (<-peers).Close()

	var failed resumablestream.Event
	deadline := time.After(time.Second)
	for failed.Type != resumablestream.EventCarrierFailed || failed.FailedCarrier != failedID {
		select {
		case failed = <-client.Events():
		case <-deadline:
			t.Fatal("prepared carrier failure event not emitted")
		}
	}
	var responderFailed resumablestream.Event
	deadline = time.After(time.Second)
	for responderFailed.Type != resumablestream.EventCarrierFailed || responderFailed.FailedCarrier != failedID {
		select {
		case responderFailed = <-server.Events():
		case <-deadline:
			t.Fatal("responder did not finish prepared carrier cleanup")
		}
	}

	coordinator.reconcileSnapshot(coordinatorSnapshot(2, freshWSS, freshWSS, relay))
	coordinator.mu.Lock()
	observed, settled := coordinator.observedRevision, coordinator.settledRevision
	coordinator.mu.Unlock()
	if observed != 2 || settled != 1 {
		t.Fatalf("observed=%d settled=%d want observed=2 settled=1", observed, settled)
	}

	coordinator.clearFailedPrepared(failed)
	coordinator.wakeUnsettledSnapshot()
	go coordinator.run()
	waitCoordinatorSettled(t, coordinator, 2, freshWSS, relay)

	payload := []byte("retried-unsettled-snapshot")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	_ = client.Close()
}

func coordinatorSnapshot(revision uint64, preferred *terminalPathCandidate, available ...*terminalPathCandidate) connectionmanager.AvailabilitySnapshot {
	snapshot := connectionmanager.AvailabilitySnapshot{Revision: revision, Preferred: connectionmanager.AvailabilitySource{Connection: preferred}}
	for index, candidate := range available {
		snapshot.Available = append(snapshot.Available, connectionmanager.AvailabilitySource{Path: connectionmanager.Path(index + 1), Generation: revision, Connection: candidate})
	}
	return snapshot
}

func waitCoordinatorSettled(t *testing.T, coordinator *streamCoordinator, revision uint64, current, prepared *terminalPathCandidate) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		coordinator.mu.Lock()
		matched := coordinator.settledRevision == revision && coordinator.current == current && coordinator.prepared == prepared
		coordinator.mu.Unlock()
		if matched {
			return
		}
		time.Sleep(time.Millisecond)
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	t.Fatalf("settled=%d current=%p prepared=%p want revision=%d current=%p prepared=%p", coordinator.settledRevision, coordinator.current, coordinator.prepared, revision, current, prepared)
}

func waitCoordinatorSource(t *testing.T, coordinator *streamCoordinator, source *terminalPathCandidate, current bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		coordinator.mu.Lock()
		matched := coordinator.prepared == source
		if current {
			matched = coordinator.current == source
		}
		coordinator.mu.Unlock()
		if matched {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("coordinator did not reach source=%p current=%t", source, current)
}

func coordinatorStreamPair(t *testing.T) (*resumablestream.Conn, *resumablestream.Conn) {
	t.Helper()
	identity := resumablestream.StreamIdentity{Principal: "endpoint", OperationID: "operation", Consumer: "exec", StreamID: "0123456789abcdef0123456789abcdef"}
	client, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10, Role: resumablestream.RoleInitiator, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	server, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: 64 << 10, Role: resumablestream.RoleResponder, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	accepted := make(chan error, 1)
	go func() { accepted <- server.AcceptCarrier(t.Context(), right) }()
	if err := client.AttachInitial(t.Context(), left); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func coordinatorTestCandidate() *terminalPathCandidate {
	return &terminalPathCandidate{streams: make(map[*resumablestream.Conn]*streamCoordinator), openAuthorized: func(context.Context, streamauth.Header) (net.Conn, error) {
		return nil, errors.New("carrier unavailable")
	}}
}

func coordinatorTestStream(stream *resumablestream.Conn, current *terminalPathCandidate) *streamCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	current.sourceRefs = 1
	return &streamCoordinator{ctx: ctx, cancel: cancel, stream: stream, header: streamauth.Header{OperationID: "operation", Consumer: "exec", StreamID: "0123456789abcdef0123456789abcdef", DeadlineUnix: time.Now().Add(time.Minute).Unix()}, current: current, committedEpoch: 1, reconcileWake: make(chan struct{}, 1)}
}

func TestAuthorizedStreamIDsRemainUniqueAcrossConcurrentAttachments(t *testing.T) {
	t.Parallel()
	const streams = 64
	ids := make(chan string, streams)
	var group sync.WaitGroup
	for range streams {
		group.Add(1)
		go func() {
			defer group.Done()
			id, err := nextAuthorizedStreamID()
			if err != nil {
				t.Errorf("allocate stream id: %v", err)
				return
			}
			ids <- id
		}()
	}
	group.Wait()
	close(ids)
	seen := make(map[string]bool, streams)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate stream id %q", id)
		}
		seen[id] = true
	}
	if len(seen) != streams {
		t.Fatalf("allocated %d unique stream ids, want %d", len(seen), streams)
	}
}

type mappingObservationSource struct{ err error }

func TestPeerAllowedPathsPreservesConfiguredMode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		mode connectionmanager.Mode
		want []string
	}{
		{connectionmanager.ModeAuto, []string{"direct_quic", "relay_quic", "relay_wss"}},
		{connectionmanager.ModeQUIC, []string{"direct_quic", "relay_quic"}},
		{connectionmanager.ModeWSS, []string{"relay_wss"}},
		{connectionmanager.ModeDirectQUIC, []string{"direct_quic"}},
		{connectionmanager.ModeRelayQUIC, []string{"relay_quic"}},
	} {
		if got := peerAllowedPaths(test.mode); !slices.Equal(got, test.want) {
			t.Fatalf("mode=%d paths=%v want=%v", test.mode, got, test.want)
		}
	}
}

func TestPrivatePreviewIgnoresRequestedAutoAndRemainsDirectOnly(t *testing.T) {
	mode, class, ok := peerApplicationMode(connectionmanager.ModeAuto, "a", "private_preview")
	if !ok || mode != connectionmanager.ModeDirectQUIC || class != peerquic.ClassPreview || !slices.Equal(peerAllowedPaths(mode), []string{"direct_quic"}) {
		t.Fatalf("mode=%d class=%d ok=%t paths=%v", mode, class, ok, peerAllowedPaths(mode))
	}
	purpose, consumer := peerDescriptorScope("private_preview", peerApplication{quic: func(context.Context, *http3.ClientConn, func() error) (Conn, error) { return nil, nil }}, false)
	if purpose != "private_preview" || consumer != "private_preview" {
		t.Fatalf("purpose=%q consumer=%q", purpose, consumer)
	}
}

func TestPrivatePreviewCandidateAllowsMultipleHTTP3Attachments(t *testing.T) {
	health := &candidateHealth{}
	attachments := 0
	candidate, err := newTerminalPathCandidate(health, func(context.Context, terminalAttachment) (Conn, error) {
		attachments++
		return candidateTerminal{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate.singleUse = false
	for range 2 {
		connection, attachErr := candidate.Attach(context.Background(), terminalAttachment{})
		if attachErr != nil {
			t.Fatal(attachErr)
		}
		_ = connection.Close()
	}
	if attachments != 2 {
		t.Fatalf("attachments=%d", attachments)
	}
}

func TestHealthAutoUsesFirstAuthenticatedPathWithoutPreferenceHold(t *testing.T) {
	base := connectionmanager.Config{RelayDelay: time.Second, WSSDelay: 2 * time.Second, ConnectTimeout: 10 * time.Second}
	health := peerRaceConfig(base, true, connectionmanager.ModeAuto)
	if health.RelayDelay != 0 || health.WSSDelay != base.WSSDelay || health.ConnectTimeout != base.ConnectTimeout {
		t.Fatalf("health config=%+v", health)
	}
	interactive := peerRaceConfig(base, false, connectionmanager.ModeAuto)
	if interactive != base {
		t.Fatalf("interactive config changed: %+v", interactive)
	}
}

func (s mappingObservationSource) AcquireSocketMapping(context.Context, uint64, uint16, net.PacketConn, []string) (portmapping.VerifiedMapping, netip.Addr, error) {
	return portmapping.VerifiedMapping{}, netip.Addr{}, s.err
}

func TestPeerOperationIDBindsEndpointsAndGeneration(t *testing.T) {
	t.Parallel()
	seed := [16]byte{1}
	base := peerOperationID("cli_01", "machine_01", "interactive", seed, 1, directpath.Generation{Attempt: 1, Network: 1})
	if base == "" || base != peerOperationID("cli_01", "machine_01", "interactive", seed, 1, directpath.Generation{Attempt: 1, Network: 1}) {
		t.Fatal("operation ID is not stable")
	}
	for _, changed := range []string{
		peerOperationID("cli_02", "machine_01", "interactive", seed, 1, directpath.Generation{Attempt: 1, Network: 1}),
		peerOperationID("cli_01", "machine_02", "interactive", seed, 1, directpath.Generation{Attempt: 1, Network: 1}),
		peerOperationID("cli_01", "machine_01", "codex", seed, 1, directpath.Generation{Attempt: 1, Network: 1}),
		peerOperationID("cli_01", "machine_01", "interactive", [16]byte{2}, 1, directpath.Generation{Attempt: 1, Network: 1}),
		peerOperationID("cli_01", "machine_01", "interactive", seed, 2, directpath.Generation{Attempt: 1, Network: 1}),
		peerOperationID("cli_01", "machine_01", "interactive", seed, 1, directpath.Generation{Attempt: 2, Network: 1}),
		peerOperationID("cli_01", "machine_01", "interactive", seed, 1, directpath.Generation{Attempt: 1, Network: 2}),
	} {
		if changed == base {
			t.Fatal("operation ID did not bind every authority field")
		}
	}
}

func TestInteractiveConsumersRemainDistinct(t *testing.T) {
	t.Parallel()
	for _, consumer := range []string{"terminal", "exec", "ssh"} {
		if purpose := peerPurpose(consumer, peerApplication{}); purpose != "interactive" {
			t.Fatalf("consumer %q purpose=%q", consumer, purpose)
		}
	}
}

func TestApplicationDescriptorsUseReusablePeerTransport(t *testing.T) {
	t.Parallel()
	for _, consumer := range []string{"terminal", "exec", "ssh", "private_preview", "codex"} {
		purpose, descriptorConsumer := peerDescriptorScope(consumer, peerApplication{}, false)
		if purpose != "peer_transport" || descriptorConsumer != "peer_transport" {
			t.Fatalf("consumer=%s purpose=%s descriptor_consumer=%s", consumer, purpose, descriptorConsumer)
		}
	}
}

func TestDirectFallbackRejectsSecurityAndProtocolFailures(t *testing.T) {
	t.Parallel()
	for _, err := range []error{signaling.ErrTransportAuthentication, signaling.ErrTransportCertificate, signaling.ErrTransportProtocol, signaling.ErrInvalid, directpath.ErrDescriptorUnauthorized, directpath.ErrDescriptorRevoked} {
		if directFallbackEligible(context.Background(), err) {
			t.Fatalf("direct failure became fallback eligible: %v", err)
		}
	}
	if !directFallbackEligible(context.Background(), errors.Join(directpath.ErrReachability, errors.New("ICE path unreachable"))) {
		t.Fatal("reachability failure was not fallback eligible")
	}
	if !directFallbackEligible(context.Background(), fmt.Errorf("signaling closed before candidates: %w", io.EOF)) {
		t.Fatal("signaling EOF was not fallback eligible")
	}
	if !directFallbackEligible(context.Background(), &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Cause: errors.New("temporary path failure")}) {
		t.Fatal("typed transient failure was not fallback eligible")
	}
	if directFallbackEligible(context.Background(), errors.New("unknown direct-path failure")) {
		t.Fatal("unknown direct-path failure became fallback eligible")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if directFallbackEligible(canceled, directpath.ErrReachability) {
		t.Fatal("caller cancellation became fallback eligible")
	}
}

func TestDirectFailureClassificationPreservesNATAndTerminalFailures(t *testing.T) {
	t.Parallel()
	natCause := errors.Join(directpath.ErrReachability, errors.New("ICE checklist exhausted"))
	classified := classifyDirectFailure(context.Background(), connectionmanager.PathDirectQUIC, natCause)
	var failure *connectionmanager.Failure
	if !errors.As(classified, &failure) || failure.Class != connectionmanager.FailureNAT || failure.Path != connectionmanager.PathDirectQUIC || !errors.Is(classified, natCause) {
		t.Fatalf("NAT failure=%v", classified)
	}
	security := signaling.ErrTransportAuthentication
	if got := classifyDirectFailure(context.Background(), connectionmanager.PathDirectQUIC, security); got != security {
		t.Fatalf("security failure changed to %v", got)
	}
}

func TestRelayFallbackRequiresExplicitTransientClass(t *testing.T) {
	t.Parallel()
	if !relayFallbackEligible(context.Background(), &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: connectionmanager.PathRelayQUIC, Cause: errors.New("relay unavailable")}) {
		t.Fatal("typed relay transient failure was not fallback eligible")
	}
	blockedUDP := &net.OpError{Op: "write", Net: "udp", Err: os.ErrPermission}
	if !relayFallbackEligible(context.Background(), fmt.Errorf("relay QUIC request failed: %w", blockedUDP)) {
		t.Fatal("UDP policy failure was not fallback eligible")
	}
	for _, err := range []error{
		errors.New("unknown relay failure"),
		&connectionmanager.Failure{Class: connectionmanager.FailureAuthentication, Path: connectionmanager.PathRelayQUIC, Cause: errors.New("bad route token")},
		&connectionmanager.Failure{Class: connectionmanager.FailureProtocol, Path: connectionmanager.PathRelayQUIC, Cause: errors.New("bad response")},
	} {
		if relayFallbackEligible(context.Background(), err) {
			t.Fatalf("terminal relay failure became fallback eligible: %v", err)
		}
	}
}

func TestPeerNetworkGenerationSaturatesWithoutZero(t *testing.T) {
	t.Parallel()
	peer := &PeerTerminalTunnel{}
	peer.network.Store(math.MaxUint64 - 1)
	peer.advanceNetwork()
	peer.advanceNetwork()
	if got := peer.network.Load(); got != math.MaxUint64 {
		t.Fatalf("network generation=%d", got)
	}
}

func TestPeerNetworkGenerationClearsSTUNObservation(t *testing.T) {
	var fingerprint networkadaptation.Fingerprint
	fingerprint[0] = 1
	peer := &PeerTerminalTunnel{networkChecks: make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation)}
	peer.recordNetworkCheck(fingerprint, networkcheck.STUNObservation{IPv4: "endpoint_independent", IPv6: "destination_dependent", CaptivePortal: "clear", PMTU: "standard", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"})
	if got := peer.networkCheck(fingerprint); got.IPv4 != "endpoint_independent" || got.IPv6 != "destination_dependent" || got.CaptivePortal != "clear" || got.PMTU != "standard" {
		t.Fatalf("observation=%#v", got)
	}
	peer.advanceNetwork()
	if got := peer.networkCheck(fingerprint); got.IPv4 != "unknown" || got.IPv6 != "unknown" || got.CaptivePortal != "unknown" || got.PMTU != "unknown" {
		t.Fatalf("stale observation=%#v", got)
	}
}

func TestObservedSocketMappingPublishesOnlyBoundedResult(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "verified", want: "verified"},
		{name: "untrusted", err: errors.Join(portmapping.ErrUntrusted, errors.New("gateway 192.0.2.1")), want: "untrusted"},
		{name: "unreachable", err: errors.Join(portmapping.ErrUnreachable, errors.New("stun://secret.example")), want: "unreachable"},
		{name: "unavailable", err: errors.Join(portmapping.ErrUnavailable, errors.New("router response")), want: "unavailable"},
		{name: "unexpected", err: errors.New("external endpoint 198.51.100.10:40000"), want: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var recorded string
			source := observedSocketMapping{source: mappingObservationSource{err: test.err}, record: func(_ string, value string) { recorded = value }}
			_, _, err := source.AcquireSocketMapping(context.Background(), 1, 1234, &net.UDPConn{}, []string{"stun:example.test:3478"})
			if !errors.Is(err, test.err) || recorded != test.want {
				t.Fatalf("err=%v recorded=%q", err, recorded)
			}
		})
	}
}

func TestNetworkObservationPreservesVerifiedRouterEvidence(t *testing.T) {
	var fingerprint networkadaptation.Fingerprint
	fingerprint[0] = 1
	peer := &PeerTerminalTunnel{networkChecks: make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation)}
	peer.recordRouterMapping(fingerprint, "nat_pmp", "verified")
	peer.recordMappingLifetime(fingerprint, "2m_to_10m")
	peer.recordNetworkCheck(fingerprint, networkcheck.STUNObservation{IPv4: "endpoint_independent", IPv6: "unknown", CaptivePortal: "clear", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"})
	got := peer.networkCheck(fingerprint)
	if got.RouterProtocol != "nat_pmp" || got.RouterMapping != "verified" || got.MappingLifetime != "2m_to_10m" {
		t.Fatalf("observation=%#v", got)
	}
	peer.advanceNetwork()
	got = peer.networkCheck(fingerprint)
	if got.RouterProtocol != "unknown" || got.RouterMapping != "unknown" || got.MappingLifetime != "unknown" {
		t.Fatalf("stale observation=%#v", got)
	}
}

func TestPeerPublishesOnlyAuthenticatedPMTUCategory(t *testing.T) {
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	var fingerprint networkadaptation.Fingerprint
	fingerprint[0] = 1
	policy := networkadaptation.DevelopmentPMTUPolicy()
	cache, err := networkadaptation.NewPMTUCache(policy)
	if err != nil {
		t.Fatal(err)
	}
	key := networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: "private-path-id", NetworkGeneration: 1}
	if err := cache.Record(key, networkadaptation.PMTUMeasurement{Complete: true, Eligible: true, PacketSize: 1372, Attempts: 3, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	peer := &PeerTerminalTunnel{config: PeerTerminalConfig{Now: func() time.Time { return now }}, pmtu: cache, networkChecks: make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation)}
	peer.recordPMTU(fingerprint, key)
	if got := peer.networkCheck(fingerprint); got.PMTU != "standard" || got.IPv4 != "unknown" || got.IPv6 != "unknown" || got.CaptivePortal != "unknown" {
		t.Fatalf("observation=%#v", got)
	}
}

func TestNetworkCheckEndpointRequiresProductionHTTPS(t *testing.T) {
	if got := networkCheckEndpoint("http://127.0.0.1:8080"); got != "" {
		t.Fatalf("HTTP endpoint=%q", got)
	}
	if got := networkCheckEndpoint("https://api.example.test"); got != "https://api.example.test/network-check/v1" {
		t.Fatalf("endpoint=%q", got)
	}
}

func TestPeerAPIRetryClassificationFailsClosed(t *testing.T) {
	t.Parallel()
	if !retryablePeerAPIError(&api.APIError{Status: 503, Code: "temporarily_unavailable"}) || !retryablePeerAPIError(&api.APIError{Status: 429, Code: "rate_limited"}) {
		t.Fatal("temporary API failures were not retryable")
	}
	for _, err := range []error{
		&api.APIError{Status: 401, Code: "authentication_required"},
		&api.APIError{Status: 403, Code: "certificate_revoked"},
		&api.APIError{Status: 409, Code: "generation_conflict"},
	} {
		if retryablePeerAPIError(err) {
			t.Fatalf("security or generation failure became retryable: %v", err)
		}
	}
}

func TestTerminalHealthRecorderFencesDescriptorAndNetworkGenerations(t *testing.T) {
	var fingerprint networkadaptation.Fingerprint
	fingerprint[0] = 1
	recorder, err := newTerminalHealthRecorder(fingerprint, "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := directpath.AttemptDescriptor{NetworkGeneration: 4}
	descriptor.Document.HostGeneration = 7
	descriptor.Document.AuthorizationGeneration = 9
	if err := recorder.observe(2, 1, descriptor); err != nil {
		t.Fatal(err)
	}
	sample := connectionmanager.ActiveHealthSample{Binding: connectionmanager.ActiveHealthBinding{Path: connectionmanager.PathRelayQUIC, Generation: 2, NetworkGeneration: 1}, Sequence: 1, At: time.Now().UTC(), Completed: time.Millisecond, Succeeded: true}
	if err := recorder.RecordActiveHealth(sample); err != nil {
		t.Fatal(err)
	}
	stale := sample
	stale.Binding.NetworkGeneration = 2
	if err := recorder.RecordActiveHealth(stale); err == nil {
		t.Fatal("recorded health for an unpublished network generation")
	}
	recorder.applyNetworkEvent(networkmonitor.Event{Generation: 2, Rebind: true})
	if err := recorder.RecordActiveHealth(sample); err == nil {
		t.Fatal("recorded relay quality after fingerprint invalidation")
	}
	wss := sample
	wss.Binding.Path = connectionmanager.PathWSS
	if err := recorder.RecordActiveHealth(wss); err != nil {
		t.Fatalf("WSS health should remain active without quality evidence: %v", err)
	}
}

func TestTerminalHealthRecorderAcceptsPromotedPoolGeneration(t *testing.T) {
	var fingerprint networkadaptation.Fingerprint
	fingerprint[0] = 1
	recorder, err := newTerminalHealthRecorder(fingerprint, "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := directpath.AttemptDescriptor{NetworkGeneration: 4}
	descriptor.Document.HostGeneration = 7
	descriptor.Document.AuthorizationGeneration = 9
	attempt := connectionmanager.ProbeAttempt{Generation: 31, NetworkGeneration: 4, Path: connectionmanager.PathDirectQUIC}
	if err := recorder.observeProbe(attempt, descriptor); err != nil {
		t.Fatal(err)
	}
	sample := connectionmanager.ActiveHealthSample{Binding: connectionmanager.ActiveHealthBinding{Path: connectionmanager.PathDirectQUIC, Generation: 2, NetworkGeneration: 4}, Sequence: 1, At: time.Now().UTC(), Completed: time.Millisecond, Succeeded: true}
	if err := recorder.RecordActiveHealth(sample); err != nil {
		t.Fatalf("promoted pool generation rejected: %v", err)
	}
}

type candidateHealth struct {
	closed atomic.Bool
	probes atomic.Uint64
}

func (h *candidateHealth) State() connectionmanager.State {
	if h.closed.Load() {
		return connectionmanager.StateFailed
	}
	return connectionmanager.StateTrusted
}

func (h *candidateHealth) Close() error { h.closed.Store(true); return nil }
func (h *candidateHealth) ActiveHealthCapability() (connectionmanager.ActiveHealthCapability, error) {
	return connectionmanager.ActiveHealthCapability{Path: connectionmanager.PathDirectQUIC, Transport: h}, nil
}
func (h *candidateHealth) HealthExchange(context.Context, [16]byte) (uint32, error) {
	h.probes.Add(1)
	return 0, nil
}

type candidateTerminal struct{}

func (candidateTerminal) Read([]byte) (int, error)        { return 0, nil }
func (candidateTerminal) Write(value []byte) (int, error) { return len(value), nil }
func (candidateTerminal) Close() error                    { return nil }
func (candidateTerminal) Resize(uint16, uint16) error     { return nil }
func (candidateTerminal) Wait() (int, error)              { return 0, nil }

type replacementTestConnector struct {
	direct         connectionmanager.Connection
	relay          connectionmanager.Connection
	allowRelay     <-chan struct{}
	relayConnected chan<- struct{}
}

func (c replacementTestConnector) Connect(_ context.Context, attempt connectionmanager.Attempt) (connectionmanager.Connection, error) {
	switch attempt.Path {
	case connectionmanager.PathDirectQUIC:
		return c.direct, nil
	case connectionmanager.PathRelayQUIC:
		<-c.allowRelay
		close(c.relayConnected)
		return c.relay, nil
	default:
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureReachability, Path: attempt.Path, Cause: errors.New("test path unavailable")}
	}
}

func TestSharedReplacementLeaseKeepsPromotedStandbyOwned(t *testing.T) {
	directHealth, relayHealth := &candidateHealth{}, &candidateHealth{}
	direct, err := newTerminalPathCandidate(directHealth, func(context.Context, terminalAttachment) (Conn, error) { return candidateTerminal{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newRelayTerminalPathCandidate("test", relayHealth, func(context.Context, terminalAttachment) (Conn, error) { return candidateTerminal{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	allowRelay := make(chan struct{})
	relayConnected := make(chan struct{})
	racer, err := connectionmanager.NewRacer(connectionmanager.Config{RelayDelay: 20 * time.Millisecond, WSSDelay: 20 * time.Millisecond, ConnectTimeout: time.Second}, replacementTestConnector{direct: direct, relay: relay, allowRelay: allowRelay, relayConnected: relayConnected})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := connectionmanager.NewPool(racer, connectionmanager.PoolConfig{IdleGrace: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := transportmanager.New()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	const key = "machine:1:interactive:auto"
	selected, err := manager.AcquireOwned(context.Background(), key, peerquic.ClassInteractive, connectionmanager.ModeAuto, connectionmanager.NetworkUnknown, func(context.Context) (*connectionmanager.Pool, func() error, error) {
		return pool, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Connection() != direct || selected.Path() != connectionmanager.PathDirectQUIC {
		t.Fatalf("selected path=%v connection=%p", selected.Path(), selected.Connection())
	}
	for {
		select {
		case <-pool.Changes():
		default:
			goto changesDrained
		}
	}
changesDrained:
	close(allowRelay)
	select {
	case <-relayConnected:
	case <-time.After(time.Second):
		t.Fatal("relay attempt did not complete")
	}
	for {
		select {
		case <-pool.Changes():
			goto standbyAdopted
		case <-time.After(time.Second):
			t.Fatal("relay standby was not adopted")
		}
	}
standbyAdopted:
	if !pool.Retire(peerquic.ClassInteractive, direct) {
		t.Fatal("selected direct carrier was not retired")
	}
	replacement, err := acquirePeerReplacementLease(context.Background(), true, manager, key, pool, connectionmanager.ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.connection != relay || replacement.path != connectionmanager.PathRelayQUIC {
		t.Fatalf("replacement path=%v connection=%p", replacement.path, replacement.connection)
	}
	selected.Release()
	if snapshots := manager.Snapshots(); len(snapshots) != 1 || snapshots[0].Leases != 1 {
		t.Fatalf("replacement lost manager ownership: %+v", snapshots)
	}
	if relayHealth.closed.Load() {
		t.Fatal("promoted relay closed when old manager lease released")
	}
	replacement.lease.Release()
	if !relayHealth.closed.Load() {
		t.Fatal("promoted relay remained after final replacement release")
	}
}

func TestTerminalPathCandidateAllowsMultipleStreamAttachments(t *testing.T) {
	health := &candidateHealth{}
	var attachments atomic.Uint64
	var operations []string
	var operationMu sync.Mutex
	candidate, err := newTerminalPathCandidate(health, func(_ context.Context, attachment terminalAttachment) (Conn, error) {
		attachments.Add(1)
		operationMu.Lock()
		operations = append(operations, attachment.application.operationID)
		operationMu.Unlock()
		return candidateTerminal{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.HealthExchange(context.Background(), [16]byte{1}); err != nil {
		t.Fatal(err)
	}
	if attachments.Load() != 0 || health.probes.Load() != 1 {
		t.Fatalf("attachments=%d probes=%d", attachments.Load(), health.probes.Load())
	}
	if _, err := candidate.Attach(context.Background(), terminalAttachment{application: peerApplication{operationID: "operation_1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Attach(context.Background(), terminalAttachment{application: peerApplication{operationID: "operation_2"}}); err != nil {
		t.Fatal("candidate rejected a second consumer attachment", err)
	}
	if attachments.Load() != 2 {
		t.Fatalf("attachments=%d", attachments.Load())
	}
	if !reflect.DeepEqual(operations, []string{"operation_1", "operation_2"}) {
		t.Fatalf("operations=%v", operations)
	}
	if err := candidate.Close(); err != nil || candidate.State() != connectionmanager.StateFailed {
		t.Fatalf("close=%v state=%d", err, candidate.State())
	}
}

func TestCachedApplicationAttachmentDoesNotInvalidateTrustedCarrier(t *testing.T) {
	applicationErr := errors.New("operation failed")
	if !cachedAttachmentPreservesCarrier(connectionmanager.StateTrusted, applicationErr) {
		t.Fatal("application attachment failure should preserve trusted carrier")
	}
	for _, err := range []error{ErrPeerCarrierExpired, ErrPeerStreamOpen, context.Canceled, context.DeadlineExceeded, io.EOF, net.ErrClosed, nil} {
		if cachedAttachmentPreservesCarrier(connectionmanager.StateTrusted, err) {
			t.Fatalf("carrier error %v was treated as application failure", err)
		}
	}
	if cachedAttachmentPreservesCarrier(connectionmanager.StateFailed, applicationErr) {
		t.Fatal("failed carrier was treated as reusable")
	}
}

type recordingPeerLease struct{ releases atomic.Uint64 }

func (l *recordingPeerLease) Release() { l.releases.Add(1) }

func TestFailedSharedApplicationReleasesOnlyItsLease(t *testing.T) {
	connection := &candidateHealth{}
	racer, err := connectionmanager.NewRacer(connectionmanager.Config{ConnectTimeout: time.Second}, replacementTestConnector{direct: connection})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := connectionmanager.NewPool(racer, connectionmanager.DevelopmentPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	lease := &recordingPeerLease{}
	closeFailedPeerApplication(true, lease, pool)
	if lease.releases.Load() != 1 {
		t.Fatalf("lease releases=%d", lease.releases.Load())
	}
	snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || snapshot.Closed {
		t.Fatalf("shared pool closed after one failed application: snapshot=%+v err=%v", snapshot, err)
	}
	_ = pool.Close()
}

func TestRetryablePeerAttachment(t *testing.T) {
	for _, err := range []error{ErrPeerStreamOpen, io.EOF, net.ErrClosed, &terminalTransportError{transport: "WSS", cause: io.EOF}} {
		if !retryablePeerAttachment(err) {
			t.Fatalf("attachment error %v was not retryable", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, context.DeadlineExceeded, errors.New("application rejected")} {
		if retryablePeerAttachment(err) {
			t.Fatalf("attachment error %v was retryable", err)
		}
	}
}

func TestTerminalPathCandidateRejectsAttachmentAtEstablishedAuthorityExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	var attachments atomic.Uint64
	candidate, err := newTerminalPathCandidate(&candidateHealth{}, func(context.Context, terminalAttachment) (Conn, error) {
		attachments.Add(1)
		return candidateTerminal{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate.expiresAt = now.Add(time.Minute)
	candidate.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := candidate.Attach(context.Background(), terminalAttachment{}); !errors.Is(err, ErrPeerCarrierExpired) {
		t.Fatalf("attachment error=%v", err)
	}
	if attachments.Load() != 0 {
		t.Fatalf("expired candidate attachments=%d", attachments.Load())
	}
}

func TestEstablishedPeerTransportCandidateAcceptsAfterSetupExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	var attachments atomic.Uint64
	candidate, err := newTerminalPathCandidate(&candidateHealth{}, func(context.Context, terminalAttachment) (Conn, error) {
		attachments.Add(1)
		return candidateTerminal{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A peer-transport setup deadline is intentionally not copied to the
	// established candidate. Only a separately declared hard lifetime belongs
	// in expiresAt.
	candidate.now = func() time.Time { return now.Add(time.Hour) }
	if _, err := candidate.Attach(context.Background(), terminalAttachment{}); err != nil {
		t.Fatalf("established candidate rejected after setup expiry: %v", err)
	}
	if attachments.Load() != 1 {
		t.Fatalf("attachments=%d", attachments.Load())
	}
}

func TestTerminalPathCandidateExposesRelayRegionOnlyWhenConfigured(t *testing.T) {
	health := &candidateHealth{}
	attach := func(context.Context, terminalAttachment) (Conn, error) { return candidateTerminal{}, nil }
	direct, err := newTerminalPathCandidate(health, attach)
	if err != nil {
		t.Fatal(err)
	}
	if direct.RelayRegion() != "" {
		t.Fatalf("direct relay region=%q", direct.RelayRegion())
	}
	relay, err := newRelayTerminalPathCandidate("bom", health, attach)
	if err != nil {
		t.Fatal(err)
	}
	if relay.RelayRegion() != "bom" {
		t.Fatalf("relay region=%q", relay.RelayRegion())
	}
}

func TestPeerApplicationAuthorizationHeaderBindsOperationAndCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	target := &resolver.TerminalTarget{Auth: resolver.AuthTarget{Token: "signed-credential", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}}
	header, err := (peerApplication{operationID: "operation_123", consumer: "exec"}).authorizationHeader(target, "exec", "fallback", "stream_1", now)
	if err != nil {
		t.Fatal(err)
	}
	if header.OperationID != "operation_123" || header.Consumer != "exec" || header.StreamID != "stream_1" || header.Credential != "signed-credential" || header.DeadlineUnix != now.Add(time.Minute).Unix() {
		t.Fatalf("header=%+v", header)
	}
	if _, err := (peerApplication{}).authorizationHeader(&resolver.TerminalTarget{}, "terminal", "fallback", "stream_1", now); err == nil {
		t.Fatal("missing credential accepted")
	}
}

func TestTargetTunnelRoutesMachineOnlyToPeerTransport(t *testing.T) {
	t.Parallel()
	machineErr := errors.New("machine")
	otherErr := errors.New("other")
	target := TargetTunnel{Machine: tunnelFunc(func(context.Context, resolver.ConnectInfo) (Conn, error) { return nil, machineErr }), Other: tunnelFunc(func(context.Context, resolver.ConnectInfo) (Conn, error) { return nil, otherErr })}
	if _, err := target.Dial(context.Background(), resolver.ConnectInfo{TargetKind: "machine"}); !errors.Is(err, machineErr) {
		t.Fatalf("machine route error=%v", err)
	}
	if _, err := target.Dial(context.Background(), resolver.ConnectInfo{TargetKind: "project"}); !errors.Is(err, otherErr) {
		t.Fatalf("other route error=%v", err)
	}
}

func TestPeerTerminalNetworkGenerationChangesOnlyForNewFingerprint(t *testing.T) {
	peer := &PeerTerminalTunnel{}
	first := networkadaptation.Fingerprint{1}
	second := networkadaptation.Fingerprint{2}
	if peer.observeNetworkFingerprint(first, true) {
		t.Fatal("initial fingerprint reported a network change")
	}
	if peer.observeNetworkFingerprint(first, true) {
		t.Fatal("unchanged fingerprint reported a network change")
	}
	if !peer.observeNetworkFingerprint(second, true) {
		t.Fatal("changed fingerprint did not report a network change")
	}
	if !peer.observeNetworkFingerprint(networkadaptation.Fingerprint{}, false) {
		t.Fatal("unidentifiable rebind did not fail safe")
	}
}

func TestPeerTerminalIPv6ViabilityIsNetworkScoped(t *testing.T) {
	fingerprint := networkadaptation.Fingerprint{1}
	peer := &PeerTerminalTunnel{
		networkChecks: make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation),
		ipv6Viable:    make(map[networkadaptation.Fingerprint]bool),
		ipv6Known:     make(map[networkadaptation.Fingerprint]bool),
		ipv6Active:    make(map[networkadaptation.Fingerprint]bool),
	}
	peer.network.Store(1)
	peer.recordIPv6Viability(fingerprint, true)
	if viable, known := peer.cachedIPv6Viability(fingerprint); !known || !viable {
		t.Fatalf("viable=%v known=%v", viable, known)
	}
	peer.advanceNetwork()
	if _, known := peer.cachedIPv6Viability(fingerprint); known {
		t.Fatal("network change retained stale IPv6 viability")
	}
}

type tunnelFunc func(context.Context, resolver.ConnectInfo) (Conn, error)

func (f tunnelFunc) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	return f(ctx, info)
}
