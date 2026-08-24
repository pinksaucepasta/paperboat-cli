//go:build darwin || linux || windows

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

func TestPeerTransferErrorClassIsTypedAndSanitized(t *testing.T) {
	tests := []struct {
		err   error
		class string
		ok    bool
	}{
		{fmt.Errorf("outer: %w", transfercrypto.ErrControlContext), "transfer_key_context_rejected", true},
		{fmt.Errorf("outer: %w", transfercrypto.ErrControlRead), "transfer_key_read_failed", true},
		{fmt.Errorf("outer: %w", transfercrypto.ErrControlRejected), "transfer_key_binding_rejected", true},
		{fmt.Errorf("%w: %w", transfercrypto.ErrControlStore, clientconfig.ErrCredentialStoreUnavailable), "transfer_key_store_credential_unavailable", true},
		{fmt.Errorf("%w: %w", transfercrypto.ErrControlStore, transfercrypto.ErrInvalid), "transfer_key_store_invalid", true},
		{fmt.Errorf("outer: %w", transfercrypto.ErrControlAck), "transfer_key_ack_failed", true},
		{errors.New("unrelated"), "", false},
	}
	for _, test := range tests {
		class, ok := peerTransferErrorClass(test.err)
		if class != test.class || ok != test.ok {
			t.Fatalf("peerTransferErrorClass(%v) = (%q, %t), want (%q, %t)", test.err, class, ok, test.class, test.ok)
		}
	}
}

func TestPeerLastErrorRecorderCoalescesToGuaranteedLatestRecord(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	writes := make(chan string, 3)
	call := 0
	recorder := newPeerLastErrorRecorder(func(_ string, body []byte) error {
		call++
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		writes <- string(body)
		return nil
	})

	recorder.record(peerLastErrorWrite{root: "root", body: []byte("first")})
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first diagnostic write did not start")
	}
	for index := 0; index < 32; index++ {
		recorder.record(peerLastErrorWrite{root: "root", body: []byte(fmt.Sprintf("latest-%02d", index))})
	}
	close(releaseFirst)
	select {
	case got := <-writes:
		if got != "first" {
			t.Fatalf("first write = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first diagnostic write did not finish")
	}
	select {
	case got := <-writes:
		if got != "latest-31" {
			t.Fatalf("coalesced write = %q, want latest-31", got)
		}
	case <-time.After(time.Second):
		t.Fatal("latest diagnostic record was dropped")
	}
	close(recorder.wake)
}

func TestPeerOutcomeRecordContainsOnlySanitizedFields(t *testing.T) {
	body, err := json.Marshal(peerLastErrorRecord{Schema: peerLastErrorSchema, At: time.Unix(1, 0).UTC(), Class: "transfer_key_ack_written"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("diagnostic fields = %#v, want schema, at, and class only", fields)
	}
	for _, name := range []string{"schema", "at", "class"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("diagnostic fields = %#v, missing %q", fields, name)
		}
	}
}
