package filetransfer

import (
	"errors"
	"testing"
	"time"
)

func TestWriterRegistryRoutesToExactMachine(t *testing.T) {
	r := NewWriterRegistry()
	r.Attach("ses", "att_a", "cli_a", "machine_a")
	if got, err := r.Recipient("ses", "machine_a"); err != nil || got != "cli_a" {
		t.Fatalf("sole=%q err=%v", got, err)
	}
	r.Attach("ses", "att_b", "cli_b", "machine_b")
	if _, err := r.Recipient("ses", "machine_missing"); !errors.Is(err, ErrNoActiveWriter) {
		t.Fatalf("ambiguous err=%v", err)
	}
	now := time.Now()
	r.Input("ses", "att_a", "cli_a", now)
	r.Input("ses", "att_b", "cli_b", now.Add(time.Second))
	if got, err := r.Recipient("ses", "machine_b"); err != nil || got != "cli_b" {
		t.Fatalf("last=%q err=%v", got, err)
	}
	r.Detach("ses", "att_b")
	if got, err := r.Recipient("ses", "machine_a"); err != nil || got != "cli_a" {
		t.Fatalf("fallback=%q err=%v", got, err)
	}
	if got := r.EligibleMachines("ses"); len(got) != 1 || got[0] != "machine_a" {
		t.Fatalf("eligible=%v", got)
	}
}
