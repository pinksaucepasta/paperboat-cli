package directpath

import (
	"context"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

func TestDirectAssembliesWithoutSubstrateUseIsolatedPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	open := func(attempt uint64) *Assembly {
		key := make([]byte, 32)
		key[0] = byte(attempt)
		assembly, err := Open(ctx, Config{
			ICE:     iceagent.Config{LocalUfrag: map[uint64]string{1: "isolated-first", 2: "isolated-second"}[attempt], LocalPwd: "isolated-password-12345678901234567890"},
			Sockets: udpsocket.DevelopmentConfig(true, false), PMTUKey: key,
			MaximumPMTU: 1452, ApplicationQueue: 16, PMTUResponseLimit: time.Second,
			AttemptGeneration: attempt, NetworkGeneration: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return assembly
	}
	first := open(1)
	defer first.Close()
	second := open(2)
	defer second.Close()
	if first.Port() == 0 || second.Port() == 0 || first.Port() == second.Port() {
		t.Fatalf("direct attempts did not receive isolated UDP ports: %d and %d", first.Port(), second.Port())
	}
}

func TestSocketSubstrateSharesPortAcrossConcurrentICEAttempts(t *testing.T) {
	substrate, err := NewSocketSubstrate(SocketSubstrateConfig{
		Sockets: udpsocket.DevelopmentConfig(true, false), MaximumPMTU: 1452,
		ApplicationQueue: 16, PMTUResponseLimit: time.Second, MaximumAttempts: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer substrate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	key := make([]byte, 32)
	first, err := substrate.Acquire(ctx, 1, 1, nil, iceagent.Config{LocalUfrag: "first", LocalPwd: "first-password-12345678901234567890"}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := substrate.Acquire(ctx, 1, 2, nil, iceagent.Config{LocalUfrag: "second", LocalPwd: "second-password-12345678901234567890"}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Port() == 0 || first.Port() != second.Port() {
		t.Fatalf("attempts did not share socket port: %d and %d", first.Port(), second.Port())
	}
	if err := substrate.NetworkChanged(2); !err {
		t.Fatal("network change did not retire generation")
	}
}
