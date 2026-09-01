package preview

import (
	"context"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

func TestMachinePreviewRuntimeOwnsSharedCarrierReferences(t *testing.T) {
	stateRoot, _ := newMachineAttachmentIdentity(t)
	runtime, err := NewMachinePreviewRuntime(MachinePreviewRuntimeConfig{
		ControlURL: "https://api.example.test", StateRoot: stateRoot, RunContext: context.Background(),
		SessionFactory: func(connector.DataCarrierIdentity, connector.DataCarrierPoolConfig, connector.NetworkDialerConfig) (connector.DataCarrierSessionSource, error) {
			return connector.DataCarrierSessionSource{}, errors.New("not used")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := runtime.MachineAuthSource()
	if err != nil || auth == nil {
		t.Fatalf("machine auth source = %v, err=%v", auth, err)
	}
	first, err := runtime.NewCarrier(context.Background(), LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, "host_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.NewCarrier(context.Background(), LeaseTarget{Scheme: "http", Address: "127.0.0.1:3001"}, "host_01", "owner_session_02")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.MachineAuthSource(); err != nil {
		t.Fatalf("runtime closed while a sibling route remained: %v", err)
	}
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.MachineAuthSource(); err != nil {
		t.Fatalf("runtime closed with final route instead of assembly shutdown: %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.MachineAuthSource(); !errors.Is(err, ErrMachinePreviewRuntimeClosed) {
		t.Fatalf("runtime state after explicit shutdown = %v", err)
	}
}

func TestMachinePreviewRuntimeRejectsForeignMachineOrUnsafeTarget(t *testing.T) {
	stateRoot, _ := newMachineAttachmentIdentity(t)
	runtime, err := NewMachinePreviewRuntime(MachinePreviewRuntimeConfig{ControlURL: "https://api.example.test", StateRoot: stateRoot, RunContext: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())
	if _, err := runtime.NewCarrier(context.Background(), LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, "other_machine", "owner_session_01"); !errors.Is(err, ErrMachinePreviewRuntimeInvalid) {
		t.Fatalf("foreign machine error = %v", err)
	}
	if _, err := runtime.NewCarrier(context.Background(), LeaseTarget{Scheme: "ftp", Address: "127.0.0.1:3000"}, "host_01", "owner_session_01"); !errors.Is(err, ErrMachinePreviewRuntimeInvalid) {
		t.Fatalf("unsafe target error = %v", err)
	}
}
