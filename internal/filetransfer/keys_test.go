package filetransfer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type keyMemoryStore struct{ values map[string]string }

func (s *keyMemoryStore) Set(key, value string) error { s.values[key] = value; return nil }
func (s *keyMemoryStore) Get(key string) (string, error) {
	value, ok := s.values[key]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}
func (s *keyMemoryStore) Delete(key string) error { delete(s.values, key); return nil }

type keyDelivererFunc func(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, error)

func (f keyDelivererFunc) DeliverTransferKey(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, error) {
	return f(ctx, target, binding, material)
}

type directKeyDeliverer struct {
	keyDelivererFunc
	transport *closingRoundTripper
}

type directKeyReceiver struct {
	keyDelivererFunc
	material  transfercrypto.KeyMaterial
	transport *closingRoundTripper
	calls     int
}

func (r *directKeyReceiver) ReceiveTransferKey(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, vault *transfercrypto.KeyVault) (peercontext.Context, error) {
	peer, _, err := r.PrepareReceiveTransferKey(ctx, target, binding, vault)
	return peer, err
}

func (r *directKeyReceiver) PrepareReceiveTransferKey(_ context.Context, _ resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, vault *transfercrypto.KeyVault) (peercontext.Context, http.RoundTripper, error) {
	r.calls++
	peer := keyContext(binding.OperationID)
	if err := vault.SaveBound(binding.TransferID, binding.Generation, r.material, binding.ExpiresAt, peer); err != nil {
		return peercontext.Context{}, nil, err
	}
	return peer, r.transport, nil
}

func (d directKeyDeliverer) PrepareTransferKey(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error) {
	peer, err := d.keyDelivererFunc(ctx, target, binding, material)
	return peer, d.transport, err
}

func TestKeyCoordinatorPersistsBeforeDeliveryAndReusesForRetry(t *testing.T) {
	store := &keyMemoryStore{values: make(map[string]string)}
	vault, _ := transfercrypto.NewKeyVault(store)
	now := time.Now().UTC().Truncate(time.Second)
	binding := transfercrypto.KeyControlBinding{OperationID: "operation_01", TransferID: "transfer_01", Generation: 1, ExpiresAt: now.Add(time.Hour)}
	firstErr := errors.New("acknowledgement lost")
	var delivered []transfercrypto.KeyMaterial
	deliverer := keyDelivererFunc(func(_ context.Context, _ resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, error) {
		if len(store.values) == 0 {
			t.Fatal("key was delivered before durable local save")
		}
		delivered = append(delivered, material)
		if len(delivered) == 1 {
			return peercontext.Context{}, firstErr
		}
		return keyContext(binding.OperationID), nil
	})
	coordinator, _ := NewKeyCoordinator(vault, deliverer)
	if _, err := coordinator.Prepare(context.Background(), resolver.ConnectInfo{}, binding); !errors.Is(err, firstErr) {
		t.Fatalf("first err=%v", err)
	}
	prepared, err := coordinator.Prepare(context.Background(), resolver.ConnectInfo{}, binding)
	if err != nil || len(delivered) != 2 || delivered[0] != delivered[1] || prepared.Material != delivered[1] || prepared.Context.OperationID != binding.OperationID {
		t.Fatalf("retry did not reuse key: err=%v deliveries=%d", err, len(delivered))
	}
	if err := coordinator.Erase(binding.TransferID); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Load(binding.TransferID, binding.Generation); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		t.Fatalf("erased key err=%v", err)
	}
}

func TestKeyCoordinatorRetainsSelectedDirectTransport(t *testing.T) {
	store := &keyMemoryStore{values: make(map[string]string)}
	vault, _ := transfercrypto.NewKeyVault(store)
	binding := transfercrypto.KeyControlBinding{OperationID: KeyOperationID("transfer_01"), TransferID: "transfer_01", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
	transport := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, nil }}
	deliverer := directKeyDeliverer{keyDelivererFunc: func(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, error) {
		return keyContext(binding.OperationID), nil
	}, transport: transport}
	coordinator, err := NewKeyCoordinator(vault, deliverer)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := coordinator.Prepare(context.Background(), resolver.ConnectInfo{}, binding)
	if err != nil || prepared.Direct != transport {
		t.Fatalf("direct=%T error=%v", prepared.Direct, err)
	}
	prepared.Material.Destroy()
	if err := prepared.Close(); err != nil || !transport.closed.Load() {
		t.Fatalf("close error=%v closed=%v", err, transport.closed.Load())
	}
}

func TestKeyCoordinatorReceivesOnceAndRetainsSelectedDirectTransport(t *testing.T) {
	store := &keyMemoryStore{values: make(map[string]string)}
	vault, _ := transfercrypto.NewKeyVault(store)
	binding := transfercrypto.KeyControlBinding{OperationID: KeyOperationID("transfer_02"), TransferID: "transfer_02", Generation: 2, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Hour)}
	material, _ := transfercrypto.GenerateKeyMaterial()
	transport := &closingRoundTripper{trip: func(*http.Request) (*http.Response, error) { return nil, nil }}
	receiver := &directKeyReceiver{keyDelivererFunc: func(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, error) {
		return peercontext.Context{}, errors.New("unexpected delivery")
	}, material: material, transport: transport}
	coordinator, err := NewKeyCoordinator(vault, receiver)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := coordinator.Receive(context.Background(), resolver.ConnectInfo{}, binding)
	if err != nil || prepared.Material != material || prepared.Context != keyContext(binding.OperationID) || prepared.Direct != transport || receiver.calls != 1 {
		t.Fatalf("received=%v direct=%T calls=%d err=%v", prepared.Material.Valid(), prepared.Direct, receiver.calls, err)
	}
	prepared.Material.Destroy()
	if err := prepared.Close(); err != nil || !transport.closed.Load() {
		t.Fatalf("close error=%v closed=%v", err, transport.closed.Load())
	}
	reused, err := coordinator.Receive(context.Background(), resolver.ConnectInfo{}, binding)
	if err != nil || reused.Material != material || reused.Direct != nil || receiver.calls != 1 {
		t.Fatalf("reuse direct=%T calls=%d err=%v", reused.Direct, receiver.calls, err)
	}
	reused.Material.Destroy()
	material.Destroy()
}

func keyContext(operationID string) peercontext.Context {
	context := peercontext.Context{AccountID: "account_01", UserID: "account_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_01", OperationID: operationID, Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	context.InitiatorCertificateHash[0] = 1
	context.ResponderCertificateHash[0] = 2
	return context
}
