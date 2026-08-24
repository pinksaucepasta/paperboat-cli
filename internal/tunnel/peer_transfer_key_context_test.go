package tunnel

import (
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type transferKeyContextSecrets struct {
	mu    sync.Mutex
	items map[string]string
}

func (s *transferKeyContextSecrets) Set(ref, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[ref] = value
	return nil
}

func (s *transferKeyContextSecrets) Get(ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.items[ref]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}

func (s *transferKeyContextSecrets) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, ref)
	return nil
}

type failedTransferKeyExchange struct{}

func (failedTransferKeyExchange) Read([]byte) (int, error)  { return 0, io.ErrClosedPipe }
func (failedTransferKeyExchange) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestPeerTransferKeyDeliveryReportsSelectedExchangeContext(t *testing.T) {
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	material, err := transfercrypto.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()

	selected := transferKeyPeerContext("intent_selected", "operation_selected", 2)
	unselected := transferKeyPeerContext("intent_unselected", "operation_unselected", 3)
	delivery := &peerTransferKeyDelivery{
		binding: transfercrypto.KeyControlBinding{
			OperationID: "ft_key_original",
			TransferID:  "transfer_01",
			Generation:  1,
			ExpiresAt:   expires,
		},
		material: material,
		context:  unselected,
	}

	vault, err := transfercrypto.NewKeyVault(&transferKeyContextSecrets{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	received := make(chan error, 1)
	go func() {
		defer right.Close()
		binding := delivery.binding
		binding.OperationID = selected.OperationID
		received <- transfercrypto.ReceiveKey(right, binding, selected, vault)
	}()

	if err := delivery.exchange(left, selected); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	exchanged, err := delivery.exchangedContext()
	if err != nil {
		t.Fatal(err)
	}
	if exchanged != selected {
		t.Fatalf("reported peer context belongs to an unselected descriptor: got operation=%q want operation=%q", exchanged.OperationID, selected.OperationID)
	}

	stored, storedContext, err := vault.LoadBound(delivery.binding.TransferID, delivery.binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	stored.Destroy()
	if storedContext != selected {
		t.Fatal("receiver did not bind the key to the selected exchange context")
	}

	failed := transferKeyPeerContext("intent_failed", "operation_failed", 4)
	if err := delivery.exchange(failedTransferKeyExchange{}, failed); err == nil {
		t.Fatal("failed key exchange unexpectedly succeeded")
	}
	exchanged, err = delivery.exchangedContext()
	if err != nil {
		t.Fatal(err)
	}
	if exchanged != selected {
		t.Fatalf("failed exchange replaced selected context: got operation=%q want operation=%q", exchanged.OperationID, selected.OperationID)
	}
}

func transferKeyPeerContext(intentID, operationID string, attempt uint64) peercontext.Context {
	return peercontext.Context{
		AccountID:                "account_01",
		UserID:                   "account_01",
		DeviceID:                 "cli_01",
		MachineID:                "machine_01",
		InitiatorCertificateHash: sha256.Sum256([]byte("initiator")),
		ResponderCertificateHash: sha256.Sum256([]byte("responder")),
		HostGeneration:           1,
		AuthorizationGeneration:  1,
		IntentID:                 intentID,
		OperationID:              operationID,
		Consumer:                 "file_transfer_key",
		InitiatorRole:            "controlling",
		ResponderRole:            "controlled",
		AttemptGeneration:        attempt,
	}
}
