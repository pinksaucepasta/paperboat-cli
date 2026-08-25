package transfercrypto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

func TestKeyControlAcknowledgesOnlyAfterDurableSave(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	binding := KeyControlBinding{OperationID: "operation_01", TransferID: "transfer_01", Generation: 2, ExpiresAt: now.Add(time.Hour)}
	material := testMaterial()
	secrets := &memorySecrets{items: make(map[string]string)}
	vault, _ := NewKeyVault(secrets)
	vault.now = func() time.Time { return now }
	left, right := net.Pipe()
	received := make(chan error, 1)
	go func() {
		defer right.Close()
		received <- ReceiveKey(right, binding, keyPeerContext(binding.OperationID), vault)
	}()
	if err := DeliverKey(left, binding, material); err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	stored, err := vault.Load(binding.TransferID, binding.Generation)
	if err != nil || stored != material {
		t.Fatalf("stored material mismatch: err=%v", err)
	}
}

func TestKeyControlRejectsWrongBindingWithoutSavingOrAcknowledging(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	binding := KeyControlBinding{OperationID: "operation_01", TransferID: "transfer_01", Generation: 2, ExpiresAt: now.Add(time.Hour)}
	payload, err := marshalKeyControl(binding, testMaterial())
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := writeControlFrame(&wire, payload); err != nil {
		t.Fatal(err)
	}
	secrets := &memorySecrets{items: make(map[string]string)}
	vault, _ := NewKeyVault(secrets)
	vault.now = func() time.Time { return now }
	wrong := binding
	wrong.Generation++
	if err := ReceiveKey(&wire, wrong, keyPeerContext(wrong.OperationID), vault); !errors.Is(err, ErrControlRejected) {
		t.Fatalf("err=%v, want ErrControlRejected", err)
	}
	if wire.Len() != 0 || len(secrets.items) != 0 {
		t.Fatal("rejected key was saved or acknowledged")
	}
}

func TestKeyControlDoesNotAcknowledgeFailedPersistence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	binding := KeyControlBinding{OperationID: "operation_01", TransferID: "transfer_01", Generation: 2, ExpiresAt: now.Add(time.Hour)}
	payload, _ := marshalKeyControl(binding, testMaterial())
	var wire bytes.Buffer
	_ = writeControlFrame(&wire, payload)
	vault, _ := NewKeyVault(failingSecrets{})
	vault.now = func() time.Time { return now }
	if err := ReceiveKey(&wire, binding, keyPeerContext(binding.OperationID), vault); !errors.Is(err, ErrControlStore) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("persistence error = %v, want typed store and underlying errors", err)
	}
	if wire.Len() != 0 {
		t.Fatal("persistence failure produced acknowledgement")
	}
}

type failingSecrets struct{}

func (failingSecrets) Set(string, string) error   { return io.ErrClosedPipe }
func (failingSecrets) Get(string) (string, error) { return "", io.ErrClosedPipe }
func (failingSecrets) Delete(string) error        { return io.ErrClosedPipe }

func keyPeerContext(operationID string) peercontext.Context {
	context := peercontext.Context{AccountID: "account_01", UserID: "account_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_01", OperationID: operationID, Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	context.InitiatorCertificateHash[0] = 1
	context.ResponderCertificateHash[0] = 2
	return context
}
