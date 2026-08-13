package localdaemon

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type transferPreparerFake struct {
	direct   *transferDirectFake
	lifetime chan context.Context
}

func (f transferPreparerFake) PrepareTransferKey(lifetime context.Context, _ resolver.ConnectInfo, _ transfercrypto.KeyControlBinding, _ transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error) {
	if f.lifetime != nil {
		f.lifetime <- lifetime
	}
	return validTransferPeerContext(), f.direct, nil
}

type transferDirectFake struct{ closed bool }

func (*transferDirectFake) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, net.ErrClosed
}
func (f *transferDirectFake) Close() error { f.closed = true; return nil }
func (*transferDirectFake) OpenTransferStream(context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestFileTransferBrokerBindsHandleToUnixPeer(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	direct := &transferDirectFake{}
	lifetimes := make(chan context.Context, 1)
	broker, err := NewFileTransferBroker(transferPreparerFake{direct: direct, lifetime: lifetimes})
	if err != nil {
		t.Fatal(err)
	}
	broker.now = func() time.Time { return now }
	material, err := transfercrypto.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	encoded, err := material.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	request := localapi.FileTransferKeyRequest{Schema: localapi.FileTransferKeySchemaV1, MachineID: "machine_1", EnvironmentID: "environment_1", MachineGeneration: 1, Transport: "d", OperationID: "operation_1", TransferID: "transfer_1", Generation: 1, ExpiresAt: now.Add(time.Hour), Material: encoded}
	owner := localapi.Peer{UID: 1000, GID: 1000, PID: 41}
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	result, err := broker.PrepareFileTransfer(setupCtx, owner, request)
	if err != nil || result.Handle == "" || len(result.PeerContext) == 0 {
		t.Fatalf("prepare result=%+v err=%v", result, err)
	}
	lifetime := <-lifetimes
	cancelSetup()
	select {
	case <-lifetime.Done():
		t.Fatal("request completion canceled retained transfer lease")
	default:
	}
	if _, err := broker.OpenFileTransferStream(context.Background(), localapi.Peer{UID: 1000, GID: 1000, PID: 42}, result.Handle); err == nil {
		t.Fatal("different PID opened transfer handle")
	}
	stream, err := broker.OpenFileTransferStream(context.Background(), owner, result.Handle)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if err := broker.ReleaseFileTransfer(owner, result.Handle); err != nil || !direct.closed {
		t.Fatalf("release err=%v closed=%t", err, direct.closed)
	}
	select {
	case <-lifetime.Done():
	default:
		t.Fatal("release did not cancel retained transfer lifetime")
	}
}

func validTransferPeerContext() peercontext.Context {
	value := peercontext.Context{AccountID: "account_1", UserID: "user_1", DeviceID: "device_1", MachineID: "machine_1", HostGeneration: 1, AuthorizationGeneration: 1, IntentID: "intent_1", OperationID: "operation_1", Consumer: "file_transfer_key", InitiatorRole: "initiating", ResponderRole: "controlled", AttemptGeneration: 1}
	value.InitiatorCertificateHash[0] = 1
	value.ResponderCertificateHash[0] = 2
	return value
}
