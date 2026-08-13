package peercontext

import (
	"crypto/sha256"
	"testing"
)

func validTransport() Transport {
	return Transport{AccountID: "account_1", UserID: "user_1", DeviceID: "cli_1", MachineID: "machine_1", InitiatorCertificateHash: sha256.Sum256([]byte("initiator")), ResponderCertificateHash: sha256.Sum256([]byte("responder")), HostGeneration: 2, AuthorizationGeneration: 3, TransportID: "transport_1", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 4}
}

func TestTransportContextExcludesOperationAuthority(t *testing.T) {
	value := validTransport()
	encoded, err := value.MarshalBinary()
	if err != nil || len(encoded) == 0 {
		t.Fatalf("marshal=%x err=%v", encoded, err)
	}
	first, _ := value.Hash()
	value.AuthorizationGeneration++
	second, _ := value.Hash()
	if first == second {
		t.Fatal("authorization generation did not change transport binding")
	}
}

func TestStreamContextBindsOperationConsumerCredentialAndLimits(t *testing.T) {
	transportHash, _ := validTransport().Hash()
	base := Stream{TransportHash: transportHash, OperationID: "operation_1", Consumer: "exec", StreamID: "native-control", CredentialHash: sha256.Sum256([]byte("credential")), DeadlineUnix: 1_800_000_000, MaximumBytes: 1024}
	want, err := base.Hash()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Stream){
		func(v *Stream) { v.OperationID = "operation_2" },
		func(v *Stream) { v.Consumer = "ssh" },
		func(v *Stream) { v.StreamID = "native-input" },
		func(v *Stream) { v.CredentialHash = sha256.Sum256([]byte("other")) },
		func(v *Stream) { v.DeadlineUnix++ },
		func(v *Stream) { v.MaximumBytes++ },
	}
	for index, mutate := range mutations {
		value := base
		mutate(&value)
		got, hashErr := value.Hash()
		if hashErr != nil || got == want {
			t.Fatalf("mutation %d hash=%x err=%v", index, got, hashErr)
		}
	}
}

func TestTransportAndStreamContextsRejectMissingBindings(t *testing.T) {
	transport := validTransport()
	transport.AuthorizationGeneration = 0
	if _, err := transport.MarshalBinary(); err == nil {
		t.Fatal("transport accepted missing authorization generation")
	}
	stream := Stream{OperationID: "operation_1", Consumer: "exec", StreamID: "native-control", DeadlineUnix: 1, MaximumBytes: 1}
	if _, err := stream.MarshalBinary(); err == nil {
		t.Fatal("stream accepted missing transport and credential hashes")
	}
}
