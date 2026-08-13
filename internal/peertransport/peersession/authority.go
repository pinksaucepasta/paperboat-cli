package peersession

import (
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

var ErrInvalid = errors.New("peer session authority is invalid")

type Config struct {
	Descriptor        api.PeerAttemptDescriptor
	LocalCertificate  endpointidentity.Certificate
	PeerCertificate   endpointidentity.Certificate
	LocalNoisePrivate [32]byte
	Consumer          string
}

type Authority struct {
	Context           peercontext.Context
	Transport         peercontext.Transport
	LocalPrivate      [32]byte
	LocalPublic       [32]byte
	PeerPublic        [32]byte
	RouteHandle       [16]byte
	pmtuKey           [32]byte
	localRole         string
	initiatorEndpoint string
	responderEndpoint string
}

type StreamAuthority struct {
	Context      peercontext.Context
	Transport    peercontext.Transport
	Stream       peercontext.Stream
	LocalPrivate [32]byte
	LocalPublic  [32]byte
	PeerPublic   [32]byte
	Handle       [16]byte
}

func New(config Config) (Authority, error) {
	value := config.Descriptor
	if value.Version != 1 || value.AccountID == "" || value.DeviceID == "" || value.OperationID == "" || value.IntentID == "" || value.ResponderEndpointID == "" || value.AttemptGeneration == 0 || value.HostGeneration == 0 || value.AuthorizationGeneration == 0 || value.Consumer != config.Consumer || !validPurposeConsumer(value.Purpose, config.Consumer) || config.LocalCertificate.Claims.AccountID != value.AccountID || config.PeerCertificate.Claims.AccountID != value.AccountID {
		return Authority{}, ErrInvalid
	}
	localRole := value.Role
	if localRole != "controlling" && localRole != "controlled" {
		return Authority{}, ErrInvalid
	}
	localEndpoint := value.InitiatorEndpointID
	peerEndpoint := value.ResponderEndpointID
	if localRole == "controlled" {
		localEndpoint, peerEndpoint = peerEndpoint, localEndpoint
	}
	if config.LocalCertificate.Claims.EndpointID != localEndpoint || config.PeerCertificate.Claims.EndpointID != peerEndpoint || config.LocalCertificate.Claims.NoisePublicKey == ([32]byte{}) || config.PeerCertificate.Claims.NoisePublicKey == ([32]byte{}) {
		return Authority{}, ErrInvalid
	}
	private, err := ecdh.X25519().NewPrivateKey(config.LocalNoisePrivate[:])
	if err != nil || !equal32(private.PublicKey().Bytes(), config.LocalCertificate.Claims.NoisePublicKey[:]) {
		return Authority{}, ErrInvalid
	}
	localRaw, localErr := config.LocalCertificate.MarshalBinary()
	peerRaw, peerErr := config.PeerCertificate.MarshalBinary()
	if localErr != nil || peerErr != nil {
		return Authority{}, ErrInvalid
	}
	initiatorRaw, responderRaw := localRaw, peerRaw
	if localRole == "controlled" {
		initiatorRaw, responderRaw = peerRaw, localRaw
	}
	contextValue := peercontext.Context{AccountID: value.AccountID, UserID: value.AccountID, DeviceID: value.DeviceID, MachineID: value.ResponderEndpointID, InitiatorCertificateHash: sha256.Sum256(initiatorRaw), ResponderCertificateHash: sha256.Sum256(responderRaw), HostGeneration: value.HostGeneration, AuthorizationGeneration: value.AuthorizationGeneration, IntentID: value.IntentID, OperationID: value.OperationID, Consumer: config.Consumer, InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: value.AttemptGeneration}
	if _, err := contextValue.MarshalBinary(); err != nil {
		return Authority{}, errors.Join(ErrInvalid, err)
	}
	peerPublic, err := ecdh.X25519().NewPublicKey(config.PeerCertificate.Claims.NoisePublicKey[:])
	if err != nil {
		return Authority{}, ErrInvalid
	}
	shared, err := private.ECDH(peerPublic)
	if err != nil {
		return Authority{}, ErrInvalid
	}
	transport := peercontext.Transport{AccountID: contextValue.AccountID, UserID: contextValue.UserID, DeviceID: contextValue.DeviceID, MachineID: contextValue.MachineID, InitiatorCertificateHash: contextValue.InitiatorCertificateHash, ResponderCertificateHash: contextValue.ResponderCertificateHash, HostGeneration: contextValue.HostGeneration, AuthorizationGeneration: contextValue.AuthorizationGeneration, TransportID: value.IntentID, InitiatorRole: contextValue.InitiatorRole, ResponderRole: contextValue.ResponderRole, AttemptGeneration: contextValue.AttemptGeneration}
	contextHash, err := transport.Hash()
	if err != nil {
		clear(shared)
		return Authority{}, errors.Join(ErrInvalid, err)
	}
	pmtuInput := make([]byte, 0, len("paperboat-peer-pmtu-v1")+1+len(shared)+len(contextHash))
	pmtuInput = append(pmtuInput, "paperboat-peer-pmtu-v1"...)
	pmtuInput = append(pmtuInput, 0)
	pmtuInput = append(pmtuInput, shared...)
	pmtuInput = append(pmtuInput, contextHash[:]...)
	pmtuKey := sha256.Sum256(pmtuInput)
	clear(shared)
	clear(pmtuInput)
	return Authority{Context: contextValue, Transport: transport, LocalPrivate: config.LocalNoisePrivate, LocalPublic: config.LocalCertificate.Claims.NoisePublicKey, PeerPublic: config.PeerCertificate.Claims.NoisePublicKey, RouteHandle: deriveHandle("paperboat-peer-route-v1", value.IntentID), pmtuKey: pmtuKey, localRole: localRole, initiatorEndpoint: value.InitiatorEndpointID, responderEndpoint: value.ResponderEndpointID}, nil
}

type StreamGrant struct {
	OperationID  string
	Consumer     string
	StreamID     string
	Credential   []byte
	Deadline     time.Time
	MaximumBytes uint64
}

func (a Authority) InitiatorStream(grant StreamGrant) (StreamAuthority, error) {
	if a.localRole != "controlling" {
		return StreamAuthority{}, ErrInvalid
	}
	return a.bindStream(grant)
}

func (a Authority) ResponderStream(grant StreamGrant) (StreamAuthority, error) {
	if a.localRole != "controlled" {
		return StreamAuthority{}, ErrInvalid
	}
	return a.bindStream(grant)
}

// InitiatorTransportStream and ResponderTransportStream authorize the stable
// relay Noise channel used to carry a stream grant in its authenticated first
// handshake payload. The grant is not known to the responder before routing,
// so the outer handle is transport-scoped rather than operation-scoped.
func (a Authority) InitiatorTransportStream() (StreamAuthority, error) {
	if a.localRole != "controlling" {
		return StreamAuthority{}, ErrInvalid
	}
	return a.transportStream()
}

func (a Authority) ResponderTransportStream() (StreamAuthority, error) {
	if a.localRole != "controlled" {
		return StreamAuthority{}, ErrInvalid
	}
	return a.transportStream()
}

func (a Authority) transportStream() (StreamAuthority, error) {
	if a.Context.Consumer != "peer_transport" {
		return StreamAuthority{}, ErrInvalid
	}
	hash, err := a.Transport.Hash()
	if err != nil {
		return StreamAuthority{}, errors.Join(ErrInvalid, err)
	}
	return StreamAuthority{Transport: a.Transport, LocalPrivate: a.LocalPrivate, LocalPublic: a.LocalPublic, PeerPublic: a.PeerPublic, Handle: deriveHandle("paperboat-peer-transport-stream-v1", string(hash[:]))}, nil
}

func (a Authority) bindStream(grant StreamGrant) (StreamAuthority, error) {
	if a.Context.Consumer != "peer_transport" {
		return StreamAuthority{}, ErrInvalid
	}
	transportHash, err := a.Transport.Hash()
	if err != nil || len(grant.Credential) == 0 || grant.Deadline.IsZero() {
		return StreamAuthority{}, ErrInvalid
	}
	stream := peercontext.Stream{TransportHash: transportHash, OperationID: grant.OperationID, Consumer: grant.Consumer, StreamID: grant.StreamID, CredentialHash: sha256.Sum256(grant.Credential), DeadlineUnix: grant.Deadline.UTC().Unix(), MaximumBytes: grant.MaximumBytes}
	streamHash, err := stream.Hash()
	if err != nil {
		return StreamAuthority{}, errors.Join(ErrInvalid, err)
	}
	return StreamAuthority{Transport: a.Transport, Stream: stream, LocalPrivate: a.LocalPrivate, LocalPublic: a.LocalPublic, PeerPublic: a.PeerPublic, Handle: deriveHandle("paperboat-peer-authorized-stream-v1", string(streamHash[:]))}, nil
}

func (a Authority) Initiator(streamID string) (StreamAuthority, error) {
	if a.localRole != "controlling" {
		return StreamAuthority{}, ErrInvalid
	}
	handle, err := a.stream(streamID)
	if err != nil {
		return StreamAuthority{}, err
	}
	return StreamAuthority{Context: a.Context, Transport: a.Transport, LocalPrivate: a.LocalPrivate, LocalPublic: a.LocalPublic, PeerPublic: a.PeerPublic, Handle: handle}, nil
}

func (a Authority) Responder(streamID string) (StreamAuthority, error) {
	if a.localRole != "controlled" {
		return StreamAuthority{}, ErrInvalid
	}
	handle, err := a.stream(streamID)
	if err != nil {
		return StreamAuthority{}, err
	}
	return StreamAuthority{Context: a.Context, Transport: a.Transport, LocalPrivate: a.LocalPrivate, LocalPublic: a.LocalPublic, PeerPublic: a.PeerPublic, Handle: handle}, nil
}

func (a Authority) stream(streamID string) ([16]byte, error) {
	valid := streamID == "native-health"
	if a.Context.Consumer == "peer_transport" {
		valid = valid || streamID == "candidate-control"
	}
	if a.Context.Consumer == "health_probe" {
		valid = streamID == "native-health"
	} else if a.Context.Consumer == "private_preview" {
		valid = valid || streamID == "private-preview"
	} else if a.Context.Consumer == "file_transfer_key" {
		valid = valid || streamID == "transfer-key-control"
	} else if a.Context.Consumer == "codex" {
		valid = valid || streamID == "codex-http"
	} else if a.Context.Consumer == "ssh" {
		valid = valid || streamID == "ssh"
	} else {
		valid = valid || streamID == "native-control" || streamID == "native-input" || streamID == "native-output"
	}
	if !valid {
		return [16]byte{}, ErrInvalid
	}
	return deriveHandle("paperboat-peer-stream-v1", a.Context.IntentID+"\x00"+streamID), nil
}

func validPurposeConsumer(purpose, consumer string) bool {
	if purpose == "peer_transport" || consumer == "peer_transport" {
		return purpose == "peer_transport" && consumer == "peer_transport"
	}
	if purpose == "health_probe" || consumer == "health_probe" {
		return purpose == "health_probe" && consumer == "health_probe"
	}
	if purpose == "private_preview" || consumer == "private_preview" {
		return purpose == "private_preview" && consumer == "private_preview"
	}
	if purpose == "file_transfer_key" || consumer == "file_transfer_key" {
		return purpose == "file_transfer_key" && consumer == "file_transfer_key"
	}
	if purpose == "codex" || consumer == "codex" {
		return purpose == "codex" && consumer == "codex"
	}
	return consumer != ""
}

func (a Authority) LocalEndpointID() string {
	if a.localRole == "controlled" {
		return a.responderEndpoint
	}
	return a.initiatorEndpoint
}

func (a Authority) PeerEndpointID() string {
	if a.localRole == "controlled" {
		return a.initiatorEndpoint
	}
	return a.responderEndpoint
}

func (a Authority) PMTUKey() [32]byte { return a.pmtuKey }

func deriveHandle(domain, value string) [16]byte {
	digest := sha256.Sum256([]byte(domain + "\x00" + value))
	var result [16]byte
	copy(result[:], digest[:16])
	return result
}

func equal32(left, right []byte) bool {
	if len(left) != 32 || len(right) != 32 {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
