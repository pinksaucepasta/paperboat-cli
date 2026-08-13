package relaynoise

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

var (
	ErrAuthentication = errors.New("relay E2EE authentication failed")
	ErrProtocol       = errors.New("relay E2EE protocol violation")
	ErrReplay         = errors.New("relay E2EE sequence violation")
	ErrLimit          = errors.New("relay E2EE size limit exceeded")
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

type Initiator struct {
	handshake *noise.HandshakeState
	handle    [16]byte
	wrote     bool
}

type Responder struct {
	handshake         *noise.HandshakeState
	handle            [16]byte
	expectedInitiator [32]byte
	read              bool
}

func GenerateStaticKey() (noise.DHKey, error) {
	key, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("generate Noise static key: %w", err)
	}
	return key, nil
}

func NewInitiator(local noise.DHKey, responderPublic [32]byte, prologue Prologue, handle [16]byte) (*Initiator, error) {
	if err := validateKeypair(local); err != nil || allZero(responderPublic[:]) || allZero(handle[:]) {
		return nil, errors.New("invalid Noise initiator identity or handle")
	}
	encoded, err := prologue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return newInitiator(local, responderPublic, encoded, handle)
}

func newInitiator(local noise.DHKey, responderPublic [32]byte, encoded []byte, handle [16]byte) (*Initiator, error) {
	handshake, err := noise.NewHandshakeState(noise.Config{CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: true, Prologue: encoded, StaticKeypair: cloneKey(local), PeerStatic: append([]byte(nil), responderPublic[:]...)})
	if err != nil {
		return nil, fmt.Errorf("create Noise initiator: %w", err)
	}
	return &Initiator{handshake: handshake, handle: handle}, nil
}

func NewResponder(local noise.DHKey, initiatorPublic [32]byte, prologue Prologue, handle [16]byte) (*Responder, error) {
	if err := validateKeypair(local); err != nil || allZero(initiatorPublic[:]) || allZero(handle[:]) {
		return nil, errors.New("invalid Noise responder identity or handle")
	}
	encoded, err := prologue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return newResponder(local, initiatorPublic, encoded, handle)
}

func newResponder(local noise.DHKey, initiatorPublic [32]byte, encoded []byte, handle [16]byte) (*Responder, error) {
	handshake, err := noise.NewHandshakeState(noise.Config{CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: false, Prologue: encoded, StaticKeypair: cloneKey(local)})
	if err != nil {
		return nil, fmt.Errorf("create Noise responder: %w", err)
	}
	return &Responder{handshake: handshake, handle: handle, expectedInitiator: initiatorPublic}, nil
}

func (i *Initiator) WriteRequest(payload []byte) ([]byte, error) {
	if i.wrote || i.handshake == nil {
		return nil, ErrProtocol
	}
	if len(payload) > 65535-96 {
		i.handshake = nil
		return nil, ErrLimit
	}
	message, send, receive, err := i.handshake.WriteMessage(nil, payload)
	if err != nil || send != nil || receive != nil {
		i.handshake = nil
		return nil, fmt.Errorf("%w: write IK request", ErrProtocol)
	}
	if len(message) > 65535 {
		i.handshake = nil
		return nil, ErrLimit
	}
	i.wrote = true
	return message, nil
}

func (r *Responder) ReadRequest(message []byte) ([]byte, error) {
	if r.read || r.handshake == nil || len(message) == 0 || len(message) > 65535 {
		r.handshake = nil
		return nil, ErrProtocol
	}
	payload, send, receive, err := r.handshake.ReadMessage(nil, message)
	if err != nil || send != nil || receive != nil {
		r.handshake = nil
		return nil, fmt.Errorf("%w: read IK request", ErrAuthentication)
	}
	if !bytes.Equal(r.handshake.PeerStatic(), r.expectedInitiator[:]) {
		r.handshake = nil
		return nil, fmt.Errorf("%w: initiator static key mismatch", ErrAuthentication)
	}
	r.read = true
	return payload, nil
}

func (r *Responder) WriteResponse(payload []byte) ([]byte, *Session, error) {
	if !r.read || r.handshake == nil {
		return nil, nil, ErrProtocol
	}
	if len(payload) > 65535-48 {
		r.handshake = nil
		return nil, nil, ErrLimit
	}
	message, send, receive, err := r.handshake.WriteMessage(nil, payload)
	if err != nil || send == nil || receive == nil {
		r.handshake = nil
		return nil, nil, fmt.Errorf("%w: write IK response", ErrProtocol)
	}
	if len(message) > 65535 {
		r.handshake = nil
		return nil, nil, ErrLimit
	}
	// Split returns initiator-to-responder first and responder-to-initiator
	// second, independent of which side completes the handshake.
	session := newSession(false, r.handle, receive, send, r.handshake.ChannelBinding())
	r.handshake = nil
	return message, session, nil
}

func (i *Initiator) ReadResponse(message []byte) ([]byte, *Session, error) {
	if !i.wrote || i.handshake == nil || len(message) == 0 || len(message) > 65535 {
		return nil, nil, ErrProtocol
	}
	payload, send, receive, err := i.handshake.ReadMessage(nil, message)
	if err != nil || send == nil || receive == nil {
		i.handshake = nil
		return nil, nil, fmt.Errorf("%w: read IK response", ErrAuthentication)
	}
	session := newSession(true, i.handle, send, receive, i.handshake.ChannelBinding())
	i.handshake = nil
	return payload, session, nil
}

func validateKeypair(key noise.DHKey) error {
	if len(key.Private) != 32 || len(key.Public) != 32 || allZero(key.Private) || allZero(key.Public) {
		return errors.New("invalid Noise static keypair")
	}
	derived, err := noise.DH25519.GenerateKeypair(bytes.NewReader(key.Private))
	if err != nil || !bytes.Equal(derived.Public, key.Public) {
		return errors.New("Noise static keypair does not match")
	}
	return nil
}

func cloneKey(key noise.DHKey) noise.DHKey {
	return noise.DHKey{Private: append([]byte(nil), key.Private...), Public: append([]byte(nil), key.Public...)}
}
