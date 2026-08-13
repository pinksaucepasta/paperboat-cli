package resumablestream

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

type Role uint8

const (
	RoleUnspecified Role = iota
	RoleInitiator
	RoleResponder
)

type CarrierID [16]byte

type StreamIdentity struct {
	Principal   string
	OperationID string
	Consumer    string
	StreamID    string
}

func (i StreamIdentity) digest() ([32]byte, error) {
	if i.Principal == "" || i.OperationID == "" || i.Consumer == "" || i.StreamID == "" {
		return [32]byte{}, ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("paperboat-resumable-stream-v2\x00"))
	for _, value := range [...]string{i.Principal, i.OperationID, i.Consumer, i.StreamID} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func randomCarrierID() (CarrierID, error) {
	var id CarrierID
	if _, err := rand.Read(id[:]); err != nil {
		return CarrierID{}, err
	}
	if id == (CarrierID{}) {
		return CarrierID{}, errors.New("zero resumable carrier id")
	}
	return id, nil
}

type EventType uint8

const (
	EventUnspecified EventType = iota
	EventDetached
	EventActive
	EventPrepared
	EventCarrierFailed
	EventAborted
)

type Event struct {
	Type            EventType
	FailedCarrier   CarrierID
	ActiveCarrier   CarrierID
	PreparedCarrier CarrierID
	CommittedEpoch  uint64
	Err             error
}

type CarrierHandle struct {
	ID    CarrierID
	Epoch uint64
}

const (
	helloPrepare byte = iota + 1
	helloReady
)

const helloV2Size = 8 + 1 + 32 + 16 + 8 + 8 + 8 + 1 + 8

type helloV2 struct {
	kind           byte
	digest         [32]byte
	carrier        CarrierID
	epoch          uint64
	committedEpoch uint64
	ack            uint64
	fin            bool
	finOffset      uint64
}

func writeHello(w io.Writer, h helloV2) error {
	var encoded [helloV2Size]byte
	copy(encoded[:8], "PBRS\x00\x00\x00\x03")
	encoded[8] = h.kind
	copy(encoded[9:41], h.digest[:])
	copy(encoded[41:57], h.carrier[:])
	binary.BigEndian.PutUint64(encoded[57:65], h.epoch)
	binary.BigEndian.PutUint64(encoded[65:73], h.committedEpoch)
	binary.BigEndian.PutUint64(encoded[73:81], h.ack)
	if h.fin {
		encoded[81] = 1
	}
	binary.BigEndian.PutUint64(encoded[82:90], h.finOffset)
	return writeAll(w, encoded[:])
}

func readHello(r io.Reader) (helloV2, error) {
	var encoded [helloV2Size]byte
	if _, err := io.ReadFull(r, encoded[:]); err != nil {
		return helloV2{}, err
	}
	if string(encoded[:8]) != "PBRS\x00\x00\x00\x03" || encoded[8] < helloPrepare || encoded[8] > helloReady || encoded[81] > 1 {
		return helloV2{}, ErrProtocol
	}
	value := helloV2{kind: encoded[8], epoch: binary.BigEndian.Uint64(encoded[57:65]), committedEpoch: binary.BigEndian.Uint64(encoded[65:73]), ack: binary.BigEndian.Uint64(encoded[73:81]), fin: encoded[81] == 1, finOffset: binary.BigEndian.Uint64(encoded[82:90])}
	copy(value.digest[:], encoded[9:41])
	copy(value.carrier[:], encoded[41:57])
	if value.carrier == (CarrierID{}) || value.epoch == 0 {
		return helloV2{}, ErrProtocol
	}
	return value, nil
}
