package relaynoise

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

const (
	protocolVersion = 1
	recordVersion   = 1
)

type Carrier uint8

const (
	CarrierRelayQUIC Carrier = iota + 1
	CarrierWSS
)

type Prologue struct {
	Context   peercontext.Context
	Transport peercontext.Transport
	Stream    peercontext.Stream
	Carrier   Carrier
	StreamID  string
}

func (p Prologue) MarshalBinary() ([]byte, error) {
	var context []byte
	version := protocolVersion
	if p.Transport != (peercontext.Transport{}) {
		transport, transportErr := p.Transport.MarshalBinary()
		if transportErr != nil {
			return nil, transportErr
		}
		context = append([]byte(nil), transport...)
		if p.Stream != (peercontext.Stream{}) {
			stream, streamErr := p.Stream.MarshalBinary()
			if streamErr != nil {
				return nil, streamErr
			}
			context = append(context, stream...)
		}
		version = 2
	} else {
		var err error
		context, err = p.Context.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	if p.Carrier != CarrierRelayQUIC && p.Carrier != CarrierWSS || !validIdentifier(p.StreamID) {
		return nil, errors.New("invalid Noise prologue stream or carrier")
	}
	encoded := []byte{'P', 'B', 'N', 'P', byte(version), recordVersion}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(context)))
	encoded = append(encoded, context...)
	encoded = append(encoded, byte(p.Carrier))
	encoded = appendString(encoded, p.StreamID)
	return encoded, nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '_' || character == '.' || character == ':' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func (p Prologue) Hash() ([32]byte, error) {
	encoded, err := p.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func appendString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint16(target, uint16(len(value)))
	return append(target, value...)
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
