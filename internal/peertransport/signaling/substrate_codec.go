package signaling

import (
	"encoding/binary"
	"errors"
)

const (
	SubstrateSubprotocol = "paperboat.peer-signaling-substrate.v1"
	substrateHeaderSize  = 10
	substrateMaximumBody = MaximumMessage
)

type substrateKind uint8

const (
	substrateAttach substrateKind = iota + 1
	substrateReady
	substrateData
	substrateComplete
	substrateAbort
	substrateRejected
)

type substrateFrame struct {
	kind    substrateKind
	channel uint64
	body    []byte
}

func encodeSubstrateFrame(frame substrateFrame) ([]byte, error) {
	if frame.channel == 0 || !validSubstrateFrame(frame.kind, frame.body) {
		return nil, ErrTransportProtocol
	}
	raw := make([]byte, substrateHeaderSize+len(frame.body))
	raw[0], raw[1] = 1, byte(frame.kind)
	binary.BigEndian.PutUint64(raw[2:10], frame.channel)
	copy(raw[substrateHeaderSize:], frame.body)
	return raw, nil
}

func decodeSubstrateFrame(raw []byte) (substrateFrame, error) {
	if len(raw) < substrateHeaderSize || len(raw) > substrateHeaderSize+substrateMaximumBody || raw[0] != 1 {
		return substrateFrame{}, ErrTransportProtocol
	}
	frame := substrateFrame{kind: substrateKind(raw[1]), channel: binary.BigEndian.Uint64(raw[2:10]), body: append([]byte(nil), raw[substrateHeaderSize:]...)}
	if frame.channel == 0 || !validSubstrateFrame(frame.kind, frame.body) {
		return substrateFrame{}, ErrTransportProtocol
	}
	return frame, nil
}

func validSubstrateFrame(kind substrateKind, body []byte) bool {
	switch kind {
	case substrateAttach:
		return validWebSocketCredential(string(body))
	case substrateData:
		return len(body) > 0 && len(body) <= MaximumMessage
	case substrateReady, substrateComplete, substrateAbort, substrateRejected:
		return len(body) == 0
	default:
		return false
	}
}

var errSubstrateClosed = errors.New("peer signaling substrate closed")
