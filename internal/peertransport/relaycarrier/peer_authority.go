package relaycarrier

import (
	"context"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

func PeerInitiatorConfig(authority peersession.StreamAuthority, carrier relaynoise.Carrier, streamID string, payload []byte) (InitiatorConfig, error) {
	prologue, err := peerPrologue(authority, carrier, streamID)
	if err != nil {
		return InitiatorConfig{}, err
	}
	return InitiatorConfig{LocalStatic: noise.DHKey{Private: append([]byte(nil), authority.LocalPrivate[:]...), Public: append([]byte(nil), authority.LocalPublic[:]...)}, ResponderPublic: authority.PeerPublic, Prologue: prologue, Handle: authority.Handle, InitialPayload: append([]byte(nil), payload...)}, nil
}

func PeerResponderConfig(authority peersession.StreamAuthority, carrier relaynoise.Carrier, streamID string, authorize func(context.Context, []byte) ([]byte, error)) (ResponderConfig, error) {
	if authorize == nil {
		return ResponderConfig{}, ErrInvalid
	}
	prologue, err := peerPrologue(authority, carrier, streamID)
	if err != nil {
		return ResponderConfig{}, err
	}
	return ResponderConfig{LocalStatic: noise.DHKey{Private: append([]byte(nil), authority.LocalPrivate[:]...), Public: append([]byte(nil), authority.LocalPublic[:]...)}, InitiatorPublic: authority.PeerPublic, Prologue: prologue, Handle: authority.Handle, Authorize: authorize}, nil
}

func peerPrologue(authority peersession.StreamAuthority, carrier relaynoise.Carrier, streamID string) (relaynoise.Prologue, error) {
	if carrier != relaynoise.CarrierRelayQUIC && carrier != relaynoise.CarrierWSS {
		return relaynoise.Prologue{}, ErrInvalid
	}
	prologue := relaynoise.Prologue{Context: authority.Context, Transport: authority.Transport, Stream: authority.Stream, Carrier: carrier, StreamID: streamID}
	if _, err := prologue.MarshalBinary(); err != nil {
		return relaynoise.Prologue{}, err
	}
	return prologue, nil
}
