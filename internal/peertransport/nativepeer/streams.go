// Package nativepeer adapts authenticated peer relay streams to native protocol connections.
package nativepeer

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
)

var ErrInvalid = errors.New("invalid native peer stream configuration")

type Initiator struct {
	Connection *relaycarrier.Connection
	Authority  peersession.Authority
}

// OpenCandidateControl opens the authenticated physical-candidate ownership
// channel. It is distinct from native application streams.
func (i Initiator) OpenCandidateControl(ctx context.Context, payload []byte) (net.Conn, []byte, error) {
	if ctx == nil || i.Connection == nil {
		return nil, nil, ErrInvalid
	}
	authority, err := i.Authority.Initiator("candidate-control")
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	config, err := relaycarrier.PeerInitiatorConfig(authority, i.Connection.Carrier(), "candidate-control", payload)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	stream, response, err := i.Connection.Initiate(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	connection, err := relaycarrier.NewSecureConn(stream, i.Authority.LocalEndpointID(), i.Authority.PeerEndpointID())
	if err != nil {
		_ = stream.Close()
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	return connection, response, nil
}

func (i Initiator) OpenAuthorized(ctx context.Context, header streamauth.Header) (net.Conn, error) {
	if ctx == nil || i.Connection == nil {
		return nil, ErrInvalid
	}
	payload, err := header.MarshalBinary()
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	authority, err := i.Authority.InitiatorTransportStream()
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	config, err := relaycarrier.PeerInitiatorConfig(authority, i.Connection.Carrier(), "authorized-stream", payload)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	stream, response, err := i.Connection.Initiate(ctx, config)
	if err != nil {
		return nil, err
	}
	if len(response) != 0 {
		return nil, errors.Join(ErrInvalid, stream.Close())
	}
	connection, err := relaycarrier.NewSecureConn(stream, i.Authority.LocalEndpointID(), i.Authority.PeerEndpointID())
	if err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	return connection, nil
}

func (i Initiator) Open(ctx context.Context, streamID string) (net.Conn, error) {
	if ctx == nil || i.Connection == nil {
		return nil, ErrInvalid
	}
	authority, err := i.Authority.Initiator(streamID)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	config, err := relaycarrier.PeerInitiatorConfig(authority, i.Connection.Carrier(), streamID, nil)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	stream, response, err := i.Connection.Initiate(ctx, config)
	if err != nil {
		return nil, err
	}
	if len(response) != 0 {
		return nil, errors.Join(ErrInvalid, stream.Close())
	}
	connection, err := relaycarrier.NewSecureConn(stream, i.Authority.LocalEndpointID(), i.Authority.PeerEndpointID())
	if err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	return connection, nil
}

func (i Initiator) Close() error {
	if i.Connection == nil {
		return nil
	}
	return i.Connection.Close()
}

type Responder struct {
	Connection *relaycarrier.Connection
	Authority  peersession.Authority
}

func (r Responder) AcceptCandidateControl(ctx context.Context, authorize func(context.Context, []byte) ([]byte, error)) (net.Conn, []byte, error) {
	if ctx == nil || r.Connection == nil || authorize == nil {
		return nil, nil, ErrInvalid
	}
	authority, err := r.Authority.Responder("candidate-control")
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	config, err := relaycarrier.PeerResponderConfig(authority, r.Connection.Carrier(), "candidate-control", authorize)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	stream, payload, err := r.Connection.Accept(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	connection, err := relaycarrier.NewSecureConn(stream, r.Authority.LocalEndpointID(), r.Authority.PeerEndpointID())
	if err != nil {
		_ = stream.Close()
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	return connection, payload, nil
}

func (r Responder) AcceptAuthorized(ctx context.Context, authorize func(context.Context, streamauth.Header) error) (net.Conn, streamauth.Header, error) {
	if ctx == nil || r.Connection == nil || authorize == nil {
		return nil, streamauth.Header{}, ErrInvalid
	}
	authority, err := r.Authority.ResponderTransportStream()
	if err != nil {
		return nil, streamauth.Header{}, errors.Join(ErrInvalid, err)
	}
	var header streamauth.Header
	config, err := relaycarrier.PeerResponderConfig(authority, r.Connection.Carrier(), "authorized-stream", func(authorizeCtx context.Context, payload []byte) ([]byte, error) {
		parsed, parseErr := streamauth.Parse(payload, time.Now().UTC())
		if parseErr != nil {
			return nil, parseErr
		}
		if authorizeErr := authorize(authorizeCtx, parsed); authorizeErr != nil {
			return nil, authorizeErr
		}
		header = parsed
		return nil, nil
	})
	if err != nil {
		return nil, streamauth.Header{}, errors.Join(ErrInvalid, err)
	}
	stream, _, err := r.Connection.Accept(ctx, config)
	if err != nil {
		return nil, streamauth.Header{}, err
	}
	connection, err := relaycarrier.NewSecureConn(stream, r.Authority.LocalEndpointID(), r.Authority.PeerEndpointID())
	if err != nil {
		return nil, streamauth.Header{}, errors.Join(err, stream.Close())
	}
	return connection, header, nil
}

func (r Responder) Accept(ctx context.Context, streamID string) (net.Conn, error) {
	connection, _, err := r.AcceptPayload(ctx, streamID, func(context.Context, []byte) ([]byte, error) { return nil, nil })
	return connection, err
}

// AcceptPayload exposes the authenticated Noise handshake payload to a caller
// that performs consumer-specific stream authorization before dispatch.
func (r Responder) AcceptPayload(ctx context.Context, streamID string, authorize func(context.Context, []byte) ([]byte, error)) (net.Conn, []byte, error) {
	if ctx == nil || r.Connection == nil || authorize == nil {
		return nil, nil, ErrInvalid
	}
	authority, err := r.Authority.Responder(streamID)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	config, err := relaycarrier.PeerResponderConfig(authority, r.Connection.Carrier(), streamID, authorize)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalid, err)
	}
	stream, request, err := r.Connection.Accept(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	connection, err := relaycarrier.NewSecureConn(stream, r.Authority.LocalEndpointID(), r.Authority.PeerEndpointID())
	if err != nil {
		return nil, nil, errors.Join(err, stream.Close())
	}
	return connection, request, nil
}

func (r Responder) Close() error {
	if r.Connection == nil {
		return nil
	}
	return r.Connection.Close()
}
