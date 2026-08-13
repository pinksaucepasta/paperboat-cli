package relaycarrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

const (
	healthPayloadSize        = 22
	healthInitialPayloadSize = healthPayloadSize + 8
)

var healthMagic = [4]byte{'P', 'B', 'R', 'H'}

type HealthConfigSource interface {
	HealthInitiatorConfig(context.Context, [16]byte) (InitiatorConfig, error)
}

type HealthConfigSourceFunc func(context.Context, [16]byte) (InitiatorConfig, error)

func (f HealthConfigSourceFunc) HealthInitiatorConfig(ctx context.Context, handle [16]byte) (InitiatorConfig, error) {
	return f(ctx, handle)
}

type HealthResponderConfigSource interface {
	HealthResponderConfig(context.Context, [16]byte) (ResponderConfig, error)
}

type HealthResponderConfigSourceFunc func(context.Context, [16]byte) (ResponderConfig, error)

func (f HealthResponderConfigSourceFunc) HealthResponderConfig(ctx context.Context, handle [16]byte) (ResponderConfig, error) {
	return f(ctx, handle)
}

type HealthTransport struct {
	Connection *Connection
	source     HealthConfigSource
	handles    *healthHandleSequence
}

type healthHandleSequence struct {
	prefix [8]byte
	next   atomic.Uint64
}

// HealthConnection carries the authenticated Noise configuration required for
// health exchanges alongside the relay connection that established it.
type HealthConnection struct {
	*Connection
	transport HealthTransport
	path      connectionmanager.Path
	state     atomic.Uint32
}

func NewHealthConnection(connection *Connection, source HealthConfigSource) (*HealthConnection, error) {
	if connection == nil || connection.closed() || source == nil {
		return nil, ErrInvalid
	}
	handles := &healthHandleSequence{}
	if _, err := rand.Read(handles.prefix[:]); err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	path := connectionmanager.PathRelayQUIC
	if connection.carrier == relaynoise.CarrierWSS {
		path = connectionmanager.PathWSS
	}
	result := &HealthConnection{Connection: connection, transport: HealthTransport{Connection: connection, source: source, handles: handles}, path: path}
	result.state.Store(uint32(connectionmanager.StateReady))
	return result, nil
}

func (c *HealthConnection) State() connectionmanager.State {
	if c == nil || c.Connection == nil || c.Connection.closed() {
		return connectionmanager.StateFailed
	}
	return connectionmanager.State(c.state.Load())
}

func (c *HealthConnection) Close() error {
	if c == nil {
		return nil
	}
	c.state.Store(uint32(connectionmanager.StateFailed))
	return c.Connection.Close()
}

func (c *HealthConnection) ActiveHealthCapability() (connectionmanager.ActiveHealthCapability, error) {
	if c == nil || c.Connection == nil || c.Connection.closed() || c.transport.Connection != c.Connection {
		return connectionmanager.ActiveHealthCapability{}, ErrClosed
	}
	return connectionmanager.ActiveHealthCapability{Path: c.path, Transport: c.transport}, nil
}

func (c *HealthConnection) AdmitInitialHealth(ctx context.Context, nonce [16]byte) error {
	if c == nil || ctx == nil || !c.state.CompareAndSwap(uint32(connectionmanager.StateReady), uint32(connectionmanager.StateProbing)) {
		return ErrInvalid
	}
	if _, err := c.transport.HealthExchange(ctx, nonce); err != nil {
		c.state.Store(uint32(connectionmanager.StateFailed))
		_ = c.Connection.Close()
		return initialHealthFailure(c.path, err)
	}
	c.state.Store(uint32(connectionmanager.StateTrusted))
	return nil
}

func initialHealthFailure(path connectionmanager.Path, err error) error {
	if errors.Is(err, yamux.ErrSessionShutdown) {
		return &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: path, Cause: err}
	}
	return err
}

// AdmitInitialRelayHealth authenticates the fixed bootstrap stream and
// negotiates the encrypted random prefix used for all later health handles.
func (c *HealthConnection) AdmitInitialRelayHealth(ctx context.Context, config InitiatorConfig, nonce [16]byte) error {
	if c == nil || ctx == nil || config.Handle == [16]byte{} || config.Prologue.Carrier != c.Connection.carrier || !c.state.CompareAndSwap(uint32(connectionmanager.StateReady), uint32(connectionmanager.StateProbing)) {
		return ErrInvalid
	}
	config.InitialPayload = initialHealthPayload(1, nonce, c.transport.handles.prefix)
	stream, response, err := c.Connection.Initiate(ctx, config)
	if err == nil {
		defer stream.Close()
		var responseNonce [16]byte
		var responsePrefix [8]byte
		responseNonce, responsePrefix, err = parseInitialHealthPayload(response, 2)
		if err == nil && (responseNonce != nonce || responsePrefix != c.transport.handles.prefix) {
			err = relaynoise.ErrProtocol
		}
	}
	if err != nil {
		c.state.Store(uint32(connectionmanager.StateFailed))
		_ = c.Connection.Close()
		return initialHealthFailure(c.path, err)
	}
	c.state.Store(uint32(connectionmanager.StateTrusted))
	return nil
}

func (t HealthTransport) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	if t.Connection == nil || ctx == nil || t.source == nil || t.handles == nil {
		return 0, ErrInvalid
	}
	handle, err := t.handles.nextHandle()
	if err != nil {
		return 0, err
	}
	config, err := t.source.HealthInitiatorConfig(ctx, handle)
	if err != nil {
		return 0, err
	}
	if config.Handle != handle || config.Prologue.Carrier != t.Connection.carrier {
		return 0, ErrInvalid
	}
	if _, err := relaynoise.NewInitiator(config.LocalStatic, config.ResponderPublic, config.Prologue, config.Handle); err != nil {
		return 0, errors.Join(ErrInvalid, err)
	}
	return t.Connection.HealthExchange(ctx, config, nonce)
}

func (s *healthHandleSequence) nextHandle() ([16]byte, error) {
	if s == nil {
		return [16]byte{}, ErrInvalid
	}
	var sequence uint64
	for {
		current := s.next.Load()
		if current == ^uint64(0) {
			return [16]byte{}, ErrInvalid
		}
		sequence = current + 1
		if s.next.CompareAndSwap(current, sequence) {
			break
		}
	}
	var handle [16]byte
	copy(handle[:8], s.prefix[:])
	binary.BigEndian.PutUint64(handle[8:], sequence)
	return handle, nil
}

func (c *Connection) HealthExchange(ctx context.Context, config InitiatorConfig, nonce [16]byte) (uint32, error) {
	if c == nil || ctx == nil {
		return 0, ErrInvalid
	}
	config.InitialPayload = healthPayload(1, nonce)
	before := c.ptoCount()
	stream, response, err := c.Initiate(ctx, config)
	if err != nil {
		return 0, err
	}
	defer stream.Close()
	responseNonce, err := parseHealthPayload(response, 2)
	if err != nil || responseNonce != nonce {
		return 0, errors.Join(relaynoise.ErrProtocol, err)
	}
	return c.ptoCount() - before, nil
}

func (c *Connection) AcceptHealth(ctx context.Context, config ResponderConfig) error {
	if c == nil || ctx == nil || config.Authorize != nil {
		return ErrInvalid
	}
	config.Authorize = func(_ context.Context, request []byte) ([]byte, error) {
		nonce, err := parseHealthPayload(request, 1)
		if err != nil {
			return nil, err
		}
		return healthPayload(2, nonce), nil
	}
	stream, _, err := c.Accept(ctx, config)
	if err != nil {
		return err
	}
	return stream.Close()
}

// AcceptInitialHealth authenticates the bootstrap exchange and returns the
// encrypted random prefix needed to predict subsequent one-time handles.
func (c *Connection) AcceptInitialHealth(ctx context.Context, config ResponderConfig) ([8]byte, error) {
	if c == nil || ctx == nil || config.Authorize != nil {
		return [8]byte{}, ErrInvalid
	}
	var prefix [8]byte
	config.Authorize = func(_ context.Context, request []byte) ([]byte, error) {
		nonce, negotiated, err := parseInitialHealthPayload(request, 1)
		if err != nil {
			return nil, err
		}
		prefix = negotiated
		return initialHealthPayload(2, nonce, negotiated), nil
	}
	stream, _, err := c.Accept(ctx, config)
	if err != nil {
		return [8]byte{}, err
	}
	return prefix, stream.Close()
}

// ServeHealth answers periodic probes in the negotiated handle order. It is
// started only after the application's long-lived relay streams are admitted.
func (c *Connection) ServeHealth(ctx context.Context, prefix [8]byte, source HealthResponderConfigSource) error {
	if c == nil || ctx == nil || prefix == [8]byte{} || source == nil {
		return ErrInvalid
	}
	handles := &healthHandleSequence{prefix: prefix}
	for {
		handle, err := handles.nextHandle()
		if err != nil {
			return err
		}
		config, err := source.HealthResponderConfig(ctx, handle)
		if err != nil {
			return err
		}
		if config.Handle != handle || config.Prologue.Carrier != c.carrier {
			return ErrInvalid
		}
		config.Authorize = nil
		if err := c.AcceptHealth(ctx, config); err != nil {
			return err
		}
	}
}

// ServeHealthOnce answers exactly one post-bootstrap probe. Short-lived ping
// attempts use this so they release host admission independently of carrier
// close propagation; long-lived sessions use ServeHealth for periodic probes.
func (c *Connection) ServeHealthOnce(ctx context.Context, prefix [8]byte, source HealthResponderConfigSource) error {
	if c == nil || ctx == nil || prefix == [8]byte{} || source == nil {
		return ErrInvalid
	}
	handles := &healthHandleSequence{prefix: prefix}
	handle, err := handles.nextHandle()
	if err != nil {
		return err
	}
	config, err := source.HealthResponderConfig(ctx, handle)
	if err != nil {
		return err
	}
	if config.Handle != handle || config.Prologue.Carrier != c.carrier {
		return ErrInvalid
	}
	config.Authorize = nil
	return c.AcceptHealth(ctx, config)
}

func healthPayload(kind byte, nonce [16]byte) []byte {
	result := make([]byte, healthPayloadSize)
	copy(result[:4], healthMagic[:])
	result[4], result[5] = 1, kind
	copy(result[6:], nonce[:])
	return result
}

func initialHealthPayload(kind byte, nonce [16]byte, prefix [8]byte) []byte {
	result := make([]byte, healthInitialPayloadSize)
	copy(result, healthPayload(kind, nonce))
	copy(result[healthPayloadSize:], prefix[:])
	return result
}

func parseInitialHealthPayload(value []byte, kind byte) ([16]byte, [8]byte, error) {
	if len(value) != healthInitialPayloadSize {
		return [16]byte{}, [8]byte{}, relaynoise.ErrProtocol
	}
	nonce, err := parseHealthPayload(value[:healthPayloadSize], kind)
	if err != nil {
		return [16]byte{}, [8]byte{}, err
	}
	var prefix [8]byte
	copy(prefix[:], value[healthPayloadSize:])
	if prefix == [8]byte{} {
		return [16]byte{}, [8]byte{}, relaynoise.ErrProtocol
	}
	return nonce, prefix, nil
}

func parseHealthPayload(value []byte, kind byte) ([16]byte, error) {
	if len(value) != healthPayloadSize || string(value[:4]) != string(healthMagic[:]) || value[4] != 1 || value[5] != kind {
		return [16]byte{}, relaynoise.ErrProtocol
	}
	var nonce [16]byte
	copy(nonce[:], value[6:])
	return nonce, nil
}
