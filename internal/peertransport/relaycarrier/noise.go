package relaycarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

const maximumHandshake = 65535

type InitiatorConfig struct {
	LocalStatic     noise.DHKey
	ResponderPublic [32]byte
	Prologue        relaynoise.Prologue
	Handle          [16]byte
	InitialPayload  []byte
}

type ResponderConfig struct {
	LocalStatic     noise.DHKey
	InitiatorPublic [32]byte
	Prologue        relaynoise.Prologue
	Handle          [16]byte
	Authorize       func(context.Context, []byte) ([]byte, error)
}

type SecureStream struct {
	carrier *relaynoise.StreamCarrier
	session *relaynoise.Session
	once    sync.Once
	err     error
}

func (c *Connection) Initiate(ctx context.Context, config InitiatorConfig) (*SecureStream, []byte, error) {
	if c == nil || ctx == nil || config.Prologue.Carrier != c.carrier {
		return nil, nil, ErrInvalid
	}
	stream, err := c.openHandle(ctx, config.Handle, false)
	if err != nil {
		return nil, nil, err
	}
	fail := func(cause error) (*SecureStream, []byte, error) {
		return nil, nil, errors.Join(cause, stream.Close())
	}
	initiator, err := relaynoise.NewInitiator(config.LocalStatic, config.ResponderPublic, config.Prologue, config.Handle)
	if err != nil {
		return fail(err)
	}
	request, err := initiator.WriteRequest(config.InitialPayload)
	if err != nil {
		return fail(err)
	}
	if err := writeHandshake(ctx, stream, request); err != nil {
		return fail(err)
	}
	response, err := readHandshake(ctx, stream)
	if err != nil {
		return fail(fmt.Errorf("read Noise response (%s): %w", noiseAuthorityDiagnostic(config.Prologue, config.LocalStatic.Public, config.ResponderPublic, config.Handle), err))
	}
	payload, session, err := initiator.ReadResponse(response)
	if err != nil {
		return fail(fmt.Errorf("authenticate Noise response (%s): %w", noiseAuthorityDiagnostic(config.Prologue, config.LocalStatic.Public, config.ResponderPublic, config.Handle), err))
	}
	carrier, err := relaynoise.NewStreamCarrier(stream)
	if err != nil {
		return fail(err)
	}
	return &SecureStream{carrier: carrier, session: session}, payload, nil
}

func (c *Connection) Accept(ctx context.Context, config ResponderConfig) (*SecureStream, []byte, error) {
	if c == nil || ctx == nil || config.Prologue.Carrier != c.carrier || config.Authorize == nil {
		return nil, nil, ErrInvalid
	}
	stream, err := c.openHandle(ctx, config.Handle, true)
	if err != nil {
		return nil, nil, err
	}
	fail := func(cause error) (*SecureStream, []byte, error) {
		return nil, nil, errors.Join(cause, stream.Close())
	}
	responder, err := relaynoise.NewResponder(config.LocalStatic, config.InitiatorPublic, config.Prologue, config.Handle)
	if err != nil {
		return fail(err)
	}
	request, err := readHandshake(ctx, stream)
	if err != nil {
		return fail(fmt.Errorf("read Noise request (%s): %w", noiseAuthorityDiagnostic(config.Prologue, config.LocalStatic.Public, config.InitiatorPublic, config.Handle), err))
	}
	payload, err := responder.ReadRequest(request)
	if err != nil {
		return fail(fmt.Errorf("authenticate Noise request (%s): %w", noiseAuthorityDiagnostic(config.Prologue, config.LocalStatic.Public, config.InitiatorPublic, config.Handle), err))
	}
	responsePayload, err := config.Authorize(ctx, append([]byte(nil), payload...))
	if err != nil {
		return fail(err)
	}
	response, session, err := responder.WriteResponse(responsePayload)
	if err != nil {
		return fail(err)
	}
	if err := writeHandshake(ctx, stream, response); err != nil {
		return fail(err)
	}
	carrier, err := relaynoise.NewStreamCarrier(stream)
	if err != nil {
		return fail(err)
	}
	return &SecureStream{carrier: carrier, session: session}, payload, nil
}

func noiseAuthorityDiagnostic(prologue relaynoise.Prologue, localPublic []byte, peerPublic [32]byte, handle [16]byte) string {
	prologueHash, _ := prologue.Hash()
	localHash := sha256.Sum256(localPublic)
	peerHash := sha256.Sum256(peerPublic[:])
	handleHash := sha256.Sum256(handle[:])
	transportIDHash := sha256.Sum256([]byte(prologue.Transport.TransportID))
	accountHash := sha256.Sum256([]byte(prologue.Transport.AccountID))
	userHash := sha256.Sum256([]byte(prologue.Transport.UserID))
	deviceHash := sha256.Sum256([]byte(prologue.Transport.DeviceID))
	machineHash := sha256.Sum256([]byte(prologue.Transport.MachineID))
	return fmt.Sprintf("prologue=%x local=%x peer=%x handle=%x transport=%x account=%x user=%x device=%x machine=%x initiator_role=%s responder_role=%s carrier=%d stream_id=%s initiator_cert=%x responder_cert=%x attempt=%d host=%d authorization=%d", prologueHash[:6], localHash[:6], peerHash[:6], handleHash[:6], transportIDHash[:6], accountHash[:4], userHash[:4], deviceHash[:4], machineHash[:4], prologue.Transport.InitiatorRole, prologue.Transport.ResponderRole, prologue.Carrier, prologue.StreamID, prologue.Transport.InitiatorCertificateHash[:4], prologue.Transport.ResponderCertificateHash[:4], prologue.Transport.AttemptGeneration, prologue.Transport.HostGeneration, prologue.Transport.AuthorizationGeneration)
}

func (s *SecureStream) Send(ctx context.Context, plaintext []byte, closeAfter bool) error {
	if s == nil || s.carrier == nil || s.session == nil {
		return ErrInvalid
	}
	return s.carrier.Send(ctx, s.session, plaintext, closeAfter)
}

func (s *SecureStream) Receive(ctx context.Context) ([]byte, bool, error) {
	if s == nil || s.carrier == nil || s.session == nil {
		return nil, false, ErrInvalid
	}
	record, err := s.carrier.ReceiveRecord(ctx)
	if err != nil {
		return nil, false, err
	}
	return s.session.Open(record)
}

func (s *SecureStream) Close() error {
	if s == nil || s.carrier == nil {
		return nil
	}
	s.once.Do(func() { s.err = s.carrier.Close() })
	return s.err
}

func (s *SecureStream) ChannelBinding() ([32]byte, error) {
	if s == nil || s.session == nil {
		return [32]byte{}, ErrInvalid
	}
	return s.session.ChannelBinding(), nil
}

type handshakeStream interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func writeHandshake(ctx context.Context, raw io.ReadWriteCloser, message []byte) error {
	stream, ok := raw.(handshakeStream)
	if !ok || len(message) == 0 || len(message) > maximumHandshake {
		return relaynoise.ErrProtocol
	}
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	return withWriteDeadline(ctx, stream, func() error {
		_, err := io.CopyN(stream, bytes.NewReader(frame), int64(len(frame)))
		return err
	})
}

func readHandshake(ctx context.Context, raw io.ReadWriteCloser) ([]byte, error) {
	stream, ok := raw.(handshakeStream)
	if !ok {
		return nil, relaynoise.ErrProtocol
	}
	var header [2]byte
	if err := withReadDeadline(ctx, stream, func() error { _, err := io.ReadFull(stream, header[:]); return err }); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 || length > maximumHandshake {
		return nil, relaynoise.ErrProtocol
	}
	payload := make([]byte, length)
	if err := withReadDeadline(ctx, stream, func() error { _, err := io.ReadFull(stream, payload); return err }); err != nil {
		return nil, err
	}
	return payload, nil
}

func withReadDeadline(ctx context.Context, stream handshakeStream, operation func() error) error {
	return withHandshakeDeadline(ctx, stream.SetReadDeadline, operation)
}

func withWriteDeadline(ctx context.Context, stream handshakeStream, operation func() error) error {
	return withHandshakeDeadline(ctx, stream.SetWriteDeadline, operation)
}

func withHandshakeDeadline(ctx context.Context, setDeadline func(time.Time) error, operation func() error) error {
	if ctx == nil {
		return ErrInvalid
	}
	interrupted := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { interrupted <- setDeadline(time.Now()) })
	finish := func() error {
		var interruptErr error
		if !stop() {
			interruptErr = <-interrupted
		}
		return errors.Join(interruptErr, setDeadline(time.Time{}))
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := setDeadline(deadline); err != nil {
			return errors.Join(err, finish())
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, finish())
	}
	err := operation()
	ctxErr := ctx.Err()
	finishErr := finish()
	if ctxErr != nil {
		return errors.Join(ctxErr, err, finishErr)
	}
	return errors.Join(err, finishErr)
}
