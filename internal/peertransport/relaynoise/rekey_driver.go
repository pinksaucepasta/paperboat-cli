package relaynoise

import (
	"context"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

type RekeyCarrier interface {
	SendRekeyRecord(context.Context, []byte) error
	ReceiveRekeyRecord(context.Context) ([]byte, error)
}

func RunInitiatorRekey(ctx context.Context, current *Session, carrier RekeyCarrier, local noise.DHKey, responderPublic [32]byte, prologue Prologue, generation uint64) (err error) {
	if ctx == nil || current == nil || carrier == nil || !current.initiator || generation == 0 {
		return ErrRekeyMarker
	}
	defer func() {
		if err != nil {
			current.poison()
		}
	}()
	prior := current.ChannelBinding()
	handshake, err := NewRekeyInitiator(local, responderPublic, prologue, current.handle, prior, generation)
	if err != nil {
		return err
	}
	request, err := handshake.WriteRequest(nil)
	if err != nil {
		return err
	}
	if err := sendHandshakeControl(ctx, current, carrier, RekeyHandshakeRequest, generation, prior, request); err != nil {
		return err
	}
	response, err := receiveHandshakeControl(ctx, current, carrier, RekeyHandshakeResponse, generation, prior)
	if err != nil {
		return err
	}
	_, next, err := handshake.ReadResponse(response)
	if err != nil {
		return err
	}
	transition, err := NewRekeyTransition(current, next, generation)
	if err != nil {
		return err
	}
	commitI2R := RekeyMarker{Generation: generation, Direction: RekeyInitiatorToResponder, Kind: RekeyCommit, Binding: prior}
	if err := sendMarker(ctx, current, carrier, transition, commitI2R); err != nil {
		return err
	}
	if _, err := receiveMarker(ctx, current, carrier, transition, prior, generation, RekeyInitiatorToResponder, RekeyAcknowledgement); err != nil {
		return err
	}
	if _, err := receiveMarker(ctx, current, carrier, transition, prior, generation, RekeyResponderToInitiator, RekeyCommit); err != nil {
		return err
	}
	ackR2I := RekeyMarker{Generation: generation, Direction: RekeyResponderToInitiator, Kind: RekeyAcknowledgement, Binding: prior}
	complete, err := sendMarkerComplete(ctx, current, carrier, transition, ackR2I)
	if err != nil {
		return err
	}
	if !complete {
		return ErrRekeyMarker
	}
	return nil
}

func RunResponderRekey(ctx context.Context, current *Session, carrier RekeyCarrier, local noise.DHKey, initiatorPublic [32]byte, prologue Prologue, generation uint64) (err error) {
	if ctx == nil || current == nil || carrier == nil || current.initiator || generation == 0 {
		return ErrRekeyMarker
	}
	defer func() {
		if err != nil {
			current.poison()
		}
	}()
	prior := current.ChannelBinding()
	handshake, err := NewRekeyResponder(local, initiatorPublic, prologue, current.handle, prior, generation)
	if err != nil {
		return err
	}
	request, err := receiveHandshakeControl(ctx, current, carrier, RekeyHandshakeRequest, generation, prior)
	if err != nil {
		return err
	}
	if _, err := handshake.ReadRequest(request); err != nil {
		return err
	}
	response, next, err := handshake.WriteResponse(nil)
	if err != nil {
		return err
	}
	if err := sendHandshakeControl(ctx, current, carrier, RekeyHandshakeResponse, generation, prior, response); err != nil {
		return err
	}
	transition, err := NewRekeyTransition(current, next, generation)
	if err != nil {
		return err
	}
	if _, err := receiveMarker(ctx, current, carrier, transition, prior, generation, RekeyInitiatorToResponder, RekeyCommit); err != nil {
		return err
	}
	ackI2R := RekeyMarker{Generation: generation, Direction: RekeyInitiatorToResponder, Kind: RekeyAcknowledgement, Binding: prior}
	if err := sendMarker(ctx, current, carrier, transition, ackI2R); err != nil {
		return err
	}
	commitR2I := RekeyMarker{Generation: generation, Direction: RekeyResponderToInitiator, Kind: RekeyCommit, Binding: prior}
	if err := sendMarker(ctx, current, carrier, transition, commitR2I); err != nil {
		return err
	}
	complete, err := receiveMarker(ctx, current, carrier, transition, prior, generation, RekeyResponderToInitiator, RekeyAcknowledgement)
	if err != nil {
		return err
	}
	if !complete {
		return ErrRekeyMarker
	}
	return nil
}

func sendHandshakeControl(ctx context.Context, session *Session, carrier RekeyCarrier, kind RekeyHandshakeKind, generation uint64, binding [32]byte, message []byte) error {
	payload, err := (RekeyHandshakeControl{Kind: kind, Generation: generation, Binding: binding, Message: message}).MarshalBinary()
	if err != nil {
		return err
	}
	return sendControlRecord(ctx, session, carrier, payload)
}

func receiveHandshakeControl(ctx context.Context, session *Session, carrier RekeyCarrier, kind RekeyHandshakeKind, generation uint64, binding [32]byte) ([]byte, error) {
	payload, err := receiveControlRecord(ctx, session, carrier)
	if err != nil {
		return nil, err
	}
	control, err := ParseRekeyHandshakeControl(payload, kind, generation, binding)
	return control.Message, err
}

func sendMarker(ctx context.Context, session *Session, carrier RekeyCarrier, transition *RekeyTransition, marker RekeyMarker) error {
	_, err := sendMarkerComplete(ctx, session, carrier, transition, marker)
	return err
}

func sendMarkerComplete(ctx context.Context, session *Session, carrier RekeyCarrier, transition *RekeyTransition, marker RekeyMarker) (bool, error) {
	payload, err := marker.MarshalBinary()
	if err != nil {
		return false, err
	}
	if err := sendControlRecord(ctx, session, carrier, payload); err != nil {
		return false, err
	}
	return transition.Accept(marker)
}

func receiveMarker(ctx context.Context, session *Session, carrier RekeyCarrier, transition *RekeyTransition, binding [32]byte, generation uint64, direction RekeyDirection, kind RekeyMarkerKind) (bool, error) {
	payload, err := receiveControlRecord(ctx, session, carrier)
	if err != nil {
		return false, err
	}
	marker, err := ParseRekeyMarker(payload, binding, direction, kind, generation)
	if err != nil {
		return false, err
	}
	return transition.Accept(marker)
}

func sendControlRecord(ctx context.Context, session *Session, carrier RekeyCarrier, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := session.sealAndSend(ctx, payload, false, true, func(record []byte) error { return carrier.SendRekeyRecord(ctx, record) }); err != nil {
		return fmt.Errorf("send relay E2EE rekey record: %w", err)
	}
	return nil
}

func receiveControlRecord(ctx context.Context, session *Session, carrier RekeyCarrier) ([]byte, error) {
	record, err := carrier.ReceiveRekeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("receive relay E2EE rekey record: %w", err)
	}
	payload, closeAfter, err := session.Open(record)
	if err != nil {
		return nil, err
	}
	if closeAfter {
		clear(payload)
		return nil, errors.New("relay E2EE rekey control closed stream")
	}
	return payload, nil
}
