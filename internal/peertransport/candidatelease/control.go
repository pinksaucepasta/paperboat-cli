package candidatelease

import (
	"context"
	"net"
)

type Control interface {
	OpenCandidateControl(context.Context, []byte) (net.Conn, []byte, error)
}

func Send(ctx context.Context, open func(context.Context, []byte) (net.Conn, []byte, error), message Message) error {
	if ctx == nil || open == nil {
		return ErrProtocol
	}
	payload, err := message.Marshal()
	if err != nil {
		return err
	}
	conn, response, err := open(ctx, payload)
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(response) == 0 {
		return ErrProtocol
	}
	ack, err := Parse(response)
	if err != nil {
		return err
	}
	if ack.Candidate != message.Candidate || ack.LeaseGeneration != message.LeaseGeneration {
		return ErrProtocol
	}
	if message.Type == Adopt && ack.Type != AdoptAck || message.Type == Release && ack.Type != ReleaseAck {
		return ErrProtocol
	}
	return nil
}
