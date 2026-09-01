package connector

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
)

var ErrDataCarrierControlRunner = errors.New("invalid data carrier control runner")

const defaultControlWriteWait = 10 * time.Second

// DataCarrierControlRunnerConfig attaches the canonical connectorrotation
// control state machine to one authenticated, long-lived data-carrier control
// stream. Rotation, renewal, heartbeat, drain, recovery, and regular
// snapshot promotion all remain owned by ControlSession.
type DataCarrierControlRunnerConfig struct {
	Control   *connectorrotation.ControlSession
	WriteWait time.Duration
}

// DataCarrierControlRunner is deliberately a transport adapter only. It does
// not decode, apply, acknowledge, or promote protocol frames itself.
type DataCarrierControlRunner struct {
	control   *connectorrotation.ControlSession
	writeWait time.Duration
}

func NewDataCarrierControlRunner(config DataCarrierControlRunnerConfig) (*DataCarrierControlRunner, error) {
	if config.Control == nil || !config.Control.HasSnapshotReadiness() {
		return nil, ErrDataCarrierControlRunner
	}
	if config.WriteWait == 0 {
		config.WriteWait = defaultControlWriteWait
	}
	if config.WriteWait <= 0 || config.WriteWait > time.Minute {
		return nil, ErrDataCarrierControlRunner
	}
	return &DataCarrierControlRunner{control: config.Control, writeWait: config.WriteWait}, nil
}

// Control returns the one canonical state machine attached to this runner.
func (r *DataCarrierControlRunner) Control() *connectorrotation.ControlSession {
	if r == nil {
		return nil
	}
	return r.control
}

// Session returns the underlying connector-v1 client state for runtime
// inspection. Callers must not run a second frame loop against it.
func (r *DataCarrierControlRunner) Session() *connectorprotocol.ClientSession {
	if r == nil || r.control == nil {
		return nil
	}
	return r.control.Session()
}

// Run delegates every frame to connectorrotation.ControlSession.Serve. The
// wrapper serializes writes and applies a bounded write deadline where the
// carrier exposes one. Connector-v1 ReadFrame enforces its protocol frame
// limit, and ControlSession closes the carrier on context cancellation so no
// blocked read or permit survives shutdown.
func (r *DataCarrierControlRunner) Run(ctx context.Context, carrier io.ReadWriteCloser, helloRequestID string) error {
	if r == nil || r.control == nil || ctx == nil || carrier == nil {
		return ErrDataCarrierControlRunner
	}
	return r.control.Serve(ctx, &boundedControlCarrier{ReadWriteCloser: carrier, writeWait: r.writeWait}, helloRequestID)
}

type boundedControlCarrier struct {
	io.ReadWriteCloser
	writeWait time.Duration
	writeMu   sync.Mutex
}

func (c *boundedControlCarrier) Write(payload []byte) (int, error) {
	if c == nil || c.ReadWriteCloser == nil {
		return 0, ErrDataCarrierControlRunner
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	deadline := time.Now().Add(c.writeWait)
	if setter, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := setter.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		defer setter.SetWriteDeadline(time.Time{})
	}
	return c.ReadWriteCloser.Write(payload)
}
