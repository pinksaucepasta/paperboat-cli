package tunnelenrollment

import (
	"context"
	"errors"
	"math"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// assemblyDrainer binds connector-protocol drain to one exact published
// tunnel/carrier generation. A replacement active generation cannot inherit a
// stale drain request through a manager lookup race.
type assemblyDrainer struct {
	tunnelID    string
	connectorID string

	mu         sync.Mutex
	assembly   *tunnelmanager.ProductionAssembly
	active     tunnelmanager.Active
	carrier    *connector.ActiveDataCarrier
	generation uint64
	hash       string
}

func newAssemblyDrainer(tunnelID, connectorID string) *assemblyDrainer {
	return &assemblyDrainer{tunnelID: tunnelID, connectorID: connectorID}
}

func (d *assemblyDrainer) bind(assembly *tunnelmanager.ProductionAssembly) error {
	if d == nil || assembly == nil || assembly.Manager == nil || assembly.Manager.Manager == nil {
		return ErrActivation
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.assembly != nil && d.assembly != assembly {
		return ErrConflict
	}
	d.assembly = assembly
	return nil
}

func (d *assemblyDrainer) exactCarrierLocked() (tunnelmanager.Active, *connector.ActiveDataCarrier, error) {
	if d.assembly == nil || d.assembly.Manager == nil || d.assembly.Manager.Manager == nil {
		return nil, nil, ErrUnavailable
	}
	active, ok := d.assembly.Manager.Manager.ActiveForTunnel(d.tunnelID)
	if !ok || active == nil || active.ConnectorID() != d.connectorID {
		return nil, nil, ErrUnavailable
	}
	provider, ok := active.(tunnelmanager.ActiveCarrierProvider)
	if !ok || provider.ActiveDataCarrier() == nil {
		return nil, nil, ErrUnavailable
	}
	carrier := provider.ActiveDataCarrier()
	if d.active != nil && (d.active != active || d.carrier != carrier || d.generation != active.Generation() || d.hash != active.ContentHash()) {
		return nil, nil, errors.Join(ErrConflict, tunnelmanager.ErrGenerationConflict)
	}
	return active, carrier, nil
}

func (d *assemblyDrainer) StopNewStreams(ctx context.Context) error {
	if d == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	active, carrier, err := d.exactCarrierLocked()
	if err != nil {
		return err
	}
	if err := carrier.BeginDrain(); err != nil {
		return err
	}
	d.active, d.carrier, d.generation, d.hash = active, carrier, active.Generation(), active.ContentHash()
	return nil
}

func (d *assemblyDrainer) ActiveStreams(ctx context.Context) (uint32, error) {
	if d == nil || ctx == nil {
		return 0, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, carrier, err := d.exactCarrierLocked()
	if err != nil {
		return 0, err
	}
	count := carrier.ActiveStreams()
	if count < 0 || count > math.MaxUint32 {
		return 0, ErrConflict
	}
	return uint32(count), nil
}

func (d *assemblyDrainer) ForceClose(ctx context.Context) error {
	if d == nil || ctx == nil {
		return ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, carrier, err := d.exactCarrierLocked()
	if err != nil {
		return err
	}
	return carrier.Close(ctx)
}
