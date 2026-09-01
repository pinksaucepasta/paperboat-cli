package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

func TestProductionTunnelAssemblyRequiresExplicitProvider(t *testing.T) {
	if _, err := productionTunnelAssembly(context.Background(), nil, ProductionTunnelAssemblyInputs{}); !errors.Is(err, ErrProductionTunnelAssemblyRequired) {
		t.Fatalf("nil provider error = %v", err)
	}
	if _, err := productionTunnelAssembly(context.Background(), func(context.Context, ProductionTunnelAssemblyInputs) (*tunnelmanager.ProductionAssembly, error) {
		return nil, nil
	}, ProductionTunnelAssemblyInputs{}); !errors.Is(err, ErrProductionTunnelAssemblyUnavailable) {
		t.Fatalf("nil assembly error = %v", err)
	}
}
