package runtime

import (
	"context"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	stablehostd "github.com/pinksaucepasta/paperboat/internal/hostruntime/hostd"
)

type identityTunnelWorkloads struct {
	identity string
}

func (*identityTunnelWorkloads) Start(context.Context) error    { return nil }
func (*identityTunnelWorkloads) Shutdown(context.Context) error { return nil }
func (*identityTunnelWorkloads) ResourceCounts() map[string]uint64 {
	return map[string]uint64{"tunnels": 1}
}
func (w *identityTunnelWorkloads) WorkloadIdentities() []string { return []string{w.identity} }

type workloadTestService struct{}

func (workloadTestService) Start(context.Context) error    { return nil }
func (workloadTestService) Shutdown(context.Context) error { return nil }

func TestWorkloadStatusAdvancesWhenTunnelIdentityChangesAtSameCount(t *testing.T) {
	tunnels := &identityTunnelWorkloads{identity: "tunnel_01\x00connector_01\x001"}
	daemon, err := stablehostd.New(stablehostd.Config{
		Workloads:  stablehostd.Workloads{Transfers: &filetransfer.Service{}, Tunnels: tunnels},
		Components: []stablehostd.Component{{Name: "test", Required: true, Service: workloadTestService{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{hostd: daemon}
	first := host.WorkloadStatus()
	tunnels.identity = "tunnel_02\x00connector_02\x001"
	second := host.WorkloadStatus()
	if first.Protected != 1 || second.Protected != 1 || second.Generation != first.Generation+1 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}
