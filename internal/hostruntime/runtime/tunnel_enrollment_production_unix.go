//go:build darwin || linux || windows

package runtime

import (
	"net/http"
	"path/filepath"

	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// newProductionTunnelEnrollmentService composes the connector-add local RPC,
// reference-backed key custody, signed WSS control, TLS/QUIC carrier bootstrap,
// durable tunnel manager, rotation, renewal, drain, and origin readiness under
// the one stable hostd lifecycle.
func newProductionTunnelEnrollmentService(controlURL, stateRoot, hostID, localControlToken string, transport http.RoundTripper) (*ProductionTunnelEnrollment, error) {
	auth, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL, StateRoot: stateRoot, Transport: transport})
	if err != nil {
		return nil, err
	}
	origins, originStreams, err := tunnelmanager.NewOriginRuntime(
		tunnelmanager.CredentialStoreOriginSecretResolver{Store: clientconfig.FileSecretStore{Dir: filepath.Join(stateRoot, "origin-credentials")}},
		false,
		nil,
	)
	if err != nil {
		return nil, err
	}
	source, err := tunnelenrollment.NewHTTPSProductionAssemblySource(tunnelenrollment.HTTPSProductionAssemblySourceConfig{
		ControlURL: controlURL, StateRoot: stateRoot, HostID: hostID, Transport: transport,
		Auth: auth, Clock: productionClock{}, Origins: origins, OriginStreams: originStreams,
	})
	if err != nil {
		return nil, err
	}
	return NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		ControlURL: controlURL, StateRoot: stateRoot, HostID: hostID, ControlToken: localControlToken,
		Transport: transport, Auth: auth, AssemblySource: source,
	})
}
