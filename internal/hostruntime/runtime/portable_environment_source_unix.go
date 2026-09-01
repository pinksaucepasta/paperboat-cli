//go:build darwin || linux || windows

package runtime

import (
	"errors"
	"path/filepath"
	"runtime"

	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

// newPortableEnvironmentKeySource binds portable ENV custody to the existing
// local machine identity. The identity store is the only root-key provider;
// no environment variable, setup flag, mounted credential, or server value is
// accepted here.
func newPortableEnvironmentKeySource(stateRoot string, registration runtimeidentity.Registration) (environmentkey.Source, error) {
	if !filepath.IsAbs(stateRoot) || registration.InstallationGeneration < 1 {
		return nil, ErrProductionInvalid
	}
	identityStore, err := runtimeidentity.Open(runtimeidentity.Config{StateRoot: filepath.Clean(stateRoot)})
	if err != nil {
		return nil, err
	}
	source, err := environmentkey.NewPortableSource(environmentkey.PortableConfig{
		StateRoot: filepath.Clean(stateRoot), MachineID: registration.MachineID,
		Generation: uint64(registration.InstallationGeneration),
	}, identityStore)
	if err != nil {
		return nil, errors.Join(ErrProductionInvalid, err)
	}
	return source, nil
}

// productionEnvironmentKeySourceForState uses the desktop Secret Service when
// it is actually reachable. Headless Linux uses the identity-wrapped portable
// store because the systemd credential is intentionally immutable at runtime,
// while ENV genesis has a monotonic prepare/commit marker that must survive
// restarts in the same authenticated custody record. OCI and Firecracker guests
// take the same branch without any setup input.
func productionEnvironmentKeySourceForState(stateRoot string, registration runtimeidentity.Registration) (environmentkey.Source, error) {
	if runtime.GOOS != "linux" {
		return productionEnvironmentKeySource(registration), nil
	}
	if clientconfig.CredentialStoreAvailable() {
		return environmentkey.KeyringSource{
			Store: clientconfig.KeyringStore{}, MachineID: registration.MachineID,
			Generation: uint64(registration.InstallationGeneration),
			NotFound:   func(err error) bool { return errors.Is(err, clientconfig.ErrSecretNotFound) },
		}, nil
	}
	return newPortableEnvironmentKeySource(stateRoot, registration)
}
