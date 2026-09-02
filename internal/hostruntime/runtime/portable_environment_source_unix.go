//go:build darwin || linux || windows

package runtime

import (
	"errors"
	"os"
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

// productionEnvironmentKeySourceForState uses a desktop credential store only
// on Windows. Linux and macOS host runtimes can start before login, where a
// Secret Service or login Keychain is unavailable. They use the
// identity-wrapped portable store so ENV genesis survives those restarts in
// the same authenticated custody record.
func productionEnvironmentKeySourceForState(stateRoot string, registration runtimeidentity.Registration) (environmentkey.Source, error) {
	if runtime.GOOS == "windows" {
		return productionEnvironmentKeySource(registration), nil
	}
	if runtime.GOOS == "darwin" {
		return newPortableEnvironmentKeySource(stateRoot, registration)
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

func resetLegacyEnvironmentCacheForPortableSource(stateRoot string) error {
	if runtime.GOOS != "darwin" || !filepath.IsAbs(stateRoot) {
		return nil
	}
	for _, name := range []string{"environment/cache.json", "environment-high-water.json"} {
		path := filepath.Join(filepath.Clean(stateRoot), name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
