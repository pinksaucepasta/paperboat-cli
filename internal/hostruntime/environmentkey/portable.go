package environmentkey

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
)

// PortableCredentialPath is relative to the runtime state root. The file is
// an authenticated ciphertext envelope, not a credential that callers mount
// or provide through an environment variable.
const PortableCredentialPath = "environment/host-key.sealed"

// PortableConfig describes the local identity binding for portable host-key
// custody. The wrapping key is obtained from the identity object passed to
// NewPortableSource; it is never read from user configuration or the server.
type PortableConfig struct {
	StateRoot  string
	MachineID  string
	Generation uint64
	Random     io.Reader
}

// EnvironmentWrappingKeyProvider is implemented by the local machine
// identity store. Keeping this narrow interface here avoids exposing private
// identity bytes or accepting a user-supplied wrapping secret.
type EnvironmentWrappingKeyProvider interface {
	EnvironmentWrappingKey() ([32]byte, error)
}

// PortableSource provides the same Source and GenesisMarker contract as the
// native secure-store source while keeping its ciphertext in the runtime's
// default writable state. It is suitable for prebuilt OCI images and a
// Firecracker guest disk when that state is retained across restarts.
type PortableSource struct {
	keyring KeyringSource
}

// NewPortableSource creates a source bound to one local machine identity and
// installation generation. A missing sealed file creates a new dedicated
// X25519 ENV recipient key. A present file must decrypt and authenticate with
// the same identity-derived wrapping key; it is never silently replaced.
func NewPortableSource(config PortableConfig, identity EnvironmentWrappingKeyProvider) (*PortableSource, error) {
	if !filepath.IsAbs(config.StateRoot) || !validIdentity(config.MachineID) || config.Generation == 0 || identity == nil {
		return nil, ErrInvalid
	}
	config.StateRoot = filepath.Clean(config.StateRoot)
	if config.Random == nil {
		config.Random = rand.Reader
	}
	wrapping, err := identity.EnvironmentWrappingKey()
	if err != nil || isZeroKey(wrapping) {
		return nil, errors.Join(ErrInvalid, err)
	}
	store, err := newPortableStore(config, wrapping)
	if err != nil {
		return nil, err
	}
	return &PortableSource{keyring: KeyringSource{
		Store:      store,
		MachineID:  config.MachineID,
		Generation: config.Generation,
		Random:     config.Random,
		NotFound:   func(err error) bool { return errors.Is(err, ErrSecretNotFound) },
	}}, nil
}

func (s *PortableSource) Load(ctx context.Context) (Material, error) {
	if s == nil {
		return Material{}, ErrInvalid
	}
	return s.keyring.Load(ctx)
}

func (s *PortableSource) GenesisState() (GenesisState, error) {
	if s == nil {
		return "", ErrInvalid
	}
	return s.keyring.GenesisState()
}

func (s *PortableSource) PrepareGenesis() error {
	if s == nil {
		return ErrInvalid
	}
	return s.keyring.PrepareGenesis()
}

func (s *PortableSource) CommitGenesis() error {
	if s == nil {
		return ErrInvalid
	}
	return s.keyring.CommitGenesis()
}

func isZeroKey(key [32]byte) bool {
	var zero [32]byte
	return key == zero
}
