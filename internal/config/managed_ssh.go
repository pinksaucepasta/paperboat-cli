package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const managedSSHKeyComment = "paperboat-managed-ssh-v1"

// ManagedSSHIdentity exposes only signing capability and public registration
// material. The private key remains inside the configured credential store.
type ManagedSSHIdentity struct {
	Signer      ssh.Signer
	PublicKey   string
	Fingerprint [32]byte
	Algorithm   string
}

func (s ProfileStore) ManagedSSHIdentity(issuer, cliClientSessionID string) (identity ManagedSSHIdentity, resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(cliClientSessionID) {
		return ManagedSSHIdentity{}, ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return ManagedSSHIdentity{}, err
	}
	ref := managedSSHSecretRef(issuer, cliClientSessionID)
	lock := newSharedLock(s.profilePath(issuer) + ".managed-ssh.lock")
	return s.managedSSHIdentity(ref, lock)
}

func (s ProfileStore) managedSSHIdentity(ref string, lock credentialLock) (identity ManagedSSHIdentity, resultErr error) {
	if ref == "" || lock == nil {
		return ManagedSSHIdentity{}, ErrCredentialStoreUnavailable
	}
	if err := lock.Lock(); err != nil {
		return ManagedSSHIdentity{}, fmt.Errorf("lock managed SSH identity: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Unlock())
		if resultErr != nil {
			identity = ManagedSSHIdentity{}
		}
	}()
	encoded, err := s.Secrets.Get(ref)
	if err == nil {
		return decodeManagedSSHIdentity(encoded)
	}
	if !errors.Is(err, ErrSecretNotFound) {
		return ManagedSSHIdentity{}, fmt.Errorf("load managed SSH identity: %w", err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ManagedSSHIdentity{}, fmt.Errorf("generate managed SSH identity: %w", err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, managedSSHKeyComment)
	if err != nil {
		return ManagedSSHIdentity{}, fmt.Errorf("encode managed SSH identity: %w", err)
	}
	encoded = string(pem.EncodeToMemory(block))
	identity, err = decodeManagedSSHIdentity(encoded)
	if err != nil {
		return ManagedSSHIdentity{}, err
	}
	if err := s.Secrets.Set(ref, encoded); err != nil {
		return ManagedSSHIdentity{}, fmt.Errorf("store managed SSH identity: %w", err)
	}
	return identity, nil
}

func (s ProfileStore) DeleteManagedSSHIdentity(issuer, cliClientSessionID string) (resultErr error) {
	if s.Path == "" || s.Secrets == nil || !validCredentialID(cliClientSessionID) {
		return ErrCredentialStoreUnavailable
	}
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return err
	}
	lock := newSharedLock(s.profilePath(issuer) + ".managed-ssh.lock")
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("lock managed SSH identity: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Unlock()) }()
	if err := s.Secrets.Delete(managedSSHSecretRef(issuer, cliClientSessionID)); err != nil {
		return fmt.Errorf("delete managed SSH identity: %w", err)
	}
	return nil
}

func decodeManagedSSHIdentity(encoded string) (ManagedSSHIdentity, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return ManagedSSHIdentity{}, errors.New("managed SSH identity is invalid")
	}
	private, err := ssh.ParseRawPrivateKey([]byte(encoded))
	if err != nil {
		return ManagedSSHIdentity{}, errors.New("managed SSH identity is invalid")
	}
	ed25519Private, ok := private.(*ed25519.PrivateKey)
	if !ok || len(*ed25519Private) != ed25519.PrivateKeySize {
		return ManagedSSHIdentity{}, errors.New("managed SSH identity is not Ed25519")
	}
	signer, err := ssh.NewSignerFromKey(*ed25519Private)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return ManagedSSHIdentity{}, errors.New("managed SSH identity is invalid")
	}
	public := signer.PublicKey()
	return ManagedSSHIdentity{
		Signer: signer, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))),
		Fingerprint: sha256.Sum256(public.Marshal()), Algorithm: public.Type(),
	}, nil
}

func managedSSHSecretRef(issuer, cliClientSessionID string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + cliClientSessionID))
	return "managed-ssh-v1-" + hex.EncodeToString(digest[:16])
}

func validCredentialID(value string) bool {
	return len(value) > 0 && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}
