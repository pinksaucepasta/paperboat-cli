// Package managedssh owns the local managed OpenSSH identity and agent policy.
package managedssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const MaxSigningPayloadBytes = 64 << 10

var (
	ErrAgentDenied          = errors.New("managed SSH agent request denied")
	ErrAgentRequestTooLarge = errors.New("managed SSH agent signing request is too large")
)

// Agent exposes one managed key and deliberately implements no mutation or
// extension surface. Existing user-agent delegation is composed separately.
type Agent struct {
	signer ssh.Signer
	key    agent.Key
}

func NewAgent(signer ssh.Signer) (*Agent, error) {
	if signer == nil || signer.PublicKey() == nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, ErrAgentDenied
	}
	public := signer.PublicKey()
	return &Agent{signer: signer, key: agent.Key{Format: public.Type(), Blob: append([]byte(nil), public.Marshal()...), Comment: "Paperboat managed SSH key"}}, nil
}

func (a *Agent) List() ([]*agent.Key, error) {
	if a == nil || a.signer == nil {
		return nil, ErrAgentDenied
	}
	key := a.key
	key.Blob = append([]byte(nil), key.Blob...)
	return []*agent.Key{&key}, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a == nil || a.signer == nil || key == nil || flags != 0 || !bytes.Equal(key.Marshal(), a.key.Blob) {
		return nil, ErrAgentDenied
	}
	if len(data) > MaxSigningPayloadBytes {
		return nil, ErrAgentRequestTooLarge
	}
	signature, err := a.signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("sign managed SSH request: %w", err)
	}
	return signature, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	if a == nil || a.signer == nil {
		return nil, ErrAgentDenied
	}
	return []ssh.Signer{a.signer}, nil
}

func (*Agent) Add(agent.AddedKey) error                 { return ErrAgentDenied }
func (*Agent) Remove(ssh.PublicKey) error               { return ErrAgentDenied }
func (*Agent) RemoveAll() error                         { return ErrAgentDenied }
func (*Agent) Lock([]byte) error                        { return ErrAgentDenied }
func (*Agent) Unlock([]byte) error                      { return ErrAgentDenied }
func (*Agent) Extension(string, []byte) ([]byte, error) { return nil, agent.ErrExtensionUnsupported }
