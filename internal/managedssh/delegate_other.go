//go:build !darwin && !linux

package managedssh

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type DelegatedAgent struct{}

func DialOwnerAgent(string, string, time.Duration) (*DelegatedAgent, error) {
	return nil, errors.New("SSH agent delegation is unsupported on this platform")
}

func (*DelegatedAgent) Close() error                { return nil }
func (*DelegatedAgent) List() ([]*agent.Key, error) { return nil, ErrAgentDenied }
func (*DelegatedAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, ErrAgentDenied
}
func (*DelegatedAgent) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, ErrAgentDenied
}
func (*DelegatedAgent) Signers() ([]ssh.Signer, error) { return nil, ErrAgentDenied }
func (*DelegatedAgent) Add(agent.AddedKey) error       { return ErrAgentDenied }
func (*DelegatedAgent) Remove(ssh.PublicKey) error     { return ErrAgentDenied }
func (*DelegatedAgent) RemoveAll() error               { return ErrAgentDenied }
func (*DelegatedAgent) Lock([]byte) error              { return ErrAgentDenied }
func (*DelegatedAgent) Unlock([]byte) error            { return ErrAgentDenied }
func (*DelegatedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
