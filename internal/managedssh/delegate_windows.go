//go:build windows

package managedssh

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type DelegatedAgent struct {
	connection net.Conn
	client     agent.ExtendedAgent
	timeout    time.Duration
	mutex      sync.Mutex
}

func DialOwnerAgent(path, aggregatePath string, timeout time.Duration) (*DelegatedAgent, error) {
	if !isDelegableWindowsAgentPipe(path) || !validWindowsAgentPipe(aggregatePath) || strings.EqualFold(path, aggregatePath) || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrAgentDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		return nil, errors.Join(ErrAgentDenied, err)
	}
	return &DelegatedAgent{connection: connection, client: agent.NewClient(connection), timeout: timeout}, nil
}
func (d *DelegatedAgent) Close() error {
	if d == nil || d.connection == nil {
		return nil
	}
	return d.connection.Close()
}
func (d *DelegatedAgent) List() (keys []*agent.Key, err error) {
	err = d.call(func() error { keys, err = d.client.List(); return err })
	return keys, err
}
func (d *DelegatedAgent) Sign(key ssh.PublicKey, data []byte) (signature *ssh.Signature, err error) {
	err = d.call(func() error { signature, err = d.client.Sign(key, data); return err })
	return signature, err
}
func (d *DelegatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (signature *ssh.Signature, err error) {
	err = d.call(func() error { signature, err = d.client.SignWithFlags(key, data, flags); return err })
	return signature, err
}
func (d *DelegatedAgent) Signers() ([]ssh.Signer, error) {
	keys, err := d.List()
	if err != nil {
		return nil, err
	}
	result := make([]ssh.Signer, 0, len(keys))
	for _, key := range keys {
		public, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			return nil, ErrAgentDenied
		}
		result = append(result, delegatedSigner{delegate: d, public: public})
	}
	return result, nil
}
func (*DelegatedAgent) Add(agent.AddedKey) error   { return ErrAgentDenied }
func (*DelegatedAgent) Remove(ssh.PublicKey) error { return ErrAgentDenied }
func (*DelegatedAgent) RemoveAll() error           { return ErrAgentDenied }
func (*DelegatedAgent) Lock([]byte) error          { return ErrAgentDenied }
func (*DelegatedAgent) Unlock([]byte) error        { return ErrAgentDenied }
func (*DelegatedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
func (d *DelegatedAgent) call(fn func() error) error {
	if d == nil || d.connection == nil {
		return ErrAgentDenied
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if err := d.connection.SetDeadline(time.Now().Add(d.timeout)); err != nil {
		return err
	}
	return fn()
}

type delegatedSigner struct {
	delegate *DelegatedAgent
	public   ssh.PublicKey
}

func (s delegatedSigner) PublicKey() ssh.PublicKey { return s.public }
func (s delegatedSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.delegate.Sign(s.public, data)
}
