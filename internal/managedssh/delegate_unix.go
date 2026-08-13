//go:build darwin || linux

package managedssh

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == filepath.Clean(aggregatePath) || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrAgentDenied
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 || stat.Uid != uint32(os.Getuid()) {
		return nil, ErrAgentDenied
	}
	connection, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	connectedInfo, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(info, connectedInfo) {
		_ = connection.Close()
		return nil, ErrAgentDenied
	}
	client := agent.NewClient(connection)
	return &DelegatedAgent{connection: connection, client: client, timeout: timeout}, nil
}

func (d *DelegatedAgent) Close() error { return d.connection.Close() }

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
