package managedssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrSSHAuthentication = errors.New("managed SSH authentication is unavailable")

// ProbeSSHAuthentication completes only the SSH transport and user-auth phases.
// It opens no session, shell, command, subsystem, or forwarding channel.
func ProbeSSHAuthentication(ctx context.Context, stream io.ReadWriteCloser, address, user string, signer ssh.Signer, authorizedHostKeys []string) error {
	if ctx == nil || stream == nil || address == "" || user == "" || signer == nil || len(authorizedHostKeys) == 0 {
		return ErrSSHAuthentication
	}
	hostKeys, err := ParseHostPublicKeys(authorizedHostKeys)
	if err != nil {
		return errors.Join(ErrSSHAuthentication, err)
	}
	allowed := make([][32]byte, len(hostKeys))
	for index := range hostKeys {
		allowed[index] = hostKeys[index].Fingerprint
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if slices.Contains(allowed, sha256.Sum256(key.Marshal())) {
				return nil
			}
			return ErrKnownHosts
		},
	}
	type result struct {
		connection ssh.Conn
		err        error
	}
	results := make(chan result, 1)
	go func() {
		connection, _, _, handshakeErr := ssh.NewClientConn(sshProbeConn{ReadWriteCloser: stream}, address, config)
		results <- result{connection: connection, err: handshakeErr}
	}()
	select {
	case outcome := <-results:
		if outcome.connection != nil {
			_ = outcome.connection.Close()
		}
		if outcome.err != nil {
			return errors.Join(ErrSSHAuthentication, outcome.err)
		}
		return nil
	case <-ctx.Done():
		_ = stream.Close()
		return errors.Join(ErrSSHAuthentication, context.Cause(ctx))
	}
}

type sshProbeConn struct{ io.ReadWriteCloser }

func (sshProbeConn) LocalAddr() net.Addr              { return sshProbeAddress("local") }
func (sshProbeConn) RemoteAddr() net.Addr             { return sshProbeAddress("remote") }
func (sshProbeConn) SetDeadline(time.Time) error      { return nil }
func (sshProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (sshProbeConn) SetWriteDeadline(time.Time) error { return nil }

type sshProbeAddress string

func (sshProbeAddress) Network() string  { return "paperboat" }
func (a sshProbeAddress) String() string { return string(a) }
