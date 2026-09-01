package windowsopenssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

const qualificationProtocolTimeout = 15 * time.Second

// qualificationSSHClient opens a fresh, pinned-host-key SSH connection. It
// deliberately does not invoke ssh.exe: Win32 OpenSSH 10 can leave redirected
// output handles open after a valid remote exit-status.
func qualificationSSHClient(ctx context.Context, address, user string, signer ssh.Signer, hostKey ssh.PublicKey) (*ssh.Client, error) {
	if ctx == nil || address == "" || user == "" || signer == nil || hostKey == nil {
		return nil, ErrInvalidConfig
	}
	dialCtx, cancel := context.WithTimeout(ctx, qualificationProtocolTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(qualificationProtocolTimeout)
	if value, ok := dialCtx.Deadline(); ok {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
			if actual == nil || !bytes.Equal(actual.Marshal(), hostKey.Marshal()) {
				return errors.New("Paperboat SSH host key does not match the pinned host key")
			}
			return nil
		},
		Timeout: qualificationProtocolTimeout,
	})
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = clientConnection.Close()
		return nil, err
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}

func qualificationSSHExec(client *ssh.Client, command string, requestPTY bool) ([]byte, int, error) {
	if client == nil || command == "" {
		return nil, -1, ErrInvalidConfig
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	combined := func() []byte { return append(append([]byte(nil), stdout.Bytes()...), stderr.Bytes()...) }
	if requestPTY {
		if err := session.RequestPty("xterm-256color", 80, 24, ssh.TerminalModes{}); err != nil {
			return combined(), -1, err
		}
	}
	err = session.Run(command)
	if err == nil {
		return combined(), 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return combined(), exitErr.ExitStatus(), nil
	}
	return combined(), -1, err
}

func qualificationSSHMarker(client *ssh.Client, command, marker string, requestPTY bool) error {
	output, status, err := qualificationSSHExec(client, command, requestPTY)
	if err != nil {
		return err
	}
	if status != 0 || !bytes.Contains(output, []byte(marker)) {
		return fmt.Errorf("SSH command result did not contain required marker or success status: status=%d output=%q", status, output)
	}
	return nil
}
