package managedssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrSSHCommandInvalid  = errors.New("managed SSH command request is invalid")
	ErrSSHCommandShutdown = errors.New("managed SSH command did not shut down")
)

const sshCommandShutdownTimeout = 5 * time.Second

// SSHCommandConfig contains the already-authorized inputs for one SSH exec
// request. Input, when non-nil, must be an owned reader whose Close unblocks
// Read. RunSSHCommand closes it on every return path.
type SSHCommandConfig struct {
	Address            string
	User               string
	Command            string
	Signer             ssh.Signer
	AuthorizedHostKeys []string
	Input              io.ReadCloser
	Output             io.Writer
	ErrorOutput        io.Writer
}

type sshCommandHandshake struct {
	connection ssh.Conn
	channels   <-chan ssh.NewChannel
	requests   <-chan *ssh.Request
	err        error
}

// RunSSHCommand opens exactly one pinned SSH connection over stream and runs
// one remote command. It never retries or falls back after the handshake
// starts. Remote *ssh.ExitError values are returned unchanged.
func RunSSHCommand(ctx context.Context, stream io.ReadWriteCloser, config SSHCommandConfig) error {
	if ctx == nil || stream == nil || config.Address == "" || config.User == "" ||
		config.Command == "" || len(config.Command) > 1<<20 ||
		strings.ContainsRune(config.Address, 0) || strings.ContainsRune(config.Command, 0) ||
		ValidateUsername(config.User) != nil || config.Signer == nil ||
		config.Output == nil || config.ErrorOutput == nil {
		closeSSHCommandInput(config.Input)
		if stream != nil {
			_ = stream.Close()
		}
		return ErrSSHCommandInvalid
	}
	keys, err := ParseHostPublicKeys(config.AuthorizedHostKeys)
	if err != nil {
		closeSSHCommandInput(config.Input)
		_ = stream.Close()
		return errors.Join(ErrSSHCommandInvalid, err)
	}
	allowed := make(map[[32]byte]string, len(keys))
	for _, key := range keys {
		allowed[key.Fingerprint] = key.Algorithm
	}
	clientConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(config.Signer)},
		HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
			if actual == nil {
				return ErrKnownHosts
			}
			algorithm, ok := allowed[sha256.Sum256(actual.Marshal())]
			if !ok || algorithm != actual.Type() {
				return ErrKnownHosts
			}
			return nil
		},
	}
	handshakeDone := make(chan sshCommandHandshake, 1)
	go func() {
		connection, channels, requests, handshakeErr := ssh.NewClientConn(sshProbeConn{ReadWriteCloser: stream}, config.Address, clientConfig)
		handshakeDone <- sshCommandHandshake{connection: connection, channels: channels, requests: requests, err: handshakeErr}
	}()
	var handshake sshCommandHandshake
	select {
	case handshake = <-handshakeDone:
	case <-ctx.Done():
		closeSSHCommandInput(config.Input)
		_ = stream.Close()
		if !waitSSHCommandHandshake(handshakeDone) {
			return errors.Join(context.Cause(ctx), ErrSSHCommandShutdown)
		}
		return context.Cause(ctx)
	}
	if handshake.err != nil {
		closeSSHCommandInput(config.Input)
		_ = stream.Close()
		return handshake.err
	}
	client := ssh.NewClient(handshake.connection, handshake.channels, handshake.requests)
	defer closeSSHCommandTransport(client, stream)
	session, err := client.NewSession()
	if err != nil {
		closeSSHCommandInput(config.Input)
		return err
	}
	session.Stdout = config.Output
	session.Stderr = config.ErrorOutput

	var (
		inputDone <-chan error
	)
	if config.Input != nil {
		inputPipe, pipeErr := session.StdinPipe()
		if pipeErr != nil {
			closeSSHCommandInput(config.Input)
			_ = session.Close()
			return pipeErr
		}
		done := make(chan error, 1)
		inputDone = done
		go func() {
			_, copyErr := io.Copy(inputPipe, config.Input)
			closeErr := inputPipe.Close()
			done <- errors.Join(copyErr, closeErr)
		}()
	}

	runDone := make(chan error, 1)
	go func() { runDone <- session.Run(config.Command) }()
	var runErr error
	select {
	case runErr = <-runDone:
	case <-ctx.Done():
		closeSSHCommandInput(config.Input)
		_ = stream.Close()
		_ = session.Close()
		if !waitSSHCommandRun(runDone) || !waitSSHCommandInput(inputDone) {
			return errors.Join(context.Cause(ctx), ErrSSHCommandShutdown)
		}
		return context.Cause(ctx)
	}
	closeSSHCommandInput(config.Input)
	_ = session.Close()
	if !waitSSHCommandInput(inputDone) {
		return errors.Join(runErr, ErrSSHCommandShutdown)
	}
	return runErr
}

func closeSSHCommandInput(input io.ReadCloser) {
	if input != nil {
		_ = input.Close()
	}
}

func closeSSHCommandTransport(client *ssh.Client, stream io.Closer) {
	// Closing the underlying peer stream first makes ssh.Client.Close bounded
	// even when the remote has stopped reading SSH disconnect messages.
	_ = stream.Close()
	_ = client.Close()
}

func waitSSHCommandHandshake(done <-chan sshCommandHandshake) bool {
	timer := time.NewTimer(sshCommandShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func waitSSHCommandRun(done <-chan error) bool {
	timer := time.NewTimer(sshCommandShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func waitSSHCommandInput(done <-chan error) bool {
	if done == nil {
		return true
	}
	timer := time.NewTimer(sshCommandShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
