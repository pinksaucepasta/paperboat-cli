//go:build windows

package windowsopenssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func qualificationSSHShellMarker(client *ssh.Client, marker string) ([]byte, error) {
	if client == nil || marker == "" {
		return nil, ErrInvalidConfig
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	combined := func() []byte { return append(append([]byte(nil), stdout.Bytes()...), stderr.Bytes()...) }
	input, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := session.RequestPty("xterm-256color", 80, 24, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return nil, err
	}
	if err := session.Shell(); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(input, "echo %s\r\nexit\r\n", marker); err != nil {
		return combined(), err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		_ = input.Close()
		if err != nil {
			return combined(), err
		}
	case <-time.After(qualificationProtocolTimeout):
		_ = input.Close()
		_ = session.Close()
		return combined(), context.DeadlineExceeded
	}
	output := combined()
	if !bytes.Contains(output, []byte(marker)) {
		return output, errors.New("SSH PTY output did not contain the required marker")
	}
	return output, nil
}
