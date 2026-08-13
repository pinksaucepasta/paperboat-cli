package managedssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrSSHTargetInvalid     = errors.New("managed SSH target is invalid")
	ErrSSHTargetUnavailable = errors.New("managed SSH loopback target is unavailable")
)

type LoopbackTarget struct {
	Host string
	Port uint16
}

type SSHReadiness struct {
	IPv4   bool
	IPv6   bool
	Target LoopbackTarget
}

type BridgeResult struct {
	ToSSHD   int64
	FromSSHD int64
}

func NewLoopbackTarget(host string, port uint16) (LoopbackTarget, error) {
	if port == 0 || host != "127.0.0.1" && host != "::1" {
		return LoopbackTarget{}, ErrSSHTargetInvalid
	}
	return LoopbackTarget{Host: host, Port: port}, nil
}

func ProbeLoopbackSSH(ctx context.Context, port uint16, timeout time.Duration) (SSHReadiness, error) {
	if ctx == nil || port == 0 || timeout <= 0 || timeout > 30*time.Second {
		return SSHReadiness{}, ErrSSHTargetInvalid
	}
	type probe struct {
		host string
		err  error
	}
	results := make(chan probe, 2)
	for _, host := range []string{"127.0.0.1", "::1"} {
		go func(host string) {
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if err == nil {
				err = connection.Close()
			}
			results <- probe{host: host, err: err}
		}(host)
	}
	var readiness SSHReadiness
	for range 2 {
		result := <-results
		if result.err != nil {
			continue
		}
		if result.host == "127.0.0.1" {
			readiness.IPv4 = true
		} else {
			readiness.IPv6 = true
		}
	}
	selected := ""
	if readiness.IPv4 {
		selected = "127.0.0.1"
	} else if readiness.IPv6 {
		selected = "::1"
	}
	if selected == "" {
		return readiness, ErrSSHTargetUnavailable
	}
	readiness.Target = LoopbackTarget{Host: selected, Port: port}
	return readiness, nil
}

func BridgeSSH(ctx context.Context, stream io.ReadWriteCloser, target LoopbackTarget, dialTimeout time.Duration) (BridgeResult, error) {
	if ctx == nil || stream == nil || dialTimeout <= 0 || dialTimeout > 30*time.Second {
		return BridgeResult{}, ErrSSHTargetInvalid
	}
	if _, err := NewLoopbackTarget(target.Host, target.Port); err != nil {
		return BridgeResult{}, err
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	sshd, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
	cancelDial()
	if err != nil {
		if ctx.Err() != nil {
			return BridgeResult{}, context.Cause(ctx)
		}
		return BridgeResult{}, fmt.Errorf("%w: %w", ErrSSHTargetUnavailable, err)
	}
	defer sshd.Close()
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = sshd.Close()
		_ = stream.Close()
	})
	defer stop()
	type copyResult struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan copyResult, 2)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			_ = sshd.Close()
			_ = stream.Close()
		})
	}
	go func() {
		count, err := io.Copy(sshd, stream)
		err = normalizeBridgeError(err)
		if tcp, ok := sshd.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		if err != nil {
			finish()
		}
		results <- copyResult{direction: "to_sshd", bytes: count, err: err}
	}()
	go func() {
		count, err := io.Copy(stream, sshd)
		err = normalizeBridgeError(err)
		if half, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			finish()
		}
		if err != nil {
			finish()
		}
		results <- copyResult{direction: "from_sshd", bytes: count, err: err}
	}()
	var result BridgeResult
	var resultErr error
	for range 2 {
		copied := <-results
		if copied.direction == "to_sshd" {
			result.ToSSHD = copied.bytes
		} else {
			result.FromSSHD = copied.bytes
		}
		resultErr = errors.Join(resultErr, copied.err)
	}
	finish()
	if ctx.Err() != nil {
		return result, context.Cause(ctx)
	}
	return result, resultErr
}

func normalizeBridgeError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var operation *net.OpError
	if errors.As(err, &operation) && errors.Is(operation.Err, net.ErrClosed) {
		return nil
	}
	return err
}
