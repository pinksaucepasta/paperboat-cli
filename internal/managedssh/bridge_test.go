package managedssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct {
		connection *net.TCPConn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		accepted <- struct {
			connection *net.TCPConn
			err        error
		}{connection, acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	result := <-accepted
	_ = listener.Close()
	if result.err != nil {
		_ = client.Close()
		t.Fatal(result.err)
	}
	return result.connection, client
}

func TestProbeAndBridgeSSHUsesOnlySelectedLoopbackTarget(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	accepted := make(chan error, 2)
	go func() {
		for range 2 {
			connection, err := listener.Accept()
			if err != nil {
				accepted <- err
				continue
			}
			go func(connection net.Conn) {
				defer connection.Close()
				value := make([]byte, len("client-request"))
				count, err := io.ReadFull(connection, value)
				if (err == nil || errors.Is(err, io.ErrUnexpectedEOF)) && count > 0 {
					_, err = connection.Write([]byte("server-response"))
				} else if errors.Is(err, io.EOF) {
					err = nil
				}
				accepted <- err
			}(connection)
		}
	}()
	readiness, err := ProbeLoopbackSSH(context.Background(), port, time.Second)
	if err != nil || !readiness.IPv4 || readiness.Target.Host != "127.0.0.1" || readiness.Target.Port != port {
		t.Fatalf("readiness=%+v error=%v", readiness, err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	bridgeSide, clientSide := net.Pipe()
	done := make(chan struct {
		result BridgeResult
		err    error
	}, 1)
	go func() {
		result, err := BridgeSSH(context.Background(), bridgeSide, readiness.Target, time.Second)
		done <- struct {
			result BridgeResult
			err    error
		}{result, err}
	}()
	if _, err := clientSide.Write([]byte("client-request")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("server-response"))
	if _, err := io.ReadFull(clientSide, response); err != nil || string(response) != "server-response" {
		t.Fatalf("response=%q error=%v", response, err)
	}
	_ = clientSide.Close()
	result := <-done
	if result.err != nil || result.result.ToSSHD != int64(len("client-request")) || result.result.FromSSHD != int64(len("server-response")) {
		t.Fatalf("bridge=%+v error=%v", result.result, result.err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestBridgeSSHCancellationAndTargetValidation(t *testing.T) {
	if _, err := NewLoopbackTarget("localhost", 22); !errors.Is(err, ErrSSHTargetInvalid) {
		t.Fatalf("hostname target error=%v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	bridgeSide, clientSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	go func() {
		_, err := BridgeSSH(ctx, bridgeSide, LoopbackTarget{Host: "127.0.0.1", Port: port}, time.Second)
		done <- err
	}()
	connection := <-accepted
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	writeErr := clientSide.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if writeErr == nil {
		_, writeErr = clientSide.Write([]byte{1})
	}
	if !errors.Is(writeErr, io.ErrClosedPipe) {
		t.Fatalf("Paperboat side write error=%v after cancellation", writeErr)
	}
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	if _, err := connection.Read(value[:]); err == nil {
		t.Fatal("sshd side remained readable after cancellation")
	}
	_ = connection.Close()
	_ = clientSide.Close()
}

func TestBridgeSSHPreservesBinaryBytesAndHalfClose(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := []byte{0x00, 0xff, 0x80, 0x7f, '\r', '\n', 0x00, 0x01}
	response := []byte{0xff, 0x00, 0xfe, 0x02, '\n', '\r', 0x80}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		value, readErr := io.ReadAll(connection)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		if !bytes.Equal(value, request) {
			serverDone <- errors.New("sshd received altered bytes")
			return
		}
		_, writeErr := connection.Write(response)
		serverDone <- writeErr
	}()

	bridgeSide, clientSide := tcpPair(t)
	done := make(chan struct {
		result BridgeResult
		err    error
	}, 1)
	go func() {
		result, bridgeErr := BridgeSSH(t.Context(), bridgeSide, LoopbackTarget{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, time.Second)
		done <- struct {
			result BridgeResult
			err    error
		}{result, bridgeErr}
	}()
	if _, err := clientSide.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	value, err := io.ReadAll(clientSide)
	if err != nil || !bytes.Equal(value, response) {
		t.Fatalf("response=%x err=%v", value, err)
	}
	_ = clientSide.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	bridged := <-done
	if bridged.err != nil || bridged.result.ToSSHD != int64(len(request)) || bridged.result.FromSSHD != int64(len(response)) {
		t.Fatalf("bridge=%+v err=%v", bridged.result, bridged.err)
	}
}

func TestBridgeSSHBackpressurePreservesOrder(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := make([]byte, 4<<20)
	for index := range payload {
		payload[index] = byte(index * 31)
	}
	wantDigest := sha256.Sum256(payload)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetReadBuffer(1024)
		time.Sleep(100 * time.Millisecond)
		value, readErr := io.ReadAll(connection)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		if digest := sha256.Sum256(value); digest != wantDigest {
			serverDone <- errors.New("sshd received dropped or reordered bytes")
			return
		}
		_, writeErr := connection.Write(wantDigest[:])
		serverDone <- writeErr
	}()

	bridgeSide, clientSide := tcpPair(t)
	bridgeDone := make(chan error, 1)
	go func() {
		_, bridgeErr := BridgeSSH(t.Context(), bridgeSide, LoopbackTarget{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, time.Second)
		bridgeDone <- bridgeErr
	}()
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(clientSide)
	_ = clientSide.Close()
	if err != nil || !bytes.Equal(reply, wantDigest[:]) {
		t.Fatalf("reply=%x err=%v", reply, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := <-bridgeDone; err != nil {
		t.Fatal(err)
	}
}

func TestBridgeSSHConcurrentStreamsRemainIndependent(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const streams = 8
	serverErrors := make(chan error, streams)
	go func() {
		for range streams {
			connection, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				serverErrors <- acceptErr
				continue
			}
			go func() {
				defer connection.Close()
				value, readErr := io.ReadAll(connection)
				if readErr == nil {
					_, readErr = connection.Write(value)
				}
				serverErrors <- readErr
			}()
		}
	}()

	var wait sync.WaitGroup
	clientErrors := make(chan error, streams)
	bridgeSides := make([]*net.TCPConn, streams)
	clientSides := make([]*net.TCPConn, streams)
	for index := range streams {
		bridgeSides[index], clientSides[index] = tcpPair(t)
	}
	for streamID := range streams {
		wait.Add(1)
		go func() {
			defer wait.Done()
			payload := bytes.Repeat([]byte{byte(streamID), 0x00, 0xff, byte(255 - streamID)}, 4096)
			bridgeSide, clientSide := bridgeSides[streamID], clientSides[streamID]
			bridgeDone := make(chan error, 1)
			go func() {
				_, bridgeErr := BridgeSSH(t.Context(), bridgeSide, LoopbackTarget{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, time.Second)
				bridgeDone <- bridgeErr
			}()
			if _, writeErr := clientSide.Write(payload); writeErr != nil {
				clientErrors <- writeErr
				_ = clientSide.Close()
				return
			}
			if closeErr := clientSide.CloseWrite(); closeErr != nil {
				clientErrors <- closeErr
				_ = clientSide.Close()
				return
			}
			response, readErr := io.ReadAll(clientSide)
			_ = clientSide.Close()
			if readErr == nil && !bytes.Equal(response, payload) {
				readErr = errors.New("concurrent SSH stream crossed or altered bytes")
			}
			clientErrors <- errors.Join(readErr, <-bridgeDone)
		}()
	}
	wait.Wait()
	for range streams {
		if err := <-clientErrors; err != nil {
			t.Fatal(err)
		}
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}
