//go:build windows

package managedssh

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

const (
	loopbackOwnerHelperRole = "PAPERBOAT_TEST_LOOPBACK_OWNER_ROLE"
	loopbackOwnerHelperPort = "PAPERBOAT_TEST_LOOPBACK_OWNER_PORT"
)

func TestVerifyWindowsSSHLoopbackOwnerMatchesExactClientPID(t *testing.T) {
	if os.Getenv(loopbackOwnerHelperRole) == "client" {
		port, err := strconv.Atoi(os.Getenv(loopbackOwnerHelperPort))
		if err != nil {
			panic(err)
		}
		connection, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			panic(err)
		}
		defer connection.Close()
		for {
			time.Sleep(time.Hour)
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	command := exec.Command(os.Args[0], "-test.run=^TestVerifyWindowsSSHLoopbackOwnerMatchesExactClientPID$")
	command.Env = append(os.Environ(), loopbackOwnerHelperRole+"=client", loopbackOwnerHelperPort+"="+strconv.Itoa(port))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	proxy, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pid := uint32(command.Process.Pid)
	if err := verifyWindowsSSHLoopbackOwner(t.Context(), proxy, pid); err != nil {
		t.Fatalf("exact owner error=%v", err)
	}
	wrongPID := uint32(os.Getpid())
	if err := verifyWindowsSSHLoopbackOwner(t.Context(), proxy, wrongPID); !errors.Is(err, ErrSSHLoopbackOwner) {
		t.Fatalf("wrong owner error=%v", err)
	}
}

func TestWindowsTCPAddressAndPortDecodeNetworkOrder(t *testing.T) {
	if got := windowsTCPAddress(0x0100007f); got != [4]byte{127, 0, 0, 1} {
		t.Fatalf("address=%v", got)
	}
	if got := windowsTCPPort(0x000000c0); got != 49152 {
		t.Fatalf("port=%d", got)
	}
}
