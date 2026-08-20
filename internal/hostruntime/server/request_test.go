package server

import (
	"net"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

func sendRequest(t *testing.T, connection net.Conn, frame protocol.Frame) protocol.Frame {
	t.Helper()
	if err := protocol.WriteFrame(connection, frame); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
