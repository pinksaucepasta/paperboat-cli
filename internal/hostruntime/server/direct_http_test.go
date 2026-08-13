package server

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeHTTPConnectionServesUntilDirectStreamCloses(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTPConnection(context.Background(), serverConn, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/v1/file-transfers/id" || request.Header.Get("Authorization") != "Bearer credential" {
				t.Errorf("request path=%q authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
			}
			writer.Header().Set("Upload-Chunk-Ordinal", "4")
			writer.WriteHeader(http.StatusNoContent)
		}))
	}()
	request, _ := http.NewRequest(http.MethodGet, "http://machine/v1/file-transfers/id", nil)
	request.Header.Set("Authorization", "Bearer credential")
	if err := request.Write(clientConn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil || response.StatusCode != http.StatusNoContent || response.Header.Get("Upload-Chunk-Ordinal") != "4" {
		t.Fatalf("response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	_ = clientConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct HTTP server did not stop after stream close")
	}
}
