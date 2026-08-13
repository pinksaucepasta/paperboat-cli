package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 || len(os.Args) == 3 && os.Args[2] != "post" && os.Args[2] != "pipe" {
		fmt.Fprintln(os.Stderr, "usage: http3-probe URL [post|pipe]")
		os.Exit(2)
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	method := http.MethodGet
	var body *bytes.Reader
	if len(os.Args) == 3 && (os.Args[2] == "post" || os.Args[2] == "pipe") {
		method = http.MethodPost
		if os.Args[2] == "pipe" {
			reader, writer := io.Pipe()
			go func() {
				_, _ = writer.Write([]byte{'P', 'B', 'P', 'R', 1})
				_, _ = writer.Write([]byte("x"))
				_ = writer.Close()
			}()
			requestBody := io.MultiReader(bytes.NewReader([]byte{'P', 'B', 'P', 'R', 1}), reader)
			request, err := http.NewRequestWithContext(ctx, method, os.Args[1], requestBody)
			if err != nil {
				panic(err)
			}
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("X-Paperboat-Connector-Admission", "invalid")
			started := time.Now()
			response, err := transport.RoundTrip(request)
			if err != nil {
				fmt.Fprintf(os.Stderr, "duration=%s error=%v\n", time.Since(started), err)
				os.Exit(1)
			}
			defer response.Body.Close()
			fmt.Printf("duration=%s protocol=%s status=%d\n", time.Since(started), response.Proto, response.StatusCode)
			return
		}
		body = bytes.NewReader([]byte{'P', 'B', 'P', 'R', 1})
	} else {
		body = bytes.NewReader(nil)
	}
	request, err := http.NewRequestWithContext(ctx, method, os.Args[1], body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("X-Paperboat-Connector-Admission", "invalid")
	}
	started := time.Now()
	response, err := transport.RoundTrip(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "duration=%s error=%v\n", time.Since(started), err)
		os.Exit(1)
	}
	defer response.Body.Close()
	fmt.Printf("duration=%s protocol=%s status=%d\n", time.Since(started), response.Proto, response.StatusCode)
}
