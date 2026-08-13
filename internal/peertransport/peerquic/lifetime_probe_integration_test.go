package peerquic_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

func TestProbeOnlyQUICCarriesAuthenticatedLifetimeExchange(t *testing.T) {
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.ListenProbe(serverConn, serverTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan *peerquic.Session, 1)
	errors := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			errors <- err
			return
		}
		accepted <- session
	}()
	client, err := peerquic.DialProbe(ctx, clientConn, clientTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-errors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	at, err := client.ProbeAfterIdle(ctx, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if at.IsZero() {
		t.Fatal("probe returned no authenticated observation time")
	}
	idle, err := router.WaitLifetimeProbe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if idle != 10*time.Millisecond {
		t.Fatalf("idle = %s", idle)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("close immediately after published probe completion: %v", err)
	}
}

func TestProbeOnlyQUICProducesAuthenticatedHealthEvidence(t *testing.T) {
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.ListenProbe(serverConn, serverTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan *peerquic.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()
	client, err := peerquic.DialProbe(ctx, clientConn, clientTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	served := make(chan error, 1)
	go func() { served <- server.ServeHealthExchanges(ctx, 3) }()
	for index := range 3 {
		var nonce [16]byte
		nonce[0] = byte(index + 1)
		ptos, err := client.HealthExchange(ctx, nonce)
		if err != nil {
			t.Fatalf("exchange %d: %v", index+1, err)
		}
		if ptos != 0 {
			t.Fatalf("loopback exchange %d reported %d PTOs", index+1, ptos)
		}
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryHealthDoesNotPublishLifetimeEvidence(t *testing.T) {
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.ListenProbe(serverConn, serverTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan *peerquic.Session, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			accepted <- session
		}
	}()
	client, err := peerquic.DialProbe(ctx, clientConn, clientTLS, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	if _, err := client.HealthExchange(ctx, [16]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer waitCancel()
	if idle, err := router.WaitLifetimeProbe(waitCtx); err == nil || idle != 0 {
		t.Fatalf("ordinary health published lifetime idle=%s err=%v", idle, err)
	}
}

func probeTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	issue := func(serial int64, commonName string) tls.Certificate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	clientCertificate := issue(1, "probe-client")
	serverCertificate := issue(2, "probe-server")
	verify := func(tls.ConnectionState) error { return nil }
	client := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{peerquic.ALPN},
		InsecureSkipVerify: true, VerifyConnection: verify, Certificates: []tls.Certificate{clientCertificate},
	}
	server := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{peerquic.ALPN},
		InsecureSkipVerify: true, VerifyConnection: verify, ClientAuth: tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{serverCertificate},
	}
	return client, server
}
