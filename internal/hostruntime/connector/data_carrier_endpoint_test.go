package connector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestDataCarrierEndpointRejectsUnverifiedServerConfig(t *testing.T) {
	_, serverConfig, _ := testDataCarrierCertificates(t)
	base := serverConfig.Clone()
	base.ClientAuth = tls.VerifyClientCertIfGiven
	if err := validateTLSConfig(base, true); !errors.Is(err, ErrDataCarrierTLS) {
		t.Fatalf("weak server client-auth error = %v, want TLS authentication error", err)
	}
}

func TestDataCarrierEndpointPeerBindingRejectsUnexpectedIdentity(t *testing.T) {
	identity := testDataCarrierIdentity()
	expected := identity
	expected.HostID = "host-other"
	endpoint := DataCarrierEndpointConfig{PeerBinding: func(tls.ConnectionState) (DataCarrierIdentity, error) { return identity, nil }, ExpectedIdentity: expected}
	if _, err := bindPeer(endpoint, tls.ConnectionState{}); !errors.Is(err, ErrDataCarrierTLS) {
		t.Fatalf("unexpected peer identity error = %v, want TLS authentication error", err)
	}
}

func TestDataCarrierEndpointClientAuthVerifierRules(t *testing.T) {
	_, serverConfig, _ := testDataCarrierCertificates(t)
	for _, tc := range []struct {
		auth tls.ClientAuthType
		want bool
	}{
		{auth: tls.VerifyClientCertIfGiven, want: true},
		{auth: tls.RequireAnyClientCert, want: false},
	} {
		config := serverConfig.Clone()
		config.ClientAuth = tc.auth
		config.VerifyConnection = func(tls.ConnectionState) error { return nil }
		err := validateTLSConfig(config, true)
		if (err != nil) != tc.want {
			t.Fatalf("client auth %v error = %v, rejected = %v, want rejected %v", tc.auth, err, err != nil, tc.want)
		}
	}
}

func TestDataCarrierEndpointTCPAuthenticatedRoundTrip(t *testing.T) {
	clientTLS, serverTLS, _ := testDataCarrierCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	config := testDataCarrierConfig()
	identity := testDataCarrierIdentity()
	serverResult := make(chan struct {
		carrier *DataCarrier
		err     error
	}, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- struct {
				carrier *DataCarrier
				err     error
			}{err: err}
			return
		}
		tlsConnection := tls.Server(connection, serverTLS.Clone())
		err = tlsConnection.HandshakeContext(ctx)
		if err == nil {
			var carrier *DataCarrier
			carrier, err = NewDataCarrierClient(ctx, tlsConnection, config, identity)
			serverResult <- struct {
				carrier *DataCarrier
				err     error
			}{carrier: carrier, err: err}
			return
		}
		_ = connection.Close()
		serverResult <- struct {
			carrier *DataCarrier
			err     error
		}{err: err}
	}()

	link, err := DialTCPMux(ctx, DataCarrierEndpointConfig{Address: listener.Addr().String(), TLS: clientTLS, PeerBinding: func(tls.ConnectionState) (DataCarrierIdentity, error) { return identity, nil }, ExpectedIdentity: identity})
	if err != nil {
		t.Fatalf("dial TCP carrier: %v", err)
	}
	client, err := NewDataCarrierServer(ctx, link, config, DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, StreamOpen) error { return nil }})
	if err != nil {
		_ = link.Close()
		t.Fatalf("new TCP client carrier: %v", err)
	}
	result := <-serverResult
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("new TCP server carrier: %v", result.err)
	}
	server := result.carrier
	defer client.Close()
	defer server.Close()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("client ping: %v", err)
	}
	open := testDataCarrierStreamOpen("route-a", "endpoint-tcp")
	stream, err := server.OpenStream(ctx, open)
	if err != nil {
		t.Fatalf("edge open TCP stream: %v", err)
	}
	accepted, metadata, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("connector accept TCP stream: %v", err)
	}
	if metadata != open {
		t.Fatalf("TCP metadata = %+v, want %+v", metadata, open)
	}
	const body = "authenticated-tcp-carrier-body"
	if _, err := io.WriteString(stream, body); err != nil {
		t.Fatalf("write TCP body: %v", err)
	}
	_ = stream.Close()
	got, err := io.ReadAll(accepted)
	if err != nil {
		t.Fatalf("read TCP body: %v", err)
	}
	_ = accepted.Close()
	if string(got) != body {
		t.Fatalf("TCP body = %q, want %q", got, body)
	}
}

func TestDataCarrierEndpointQUICAuthenticatedRoundTrip(t *testing.T) {
	clientTLS, serverTLS, _ := testDataCarrierCertificates(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	config := testDataCarrierConfig()
	quicListener, err := quic.Listen(packetConn, serverTLS.Clone(), defaultQUICConfig())
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("listen QUIC: %v", err)
	}
	defer quicListener.Close()

	identity := testDataCarrierIdentity()
	serverResult := make(chan struct {
		carrier *DataCarrier
		err     error
	}, 1)
	go func() {
		connection, err := quicListener.Accept(ctx)
		if err != nil {
			serverResult <- struct {
				carrier *DataCarrier
				err     error
			}{err: err}
			return
		}
		session := newQUICDataCarrierSession(connection)
		carrier, err := NewDataCarrierClientWithSession(ctx, session, config, identity)
		serverResult <- struct {
			carrier *DataCarrier
			err     error
		}{carrier: carrier, err: err}
	}()

	session, err := DialQUIC(ctx, DataCarrierEndpointConfig{Address: quicListener.Addr().String(), TLS: clientTLS, PeerBinding: func(tls.ConnectionState) (DataCarrierIdentity, error) { return identity, nil }, ExpectedIdentity: identity})
	if err != nil {
		t.Fatalf("dial QUIC carrier: %v", err)
	}
	client, err := NewDataCarrierServerWithSession(ctx, session, config, DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, StreamOpen) error { return nil }})
	if err != nil {
		_ = session.Close()
		t.Fatalf("new QUIC client carrier: %v", err)
	}
	result := <-serverResult
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("new QUIC server carrier: %v", result.err)
	}
	server := result.carrier
	defer client.Close()
	defer server.Close()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("client QUIC ping: %v", err)
	}
	open := testDataCarrierStreamOpen("route-a", "endpoint-quic")
	stream, err := server.OpenStream(ctx, open)
	if err != nil {
		t.Fatalf("edge open QUIC stream: %v", err)
	}
	accepted, metadata, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("connector accept QUIC stream: %v", err)
	}
	if metadata != open {
		t.Fatalf("QUIC metadata = %+v, want %+v", metadata, open)
	}
	const body = "independent-quic-stream-body"
	if _, err := io.WriteString(stream, body); err != nil {
		t.Fatalf("write QUIC body: %v", err)
	}
	_ = stream.Close()
	got, err := io.ReadAll(accepted)
	if err != nil {
		t.Fatalf("read QUIC body: %v", err)
	}
	_ = accepted.Close()
	if string(got) != body {
		t.Fatalf("QUIC body = %q, want %q", got, body)
	}
}

func testDataCarrierCertificates(t *testing.T) (clientTLS, serverTLS *tls.Config, pool *x509.CertPool) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "paperboat test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCertificate)
	makeCertificate := func(serial int64, commonName string, dnsNames []string, usages []x509.ExtKeyUsage) tls.Certificate {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate %s key: %v", commonName, err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: usages, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create %s certificate: %v", commonName, err)
		}
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			t.Fatalf("load %s certificate: %v", commonName, err)
		}
		certificate.Certificate = append(certificate.Certificate, caDER)
		return certificate
	}
	serverCertificate := makeCertificate(2, "carrier-server", []string{"localhost"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertificate := makeCertificate(3, "carrier-client", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	serverTLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, NextProtos: []string{DataCarrierALPN}}
	clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCertificate}, RootCAs: pool, ServerName: "localhost", NextProtos: []string{DataCarrierALPN}}
	return clientTLS, serverTLS, pool
}
