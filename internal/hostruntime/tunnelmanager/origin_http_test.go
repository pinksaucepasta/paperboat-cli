package tunnelmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

type originSecrets map[string][]byte

func (s originSecrets) ResolveOriginSecret(_ context.Context, reference string) ([]byte, error) {
	value, ok := s[reference]
	if !ok {
		return nil, errors.New("sensitive backend failure for " + reference)
	}
	return append([]byte(nil), value...), nil
}

type observingOriginSecret struct{ payload []byte }

func (s *observingOriginSecret) ResolveOriginSecret(context.Context, string) ([]byte, error) {
	return s.payload, nil
}

type countingOriginDialer struct{ count atomic.Int32 }

func (d *countingOriginDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.count.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

type originPKI struct {
	caPEM     []byte
	serverTLS tls.Certificate
	clientDoc []byte
}

func newOriginPKI(t *testing.T, serverName string) originPKI {
	t.Helper()
	now := time.Now().UTC()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Paperboat test origin CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		certificate, pairErr := tls.X509KeyPair(certPEM, keyPEM)
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		return certificate, certPEM, keyPEM
	}
	server, _, _ := issue(2, serverName, x509.ExtKeyUsageServerAuth)
	_, clientCert, clientKey := issue(3, "paperboat-origin-client", x509.ExtKeyUsageClientAuth)
	document, err := json.Marshal(originClientIdentity{CertificatePEM: string(clientCert), PrivateKeyPEM: string(clientKey)})
	if err != nil {
		t.Fatal(err)
	}
	return originPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), serverTLS: server, clientDoc: document}
}

func httpsOriginRoute(address, serverName string) hoststate.TunnelConfigRoute {
	caRef := "keychain://paperboat/origins/ca_01"
	return hoststate.TunnelConfigRoute{ID: "route_01", Protocol: "http", OriginScheme: "https", OriginAddress: address, PreserveHost: true, TLSVerification: "custom_ca", TLSServerName: &serverName, CAReference: &caRef, ConnectTimeoutMs: 1000, IdleTimeoutMs: 2000, DesiredState: "active"}
}

func TestOriginHTTPTransportCustomCAKeepsHostAndSNIIndependent(t *testing.T) {
	pki := newOriginPKI(t, "origin.internal.test")
	seenHost := ""
	seenInternal := ""
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenHost = request.Host
		seenInternal = request.Header.Get("X-Paperboat-Session")
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverTLS}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	route := httpsOriginRoute(server.Listener.Addr().String(), "origin.internal.test")
	provider := ReferenceOriginTLSProvider{Secrets: originSecrets{*route.CAReference: pki.caPEM}}
	request, _ := http.NewRequest(http.MethodGet, "https://public.example.test/status", nil)
	request.Host = "public.example.test"
	request.Header.Set("X-Paperboat-Session", "must-not-reach-origin")
	response, err := (&OriginHTTPTransport{TLS: provider}).RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || seenHost != "public.example.test" || seenInternal != "" {
		t.Fatalf("status=%d host=%q internal=%q", response.StatusCode, seenHost, seenInternal)
	}
	hostOverride := "backend-vhost.internal.test"
	route.HostOverride = &hostOverride
	request, _ = http.NewRequest(http.MethodGet, "https://public.example.test/status", nil)
	request.Host = "public.example.test"
	response, err = (&OriginHTTPTransport{TLS: provider}).RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if seenHost != hostOverride {
		t.Fatalf("Host=%q, want independent override %q", seenHost, hostOverride)
	}
	wrong := "wrong.internal.test"
	route.TLSServerName = &wrong
	request, _ = http.NewRequest(http.MethodGet, "https://public.example.test/status", nil)
	if _, err := (&OriginHTTPTransport{TLS: provider}).RoundTrip(context.Background(), route, request); !errors.Is(err, ErrOriginUnavailable) {
		t.Fatalf("wrong SNI/hostname error=%v", err)
	}
}

func TestOriginHTTPTransportRequiresConfiguredMTLSIdentity(t *testing.T) {
	pki := newOriginPKI(t, "origin.internal.test")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.caPEM) {
		t.Fatal("append CA")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverTLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	route := httpsOriginRoute(server.Listener.Addr().String(), "origin.internal.test")
	clientRef := "keychain://paperboat/origins/mtls_01"
	route.MTLSCredentialReference = &clientRef
	secrets := originSecrets{*route.CAReference: pki.caPEM, clientRef: pki.clientDoc}
	request, _ := http.NewRequest(http.MethodGet, "https://public.example.test/", nil)
	response, err := (&OriginHTTPTransport{TLS: ReferenceOriginTLSProvider{Secrets: secrets}}).RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	delete(secrets, clientRef)
	request, _ = http.NewRequest(http.MethodGet, "https://public.example.test/", nil)
	_, err = (&OriginHTTPTransport{TLS: ReferenceOriginTLSProvider{Secrets: secrets}}).RoundTrip(context.Background(), route, request)
	if err == nil || strings.Contains(err.Error(), clientRef) || strings.Contains(err.Error(), "sensitive backend") {
		t.Fatalf("missing credential error leaked secret context: %v", err)
	}
}

func TestOriginHTTPTransportInsecureDevelopmentRequiresAuditHook(t *testing.T) {
	pki := newOriginPKI(t, "origin.internal.test")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverTLS}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	route := httpsOriginRoute(server.Listener.Addr().String(), "wrong.internal.test")
	route.TLSVerification, route.CAReference = "insecure_development", nil
	request, _ := http.NewRequest(http.MethodGet, "https://public.example.test/", nil)
	if _, err := (&OriginHTTPTransport{AllowInsecureDevelopment: true}).RoundTrip(context.Background(), route, request); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing audit hook error=%v", err)
	}
	observed := OriginProbeObservation{}
	request, _ = http.NewRequest(http.MethodGet, "https://public.example.test/", nil)
	response, err := (&OriginHTTPTransport{AllowInsecureDevelopment: true, Observe: func(value OriginProbeObservation) { observed = value }}).RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if observed.RouteID != route.ID || observed.Code != OriginProbeInsecureDevelopment {
		t.Fatalf("audit observation=%+v", observed)
	}
}

func TestReferenceOriginTLSProviderClearsResolverOwnedBuffer(t *testing.T) {
	pki := newOriginPKI(t, "origin.internal.test")
	secret := &observingOriginSecret{payload: append([]byte(nil), pki.caPEM...)}
	reference := "keychain://paperboat/origins/ca_01"
	_, err := (ReferenceOriginTLSProvider{Secrets: secret}).TLSConfig(context.Background(), hoststate.TunnelConfigRoute{TLSVerification: "custom_ca", CAReference: &reference})
	if err != nil {
		t.Fatal(err)
	}
	for index, value := range secret.payload {
		if value != 0 {
			t.Fatalf("resolver buffer byte %d was not cleared", index)
		}
	}
}

func TestOriginHTTPTransportReusesConnectionsAndGenerationCloseFencesPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("ok")) }))
	defer server.Close()
	dialer := &countingOriginDialer{}
	base := &OriginHTTPTransport{Dialer: dialer}
	first := base.newGeneration()
	route := hoststate.TunnelConfigRoute{ID: "route_01", Protocol: "http", OriginScheme: "http", OriginAddress: server.Listener.Addr().String(), PreserveHost: true, TLSVerification: "not_applicable", ConnectTimeoutMs: 1000, IdleTimeoutMs: 5000, DesiredState: "active"}
	for range 2 {
		request, _ := http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
		response, err := first.RoundTrip(context.Background(), route, request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	if dialer.count.Load() != 1 {
		t.Fatalf("same generation dials=%d, want keepalive reuse", dialer.count.Load())
	}
	first.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	if _, err := first.RoundTrip(context.Background(), route, request); !errors.Is(err, ErrOriginUnavailable) {
		t.Fatalf("closed generation error=%v", err)
	}
	second := base.newGeneration()
	request, _ = http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	response, err := second.RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	second.CloseIdleConnections()
	if dialer.count.Load() != 2 {
		t.Fatalf("replacement generation dials=%d, want separate policy pool", dialer.count.Load())
	}
}

func TestOriginHTTPTransportUsesRealH2C(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 2 {
			t.Errorf("origin protocol=%s", request.Proto)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	route := hoststate.TunnelConfigRoute{ID: "route_h2c", Protocol: "http", OriginScheme: "h2c", OriginAddress: server.Listener.Addr().String(), PreserveHost: true, TLSVerification: "not_applicable", ConnectTimeoutMs: 1000, IdleTimeoutMs: 5000, DesiredState: "active"}
	transport := (&OriginHTTPTransport{}).newGeneration()
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	response, err := transport.RoundTrip(context.Background(), route, request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusNoContent {
		t.Fatalf("response protocol/status=%s %d", response.Proto, response.StatusCode)
	}
}
