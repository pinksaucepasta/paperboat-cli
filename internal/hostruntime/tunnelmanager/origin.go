package tunnelmanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

// OriginDialer is the context-aware subset of net.Dialer used by readiness
// probes. It is injectable so route activation tests never need local infra.
type OriginDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// OriginTLSProvider resolves write-only CA and client-certificate references.
// Returned configurations are cloned before use and must not disable
// verification; only the explicit insecure_development route mode may do so.
type OriginTLSProvider interface {
	TLSConfig(context.Context, hoststate.TunnelConfigRoute) (*tls.Config, error)
}

// OriginSecretResolver reads a write-only reference from an OS-protected
// credential store. Implementations must never return the reference or secret
// material in an error. The returned bytes are copied and cleared by the TLS
// provider after parsing.
type OriginSecretResolver interface {
	ResolveOriginSecret(context.Context, string) ([]byte, error)
}

type OriginCredentialStore interface {
	Get(string) (string, error)
}

// CredentialStoreOriginSecretResolver adapts the platform keychain,
// Credential Manager, Secret Service, or protected-file store without making
// the origin runtime depend on a concrete OS backend.
type CredentialStoreOriginSecretResolver struct {
	Store OriginCredentialStore
}

func (r CredentialStoreOriginSecretResolver) ResolveOriginSecret(ctx context.Context, reference string) ([]byte, error) {
	if ctx == nil || r.Store == nil {
		return nil, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, err := r.Store.Get(reference)
	if err != nil {
		return nil, errors.New("origin credential store is unavailable")
	}
	return []byte(value), nil
}

// NewOriginRuntime constructs matching probe and request-forwarding policy so
// readiness cannot pass with different TLS settings from live traffic.
func NewOriginRuntime(secrets OriginSecretResolver, allowInsecureDevelopment bool, observe func(OriginProbeObservation)) (NetworkOriginProber, *OriginStreamForwarder, error) {
	if secrets == nil {
		return NetworkOriginProber{}, nil, ErrInvalidConfig
	}
	provider := ReferenceOriginTLSProvider{Secrets: secrets}
	transport := &OriginHTTPTransport{TLS: provider, AllowInsecureDevelopment: allowInsecureDevelopment, Observe: observe}
	prober := NetworkOriginProber{TLS: provider, AllowInsecureDevelopment: allowInsecureDevelopment, Observe: observe}
	return prober, &OriginStreamForwarder{Transport: transport}, nil
}

// ReferenceOriginTLSProvider resolves custom roots and mTLS identities without
// putting PEM material in route state. A client identity is stored as one
// bounded JSON document with certificate_pem and private_key_pem fields.
type ReferenceOriginTLSProvider struct {
	Secrets OriginSecretResolver
}

const maximumOriginTLSSecretBytes = 1 << 20

type originClientIdentity struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

func (p ReferenceOriginTLSProvider) TLSConfig(ctx context.Context, route hoststate.TunnelConfigRoute) (*tls.Config, error) {
	if ctx == nil || p.Secrets == nil {
		return nil, ErrInvalidConfig
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if route.CAReference != nil {
		payload, err := p.resolve(ctx, *route.CAReference)
		if err != nil {
			return nil, err
		}
		defer clear(payload)
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(payload) {
			return nil, errors.Join(ErrInvalidConfig, errors.New("origin CA reference contains no certificates"))
		}
		config.RootCAs = pool
	}
	if route.MTLSCredentialReference != nil {
		payload, err := p.resolve(ctx, *route.MTLSCredentialReference)
		if err != nil {
			return nil, err
		}
		defer clear(payload)
		var identity originClientIdentity
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&identity); err != nil || identity.CertificatePEM == "" || identity.PrivateKeyPEM == "" {
			return nil, errors.Join(ErrInvalidConfig, errors.New("origin mTLS reference is invalid"))
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, errors.Join(ErrInvalidConfig, errors.New("origin mTLS reference is invalid"))
		}
		certificate, err := tls.X509KeyPair([]byte(identity.CertificatePEM), []byte(identity.PrivateKeyPEM))
		identity.CertificatePEM = ""
		identity.PrivateKeyPEM = ""
		if err != nil {
			return nil, errors.Join(ErrInvalidConfig, errors.New("origin mTLS reference is invalid"))
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func (p ReferenceOriginTLSProvider) resolve(ctx context.Context, reference string) ([]byte, error) {
	payload, err := p.Secrets.ResolveOriginSecret(ctx, reference)
	if err != nil {
		clear(payload)
		return nil, errors.Join(ErrOriginUnavailable, errors.New("origin credential reference is unavailable"))
	}
	if len(payload) == 0 || len(payload) > maximumOriginTLSSecretBytes {
		clear(payload)
		return nil, errors.Join(ErrInvalidConfig, errors.New("origin credential reference has invalid size"))
	}
	copy := append([]byte(nil), payload...)
	clear(payload)
	return copy, nil
}

type NetworkOriginProber struct {
	Dialer                   OriginDialer
	TLS                      OriginTLSProvider
	AllowInsecureDevelopment bool
	Observe                  func(OriginProbeObservation)
}

type OriginProbeObservation struct {
	RouteID string
	Code    string
}

const OriginProbeInsecureDevelopment = "insecure_development_tls"

func (p NetworkOriginProber) ProbeOrigin(ctx context.Context, route hoststate.TunnelConfigRoute) error {
	if ctx == nil || route.DesiredState != "active" || route.ConnectTimeoutMs < 100 {
		return ErrInvalidConfig
	}
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(route.ConnectTimeoutMs)*time.Millisecond)
	defer cancel()
	network := "tcp"
	switch route.OriginScheme {
	case "http", "h2c", "tcp":
		if route.TLSVerification != "not_applicable" {
			return ErrInvalidConfig
		}
	case "unix":
		if route.TLSVerification != "not_applicable" {
			return ErrInvalidConfig
		}
		network = "unix"
	case "https":
		switch route.TLSVerification {
		case "system", "custom_ca":
		case "insecure_development":
			if !p.AllowInsecureDevelopment || p.Observe == nil {
				return ErrInvalidConfig
			}
			p.Observe(OriginProbeObservation{RouteID: route.ID, Code: OriginProbeInsecureDevelopment})
		default:
			return ErrInvalidConfig
		}
	default:
		return ErrInvalidConfig
	}
	connection, err := dialer.DialContext(probeCtx, network, route.OriginAddress)
	if err != nil {
		return errors.Join(ErrOriginUnavailable, err)
	}
	defer connection.Close()
	if err := probeCtx.Err(); err != nil {
		return errors.Join(ErrOriginUnavailable, err)
	}
	if route.OriginScheme != "https" {
		return nil
	}
	config, err := p.originTLSConfig(probeCtx, route)
	if err != nil {
		return errors.Join(ErrOriginUnavailable, err)
	}
	tlsConnection := tls.Client(connection, config)
	if err := tlsConnection.HandshakeContext(probeCtx); err != nil {
		return errors.Join(ErrOriginUnavailable, err)
	}
	return nil
}

func (p NetworkOriginProber) originTLSConfig(ctx context.Context, route hoststate.TunnelConfigRoute) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	needsProvider := route.CAReference != nil || route.MTLSCredentialReference != nil
	if needsProvider {
		if p.TLS == nil {
			return nil, ErrInvalidConfig
		}
		resolved, err := p.TLS.TLSConfig(ctx, route)
		if err != nil || resolved == nil {
			if err == nil {
				err = ErrInvalidConfig
			}
			return nil, err
		}
		config = resolved.Clone()
		if config.MinVersion == 0 || config.MinVersion < tls.VersionTLS12 {
			config.MinVersion = tls.VersionTLS12
		}
		if config.InsecureSkipVerify {
			return nil, ErrInvalidConfig
		}
		if route.TLSVerification == "custom_ca" && config.RootCAs == nil {
			return nil, ErrInvalidConfig
		}
		if route.MTLSCredentialReference != nil && len(config.Certificates) == 0 && config.GetClientCertificate == nil {
			return nil, ErrInvalidConfig
		}
	}
	if route.TLSVerification == "custom_ca" && route.CAReference == nil {
		return nil, ErrInvalidConfig
	}
	if route.TLSVerification != "custom_ca" && route.CAReference != nil {
		return nil, ErrInvalidConfig
	}
	if route.TLSVerification == "insecure_development" {
		// This is deliberately limited to the explicit development-only mode.
		config.InsecureSkipVerify = true //nolint:gosec
	}
	if route.TLSServerName != nil {
		config.ServerName = *route.TLSServerName
	} else if host, _, err := net.SplitHostPort(route.OriginAddress); err == nil {
		config.ServerName = strings.Trim(host, "[]")
	}
	return config, nil
}

var _ OriginProber = NetworkOriginProber{}
