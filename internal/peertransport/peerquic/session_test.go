package peerquic

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestTLSBoundaryRejectsUnpinnedOrUnauthenticatedConfigs(t *testing.T) {
	certificate := tls.Certificate{Certificate: [][]byte{{1}}}
	verify := func(tls.ConnectionState) error { return nil }
	validClient := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, InsecureSkipVerify: true, VerifyConnection: verify, Certificates: []tls.Certificate{certificate}}
	validServer := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, InsecureSkipVerify: true, VerifyConnection: verify, ClientAuth: tls.RequireAnyClientCert, Certificates: []tls.Certificate{certificate}}
	if err := validateClientTLS(validClient); err != nil {
		t.Fatal(err)
	}
	if err := validateServerTLS(validServer); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]*tls.Config{
		"tls12":       {MinVersion: tls.VersionTLS12, NextProtos: []string{ALPN}, InsecureSkipVerify: true, VerifyConnection: verify, Certificates: []tls.Certificate{certificate}},
		"wrong alpn":  {MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, InsecureSkipVerify: true, VerifyConnection: verify, Certificates: []tls.Certificate{certificate}},
		"no verifier": {MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, InsecureSkipVerify: true, Certificates: []tls.Certificate{certificate}},
		"web pki":     {MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, VerifyConnection: verify, Certificates: []tls.Certificate{certificate}},
		"no identity": {MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, InsecureSkipVerify: true, VerifyConnection: verify},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateClientTLS(config); err == nil {
				t.Fatal("client configuration accepted")
			}
		})
	}
}

func TestCanonicalQUICConfigDisablesZeroRTTAndDatagrams(t *testing.T) {
	for _, class := range []Class{ClassInteractive, ClassPreview, ClassTransfer} {
		config := config(class)
		wantUni := int64(-1)
		if class == ClassPreview {
			wantUni = 16
		}
		if config.Allow0RTT || config.EnableDatagrams || config.MaxIncomingStreams <= 0 || config.MaxIncomingUniStreams != wantUni || config.KeepAlivePeriod != 3*time.Second || config.MaxIdleTimeout != 2*time.Minute || config.InitialPacketSize != 1200 || config.DisablePathMTUDiscovery {
			t.Fatalf("class=%d config=%+v", class, config)
		}
	}
	probe := probeConfig(2 * time.Minute)
	if probe.KeepAlivePeriod != 0 || probe.MaxIdleTimeout != 2*time.Minute || probe.MaxIncomingStreams != 3 || probe.Allow0RTT || probe.EnableDatagrams {
		t.Fatalf("probe config=%+v", probe)
	}
}

func TestSessionConfigAcceptsMeasuredKeepaliveAndVerifiedPacketSize(t *testing.T) {
	config := DevelopmentSessionConfig(ClassInteractive)
	config.InitialPacketSize = 1380
	adapted, err := config.WithKeepAlive(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	quicConfig := quicConfig(adapted)
	if quicConfig.KeepAlivePeriod != 30*time.Second || quicConfig.InitialPacketSize != 1380 || quicConfig.DisablePathMTUDiscovery {
		t.Fatalf("config=%+v", quicConfig)
	}
	for name, invalid := range map[string]SessionConfig{
		"packet size":  {Class: ClassInteractive, KeepAlivePeriod: 3 * time.Second, MaxIdleTimeout: time.Minute, InitialPacketSize: 1199},
		"keepalive":    {Class: ClassInteractive, MaxIdleTimeout: time.Minute, InitialPacketSize: 1200},
		"idle horizon": {Class: ClassInteractive, KeepAlivePeriod: 30 * time.Second, MaxIdleTimeout: time.Minute, InitialPacketSize: 1200},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.validate(); err == nil {
				t.Fatal("invalid session configuration accepted")
			}
		})
	}
}
