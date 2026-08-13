package relaycarrier

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/wsscarrier"
)

const relayWSSSubprotocol = "paperboat.peer-relay.v1"

type WSSDialConfig struct {
	URL             string
	Credential      string
	StreamHandle    [16]byte
	EndpointID      string
	Role            string
	RelayID         string
	TLS             *tls.Config
	HTTPClient      *http.Client
	Lifetime        context.Context
	MaximumDeadline time.Duration
	Carrier         Config
}

func DialWSS(ctx context.Context, config WSSDialConfig) (*Connection, error) {
	parsed, err := url.Parse(config.URL)
	if ctx == nil || err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil || parsed.Path != "/v1/peer-relay" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !compactCredential(config.Credential) || allZeroHandle(config.StreamHandle) || !boundedAttachmentID(config.EndpointID) || config.Role != "initiator" && config.Role != "responder" || !boundedAttachmentID(config.RelayID) || config.TLS == nil || config.MaximumDeadline <= 0 || config.MaximumDeadline > 24*time.Hour || !config.Carrier.valid() {
		return nil, ErrInvalid
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		transportConfig := httptransport.DevelopmentConfig()
		transportConfig.TLSConfig = config.TLS.Clone()
		transport, transportErr := httptransport.New(transportConfig)
		if transportErr != nil {
			return nil, errors.Join(ErrInvalid, transportErr)
		}
		httpClient = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+config.Credential)
	headers.Set("X-Paperboat-Stream-Handle", base64.RawURLEncoding.EncodeToString(config.StreamHandle[:]))
	headers.Set("X-Paperboat-Endpoint-Id", config.EndpointID)
	headers.Set("X-Paperboat-Relay-Role", config.Role)
	connection, response, err := websocket.Dial(ctx, config.URL, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: headers, Subprotocols: []string{relayWSSSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if connection.Subprotocol() != relayWSSSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "subprotocol mismatch")
		return nil, ErrInvalid
	}
	lifetime := config.Lifetime
	if lifetime == nil {
		lifetime = ctx
	}
	carrier, err := wsscarrier.New(lifetime, connection, wsscarrier.Config{RelayID: config.RelayID, MaximumDeadline: config.MaximumDeadline})
	if err != nil {
		_ = connection.CloseNow()
		return nil, err
	}
	var result *Connection
	if config.Role == "initiator" {
		result, err = NewWSSClient(carrier, config.Carrier)
	} else {
		result, err = NewWSSServer(carrier, config.Carrier)
	}
	if err != nil {
		return nil, errors.Join(err, carrier.Close())
	}
	return result, nil
}

func compactCredential(value string) bool {
	if len(value) == 0 || len(value) > 8192 || strings.TrimSpace(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
				return false
			}
		}
	}
	return true
}

func allZeroHandle(value [16]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func boundedAttachmentID(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n ")
}
