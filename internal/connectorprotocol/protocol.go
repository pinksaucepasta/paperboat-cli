// Package connectorprotocol implements the Paperboat connector control-plane
// protocol. It contains only control messages and session state. Byte transport,
// route forwarding, and origin proxying belong to their owning packages.
//
// This directory is the canonical Go implementation for the connector-v1
// family. Run contracts/connector-v1/sync-consumers.sh --check before release.
package connectorprotocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ProtocolName    = "paperboat.connector"
	ProtocolVersion = "1.0"

	// A frame carries one complete configuration snapshot. The envelope is
	// intentionally larger than MaxSnapshotBytes so the snapshot limit is
	// meaningful on the wire.
	MaxFrameBytes       = MaxSnapshotBytes + 64<<10
	MaxSnapshotBytes    = 4 << 20
	MaxDeltaBytes       = 1 << 20
	MaxCapabilities     = 64
	MaxCapabilityBytes  = 128
	MaxIdentifierBytes  = 128
	MaxCredentialRef    = 512
	MaxProofBytes       = 16 << 10
	MaxNonceBytes       = 128
	MaxReasonMessage    = 512
	MaxJSONDepth        = 64
	MaxClockSkew        = 2 * time.Minute
	DefaultLease        = 45 * time.Second
	DefaultHeartbeat    = 15 * time.Second
	DefaultApplyTimeout = 15 * time.Second
	DefaultAbortTimeout = 5 * time.Second
	MaxLease            = 24 * time.Hour
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,127}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
var hashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var identityKeyIDPattern = regexp.MustCompile(`^ed25519:[A-Za-z0-9_-]{43}$`)
var identityThumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type Code string

const (
	CodeInvalidInput               Code = "invalid_input"
	CodeMalformedFrame             Code = "malformed_frame"
	CodeFrameTooLarge              Code = "frame_too_large"
	CodeProtocolIncompatible       Code = "protocol_incompatible"
	CodeCapabilityMissing          Code = "capability_missing"
	CodeAuthenticationFailed       Code = "authentication_failed"
	CodeCredentialExpired          Code = "credential_expired"
	CodeIdentityMismatch           Code = "identity_mismatch"
	CodeSessionConflict            Code = "session_conflict"
	CodeSessionClosed              Code = "session_closed"
	CodeLeaseExpired               Code = "lease_expired"
	CodeHeartbeatTimeout           Code = "heartbeat_timeout"
	CodeSnapshotRequired           Code = "snapshot_required"
	CodeGenerationGap              Code = "generation_gap"
	CodeStaleGeneration            Code = "stale_generation"
	CodeContentHashMismatch        Code = "content_hash_mismatch"
	CodeSnapshotRejected           Code = "snapshot_rejected"
	CodeDeltaRejected              Code = "delta_rejected"
	CodeNotReady                   Code = "not_ready"
	CodeCanceled                   Code = "canceled"
	CodeStaleSession               Code = "stale_session"
	CodeUnsupportedMessage         Code = "unsupported_message"
	CodeDrainRejected              Code = "drain_rejected"
	CodeDrainTimeout               Code = "drain_timeout"
	CodeCredentialRotationRejected Code = "credential_rotation_rejected"
	CodeCredentialRotationNotReady Code = "credential_rotation_not_ready"
	CodeCredentialRotationFailed   Code = "credential_rotation_failed"
)

// DisconnectReason is deliberately finite. User-visible diagnostics can map
// these values to recovery text without branching on an error string.
type DisconnectReason string

const (
	ReasonProtocolMismatch   DisconnectReason = "protocol_mismatch"
	ReasonCapabilityMissing  DisconnectReason = "capability_missing"
	ReasonMalformed          DisconnectReason = "malformed_message"
	ReasonAuthentication     DisconnectReason = "authentication_failed"
	ReasonCredentialExpired  DisconnectReason = "credential_expired"
	ReasonLeaseExpired       DisconnectReason = "lease_expired"
	ReasonHeartbeatTimeout   DisconnectReason = "heartbeat_timeout"
	ReasonSessionReplaced    DisconnectReason = "session_replaced"
	ReasonStaleGeneration    DisconnectReason = "stale_generation"
	ReasonSnapshotRejected   DisconnectReason = "snapshot_rejected"
	ReasonGenerationGap      DisconnectReason = "generation_gap"
	ReasonCredentialRotation DisconnectReason = "credential_rotation"
	ReasonCanceled           DisconnectReason = "canceled"
	ReasonServerShutdown     DisconnectReason = "server_shutdown"
	ReasonProtocolClosed     DisconnectReason = "protocol_closed"
)

// Error is the typed boundary error returned by this package. Retryable is a
// protocol decision, not a claim that the caller may repeat an unsafe write.
type Error struct {
	Code       Code
	Reason     DisconnectReason
	Retryable  bool
	RetryAfter time.Duration
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Cause.Error()
}

func (e *Error) Unwrap() error { return e.Cause }

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other != nil && e != nil && e.Code == other.Code
}

func (e *Error) Temporary() bool { return e != nil && e.Retryable }

var (
	ErrInvalidInput               = &Error{Code: CodeInvalidInput}
	ErrMalformedFrame             = &Error{Code: CodeMalformedFrame}
	ErrFrameTooLarge              = &Error{Code: CodeFrameTooLarge}
	ErrProtocolIncompatible       = &Error{Code: CodeProtocolIncompatible}
	ErrCapabilityMissing          = &Error{Code: CodeCapabilityMissing}
	ErrAuthenticationFailed       = &Error{Code: CodeAuthenticationFailed}
	ErrCredentialExpired          = &Error{Code: CodeCredentialExpired}
	ErrIdentityMismatch           = &Error{Code: CodeIdentityMismatch}
	ErrSessionConflict            = &Error{Code: CodeSessionConflict}
	ErrSessionClosed              = &Error{Code: CodeSessionClosed}
	ErrLeaseExpired               = &Error{Code: CodeLeaseExpired}
	ErrHeartbeatTimeout           = &Error{Code: CodeHeartbeatTimeout}
	ErrSnapshotRequired           = &Error{Code: CodeSnapshotRequired}
	ErrGenerationGap              = &Error{Code: CodeGenerationGap}
	ErrStaleGeneration            = &Error{Code: CodeStaleGeneration}
	ErrContentHashMismatch        = &Error{Code: CodeContentHashMismatch}
	ErrSnapshotRejected           = &Error{Code: CodeSnapshotRejected}
	ErrDeltaRejected              = &Error{Code: CodeDeltaRejected}
	ErrNotReady                   = &Error{Code: CodeNotReady}
	ErrCanceled                   = &Error{Code: CodeCanceled}
	ErrStaleSession               = &Error{Code: CodeStaleSession}
	ErrUnsupportedMessage         = &Error{Code: CodeUnsupportedMessage}
	ErrDrainRejected              = &Error{Code: CodeDrainRejected}
	ErrDrainTimeout               = &Error{Code: CodeDrainTimeout}
	ErrCredentialRotationRejected = &Error{Code: CodeCredentialRotationRejected}
	ErrCredentialRotationNotReady = &Error{Code: CodeCredentialRotationNotReady}
	ErrCredentialRotationFailed   = &Error{Code: CodeCredentialRotationFailed}
)

func codeError(base *Error, reason DisconnectReason, retryable bool, cause error) error {
	return &Error{Code: base.Code, Reason: reason, Retryable: retryable, Cause: cause}
}

func CodeOf(err error) Code {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.Code
	}
	return ""
}

func ReasonOf(err error) DisconnectReason {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.Reason
	}
	return ""
}

func ValidateIdentifier(value string) error {
	if !identifierPattern.MatchString(value) || len(value) > MaxIdentifierBytes {
		return ErrInvalidInput
	}
	return nil
}

func ValidateCredentialReference(value string) error {
	if len(value) == 0 || len(value) > MaxCredentialRef || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return ErrInvalidInput
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host != "paperboat" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" {
		return ErrInvalidInput
	}
	switch parsed.Scheme {
	case "keychain", "credential-manager", "secret-service", "protected-file", "tpm":
		return nil
	default:
		return ErrInvalidInput
	}
}

func ValidateProof(value string) error {
	if len(value) < 32 || len(value) > MaxProofBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return ErrInvalidInput
	}
	return nil
}

// VerifyProofFunc lets the host identity package keep ownership of public-key
// lookup and revocation while this package owns the signed transcript.
type VerifyProofFunc func(message, signature []byte) bool

func SignProofPayload(payload []byte, sign func([]byte) []byte) (string, error) {
	if len(payload) == 0 || len(payload) > MaxProofBytes || sign == nil {
		return "", ErrInvalidInput
	}
	signature := sign(payload)
	if len(signature) == 0 || len(signature) > MaxProofBytes {
		return "", ErrInvalidInput
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func VerifyProofPayload(payload []byte, signedProof string, verify VerifyProofFunc) error {
	if len(payload) == 0 || verify == nil {
		return ErrAuthenticationFailed
	}
	signature, err := DecodeProof(signedProof)
	if err != nil || !verify(payload, signature) {
		return ErrAuthenticationFailed
	}
	return nil
}

// DecodeProof decodes the detached base64url signature without exposing any
// credential material. Server adapters use this after deriving the exact
// transcript and resolving the enrolled public identity for the request.
func DecodeProof(signedProof string) ([]byte, error) {
	if ValidateProof(signedProof) != nil {
		return nil, ErrAuthenticationFailed
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signedProof)
	if err != nil || len(signature) == 0 || len(signature) > MaxProofBytes {
		return nil, ErrAuthenticationFailed
	}
	return signature, nil
}

// ValidateIdentityKey checks the stable public-key identity metadata used by
// the host enrollment store. The private key, certificate bytes, and bearer
// credential never cross this protocol boundary.
func ValidateIdentityKey(keyID, thumbprint string) error {
	if !identityKeyIDPattern.MatchString(keyID) || !identityThumbprintPattern.MatchString(thumbprint) || keyID[len("ed25519:"):] != thumbprint {
		return ErrInvalidInput
	}
	return nil
}

// IdentityThumbprint returns the RFC 7638-style SHA-256 thumbprint for an
// Ed25519 public key. The canonical JSON member order is part of the identity
// contract and matches the host enrollment store.
func IdentityThumbprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidInput
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func IdentityKeyID(publicKey ed25519.PublicKey) (string, error) {
	thumbprint, err := IdentityThumbprint(publicKey)
	if err != nil {
		return "", err
	}
	return "ed25519:" + thumbprint, nil
}

// Capability names are stable wire names. The required set is intentionally
// small so optional data-plane features can be negotiated independently.
const (
	CapabilitySnapshot           = "config.snapshot.v1"
	CapabilityDelta              = "config.delta.v1"
	CapabilityAck                = "config.ack.v1"
	CapabilityHeartbeat          = "session.heartbeat.v1"
	CapabilityRenewal            = "auth.renew.v1"
	CapabilityDrain              = "connector.drain.v1"
	CapabilityCredentialRotation = "credential.rotate.v1"
)

var requiredCapabilities = map[string]struct{}{
	CapabilitySnapshot: {}, CapabilityDelta: {}, CapabilityAck: {},
	CapabilityHeartbeat: {}, CapabilityRenewal: {},
}

// ProductionCapabilities returns a fresh copy of every connector-v1
// capability implemented by the canonical server and stable host runtime.
func ProductionCapabilities() []string {
	return []string{
		CapabilitySnapshot,
		CapabilityDelta,
		CapabilityAck,
		CapabilityHeartbeat,
		CapabilityRenewal,
		CapabilityDrain,
		CapabilityCredentialRotation,
	}
}

func ValidateCapabilities(values []string) error {
	if len(values) == 0 || len(values) > MaxCapabilities {
		return ErrCapabilityMissing
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) > MaxCapabilityBytes || !capabilityPattern.MatchString(value) {
			return ErrInvalidInput
		}
		if _, exists := seen[value]; exists {
			return ErrInvalidInput
		}
		seen[value] = struct{}{}
	}
	for required := range requiredCapabilities {
		if _, ok := seen[required]; !ok {
			return codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, fmt.Errorf("missing capability %q", required))
		}
	}
	return nil
}

func NegotiateCapabilities(offered, supported []string) ([]string, error) {
	if err := ValidateCapabilities(offered); err != nil {
		return nil, err
	}
	if err := ValidateCapabilities(supported); err != nil {
		return nil, err
	}
	supportedSet := make(map[string]struct{}, len(supported))
	for _, value := range supported {
		supportedSet[value] = struct{}{}
	}
	selected := make([]string, 0, len(offered))
	for _, value := range offered {
		if _, ok := supportedSet[value]; ok {
			selected = append(selected, value)
		}
	}
	if err := ValidateCapabilities(selected); err != nil {
		return nil, codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, err)
	}
	return selected, nil
}

func NegotiateVersion(minVersion, maxVersion string) (string, error) {
	if !versionPattern.MatchString(minVersion) || !versionPattern.MatchString(maxVersion) {
		return "", codeError(ErrProtocolIncompatible, ReasonProtocolMismatch, false, errors.New("invalid version range"))
	}
	minMajor, minMinor, minOK := parseVersion(minVersion)
	maxMajor, maxMinor, maxOK := parseVersion(maxVersion)
	selectedMajor, selectedMinor, selectedOK := parseVersion(ProtocolVersion)
	if !maxOK || !selectedOK {
		return "", codeError(ErrProtocolIncompatible, ReasonProtocolMismatch, false, errors.New("invalid protocol version"))
	}
	if !minOK {
		return "", codeError(ErrProtocolIncompatible, ReasonProtocolMismatch, false, errors.New("invalid protocol version"))
	}
	if minMajor > maxMajor || minMajor > selectedMajor || maxMajor < selectedMajor || minMajor == selectedMajor && minMinor > selectedMinor || maxMajor == selectedMajor && maxMinor < selectedMinor {
		return "", codeError(ErrProtocolIncompatible, ReasonProtocolMismatch, false, errors.New("no compatible protocol version"))
	}
	return ProtocolVersion, nil
}

func parseVersion(value string) (int, int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil || major < 0 || minor < 0 || strconv.Itoa(major) != parts[0] || strconv.Itoa(minor) != parts[1] {
		return 0, 0, false
	}
	return major, minor, true
}

type MessageType string

const (
	MessageHello                       MessageType = "hello"
	MessageWelcome                     MessageType = "welcome"
	MessageSnapshot                    MessageType = "snapshot"
	MessageDelta                       MessageType = "delta"
	MessageAck                         MessageType = "ack"
	MessageReady                       MessageType = "ready"
	MessageHeartbeat                   MessageType = "heartbeat"
	MessageHeartbeatAck                MessageType = "heartbeat_ack"
	MessageAuthRenew                   MessageType = "auth_renew"
	MessageAuthRenewed                 MessageType = "auth_renewed"
	MessageDrain                       MessageType = "drain"
	MessageDrainAck                    MessageType = "drain_ack"
	MessageCredentialRotationChallenge MessageType = "credential_rotation_challenge"
	MessageCredentialRotationProof     MessageType = "credential_rotation_proof"
	MessageCredentialRotationInstall   MessageType = "credential_rotation_install"
	MessageCredentialRotationReady     MessageType = "credential_rotation_ready"
	MessageCredentialRotationRevoke    MessageType = "credential_rotation_revoke"
	MessageCredentialRotationAck       MessageType = "credential_rotation_ack"
	MessageDisconnect                  MessageType = "disconnect"
	MessageReject                      MessageType = "reject"
)

const (
	MessageRotationChallenge = MessageCredentialRotationChallenge
	MessageRotationProof     = MessageCredentialRotationProof
	MessageRotationInstall   = MessageCredentialRotationInstall
	MessageRotationReady     = MessageCredentialRotationReady
	MessageRotationRevoke    = MessageCredentialRotationRevoke
	MessageRotationAck       = MessageCredentialRotationAck
)

var allowedMessageTypes = map[MessageType]struct{}{
	MessageHello: {}, MessageWelcome: {}, MessageSnapshot: {}, MessageDelta: {},
	MessageAck: {}, MessageReady: {}, MessageHeartbeat: {}, MessageHeartbeatAck: {},
	MessageAuthRenew: {}, MessageAuthRenewed: {}, MessageDrain: {}, MessageDrainAck: {},
	MessageCredentialRotationChallenge: {}, MessageCredentialRotationProof: {}, MessageCredentialRotationInstall: {}, MessageCredentialRotationReady: {}, MessageCredentialRotationRevoke: {}, MessageCredentialRotationAck: {},
	MessageDisconnect: {}, MessageReject: {},
}

type Frame struct {
	Type      MessageType     `json:"type"`
	Version   string          `json:"version"`
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

func NewFrame(messageType MessageType, requestID string, payload any) (Frame, error) {
	if _, ok := allowedMessageTypes[messageType]; !ok || !validRequestID(requestID) {
		return Frame{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Frame{}, codeError(ErrInvalidInput, ReasonMalformed, false, err)
	}
	if payloadTooLarge(messageType, payload) {
		return Frame{}, ErrFrameTooLarge
	}
	if len(encoded) > maxPayloadBytes(messageType) {
		return Frame{}, ErrFrameTooLarge
	}
	if err := validatePayloadJSON(encoded); err != nil {
		return Frame{}, err
	}
	if err := validateMessagePayload(messageType, encoded); err != nil {
		return Frame{}, err
	}
	return Frame{Type: messageType, Version: ProtocolVersion, RequestID: requestID, Payload: encoded}, nil
}

func payloadTooLarge(messageType MessageType, payload any) bool {
	switch messageType {
	case MessageSnapshot:
		if value, ok := payload.(Snapshot); ok {
			return len(value.Payload) > MaxSnapshotBytes
		}
	case MessageDelta:
		if value, ok := payload.(Delta); ok {
			return len(value.Payload) > MaxDeltaBytes
		}
	}
	return false
}

func (f Frame) Validate() error {
	if _, ok := allowedMessageTypes[f.Type]; !ok {
		return codeError(ErrUnsupportedMessage, ReasonMalformed, false, nil)
	}
	if f.Version != ProtocolVersion || !validRequestID(f.RequestID) || len(f.Payload) == 0 || len(f.Payload) > maxPayloadBytes(f.Type) {
		return ErrMalformedFrame
	}
	if err := validatePayloadJSON(f.Payload); err != nil {
		return err
	}
	return validateMessagePayload(f.Type, f.Payload)
}

func validateMessagePayload(messageType MessageType, payload []byte) error {
	switch messageType {
	case MessageHello:
		var message Hello
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageWelcome:
		var message Welcome
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageSnapshot:
		var message Snapshot
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.ValidateBound()
	case MessageDelta:
		var message Delta
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.ValidateBound()
	case MessageAck:
		var message Ack
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageReady:
		var message Readiness
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageHeartbeat:
		var message Heartbeat
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageHeartbeatAck:
		var message HeartbeatAck
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageAuthRenew:
		var message RenewalRequest
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageAuthRenewed:
		var message AuthResult
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.ValidateBound()
	case MessageDrain:
		var message Drain
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageDrainAck:
		var message DrainAck
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationChallenge:
		var message CredentialRotationChallenge
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationProof:
		var message CredentialRotationProof
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationInstall:
		var message CredentialRotationInstall
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationReady:
		var message CredentialRotationReady
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationRevoke:
		var message CredentialRotationRevoke
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate(time.Time{})
	case MessageCredentialRotationAck:
		var message CredentialRotationAck
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageDisconnect:
		var message Disconnect
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	case MessageReject:
		var message Reject
		if err := decodeStrict(payload, &message); err != nil {
			return ErrMalformedFrame
		}
		return message.Validate()
	}
	return ErrUnsupportedMessage
}

func (f Frame) DecodePayload(target any) error {
	if err := f.Validate(); err != nil {
		return err
	}
	return decodeStrict(f.Payload, target)
}

func ReadFrame(reader io.Reader) (Frame, error) {
	if reader == nil {
		return Frame{}, ErrInvalidInput
	}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return Frame{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 {
		return Frame{}, ErrMalformedFrame
	}
	if length > MaxFrameBytes {
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(reader, body); err != nil {
		return Frame{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if !json.Valid(body) || rejectDuplicateKeys(body) != nil {
		return Frame{}, ErrMalformedFrame
	}
	var frame Frame
	if err := decodeStrict(body, &frame); err != nil {
		return Frame{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if err := frame.Validate(); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func WriteFrame(writer io.Writer, frame Frame) error {
	if writer == nil {
		return ErrInvalidInput
	}
	if err := frame.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(frame)
	if err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if len(body) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeAll(writer, body)
}

func maxPayloadBytes(messageType MessageType) int {
	switch messageType {
	case MessageSnapshot:
		return MaxSnapshotBytes + 16<<10
	case MessageDelta:
		return MaxDeltaBytes + 16<<10
	default:
		return 64 << 10
	}
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func validRequestID(value string) bool {
	return len(value) >= 1 && len(value) <= MaxIdentifierBytes && identifierPattern.MatchString(value)
}

func decodeStrict(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxFrameBytes || target == nil || rejectDuplicateKeys(data) != nil {
		return ErrMalformedFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func validatePayloadJSON(data []byte) error {
	if len(data) == 0 || len(data) > MaxFrameBytes || !json.Valid(data) {
		return ErrMalformedFrame
	}
	if rejectDuplicateKeys(data) != nil {
		return ErrMalformedFrame
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > MaxJSONDepth {
			return errors.New("JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

type AuthRequest struct {
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	ConnectorID           string    `json:"connector_id"`
	HostID                string    `json:"host_id"`
	IdentityKeyID         string    `json:"identity_key_id"`
	IdentityKeyThumbprint string    `json:"identity_key_thumbprint"`
	ProcessGeneration     uint64    `json:"process_generation"`
	CredentialGeneration  uint64    `json:"credential_generation"`
	Nonce                 string    `json:"nonce"`
	SignedProof           string    `json:"signed_proof"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
}

type authProofTranscript struct {
	Domain                string    `json:"domain"`
	Protocol              string    `json:"protocol"`
	Version               string    `json:"version"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	ConnectorID           string    `json:"connector_id"`
	HostID                string    `json:"host_id"`
	IdentityKeyID         string    `json:"identity_key_id"`
	IdentityKeyThumbprint string    `json:"identity_key_thumbprint"`
	ProcessGeneration     uint64    `json:"process_generation"`
	CredentialGeneration  uint64    `json:"credential_generation"`
	SessionID             string    `json:"session_id,omitempty"`
	Nonce                 string    `json:"nonce"`
	IssuedAt              time.Time `json:"issued_at,omitempty"`
	ExpiresAt             time.Time `json:"expires_at,omitempty"`
	RequestedAt           time.Time `json:"requested_at,omitempty"`
}

func AuthProofPayload(request AuthRequest) ([]byte, error) {
	if err := request.validate(time.Time{}, false); err != nil {
		return nil, err
	}
	return json.Marshal(authProofTranscript{
		Domain: "paperboat.connector.auth.v1", Protocol: ProtocolName, Version: ProtocolVersion,
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
		HostID: request.HostID, IdentityKeyID: request.IdentityKeyID, IdentityKeyThumbprint: request.IdentityKeyThumbprint,
		ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration,
		Nonce: request.Nonce, IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt,
	})
}

func RenewalProofPayload(request RenewalRequest) ([]byte, error) {
	if err := request.validate(false); err != nil {
		return nil, err
	}
	return json.Marshal(authProofTranscript{
		Domain: "paperboat.connector.auth.renew.v1", Protocol: ProtocolName, Version: ProtocolVersion,
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
		HostID: request.HostID, IdentityKeyID: request.IdentityKeyID, IdentityKeyThumbprint: request.IdentityKeyThumbprint,
		ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration,
		SessionID: request.SessionID, Nonce: request.Nonce, RequestedAt: request.RequestedAt,
	})
}

func VerifyAuthProof(request AuthRequest, verify VerifyProofFunc) error {
	payload, err := AuthProofPayload(request)
	if err != nil {
		return err
	}
	return VerifyProofPayload(payload, request.SignedProof, verify)
}

func SignAuthProof(request AuthRequest, sign func([]byte) []byte) (AuthRequest, error) {
	payload, err := AuthProofPayload(request)
	if err != nil {
		return AuthRequest{}, err
	}
	request.SignedProof, err = SignProofPayload(payload, sign)
	if err != nil {
		return AuthRequest{}, err
	}
	return request, request.Validate(time.Time{})
}

func VerifyRenewalProof(request RenewalRequest, verify VerifyProofFunc) error {
	payload, err := RenewalProofPayload(request)
	if err != nil {
		return err
	}
	return VerifyProofPayload(payload, request.SignedProof, verify)
}

func SignRenewalProof(request RenewalRequest, sign func([]byte) []byte) (RenewalRequest, error) {
	payload, err := RenewalProofPayload(request)
	if err != nil {
		return RenewalRequest{}, err
	}
	request.SignedProof, err = SignProofPayload(payload, sign)
	if err != nil {
		return RenewalRequest{}, err
	}
	return request, request.Validate()
}

func (a AuthRequest) Validate(now time.Time) error {
	return a.validate(now, true)
}

func (a AuthRequest) validate(now time.Time, requireProof bool) error {
	if ValidateIdentifier(a.AccountID) != nil || ValidateIdentifier(a.TunnelID) != nil || ValidateIdentifier(a.ConnectorID) != nil || ValidateIdentifier(a.HostID) != nil || ValidateIdentityKey(a.IdentityKeyID, a.IdentityKeyThumbprint) != nil {
		return ErrInvalidInput
	}
	if len(a.Nonce) < 16 || len(a.Nonce) > MaxNonceBytes || strings.TrimSpace(a.Nonce) != a.Nonce || strings.ContainsAny(a.Nonce, "\r\n") || a.ProcessGeneration == 0 || a.CredentialGeneration == 0 || a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.Sub(a.IssuedAt) > 15*time.Minute || requireProof && ValidateProof(a.SignedProof) != nil {
		return ErrInvalidInput
	}
	if !now.IsZero() && (a.IssuedAt.After(now.Add(MaxClockSkew)) || now.Sub(a.IssuedAt) > MaxClockSkew || !a.ExpiresAt.After(now)) {
		return codeError(ErrCredentialExpired, ReasonCredentialExpired, true, nil)
	}
	return nil
}

type AuthResult struct {
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	ConnectorID           string    `json:"connector_id"`
	SessionID             string    `json:"session_id,omitempty"`
	HostID                string    `json:"host_id"`
	IdentityKeyID         string    `json:"identity_key_id"`
	IdentityKeyThumbprint string    `json:"identity_key_thumbprint"`
	ProcessGeneration     uint64    `json:"process_generation"`
	CredentialGeneration  uint64    `json:"credential_generation"`
	CredentialExpiresAt   time.Time `json:"credential_expires_at"`
	LeaseExpiresAt        time.Time `json:"lease_expires_at"`
}

func (a AuthResult) Validate(now time.Time) error {
	for _, value := range []string{a.AccountID, a.TunnelID, a.ConnectorID, a.HostID} {
		if ValidateIdentifier(value) != nil {
			return ErrAuthenticationFailed
		}
	}
	if a.SessionID != "" && ValidateIdentifier(a.SessionID) != nil {
		return ErrAuthenticationFailed
	}
	if ValidateIdentityKey(a.IdentityKeyID, a.IdentityKeyThumbprint) != nil || a.ProcessGeneration == 0 || a.CredentialGeneration == 0 || a.CredentialExpiresAt.IsZero() || a.LeaseExpiresAt.IsZero() || a.LeaseExpiresAt.After(a.CredentialExpiresAt) {
		return ErrAuthenticationFailed
	}
	if !now.IsZero() && (!a.CredentialExpiresAt.After(now) || !a.LeaseExpiresAt.After(now) || a.LeaseExpiresAt.Sub(now) > MaxLease) {
		return ErrAuthenticationFailed
	}
	return nil
}

func (a AuthResult) ValidateBound() error {
	if err := a.Validate(time.Time{}); err != nil || ValidateIdentifier(a.SessionID) != nil {
		return ErrAuthenticationFailed
	}
	return nil
}

type RenewalRequest struct {
	SessionID             string    `json:"session_id"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	ConnectorID           string    `json:"connector_id"`
	HostID                string    `json:"host_id"`
	IdentityKeyID         string    `json:"identity_key_id"`
	IdentityKeyThumbprint string    `json:"identity_key_thumbprint"`
	ProcessGeneration     uint64    `json:"process_generation"`
	CredentialGeneration  uint64    `json:"credential_generation"`
	Nonce                 string    `json:"nonce"`
	SignedProof           string    `json:"signed_proof"`
	RequestedAt           time.Time `json:"requested_at"`
}

func (r RenewalRequest) Validate() error {
	return r.validate(true)
}

// ValidateAt adds freshness checks that cannot be encoded in the detached
// signature alone. Durable server adapters must call this before accepting a
// renewal so an old signed nonce cannot be replayed after a process restart.
func (r RenewalRequest) ValidateAt(now time.Time) error {
	if err := r.validate(true); err != nil {
		return err
	}
	if !now.IsZero() && (r.RequestedAt.After(now.Add(MaxClockSkew)) || now.Sub(r.RequestedAt) > MaxClockSkew) {
		return codeError(ErrAuthenticationFailed, ReasonAuthentication, false, errors.New("renewal request is outside clock skew"))
	}
	return nil
}

func (r RenewalRequest) validate(requireProof bool) error {
	if ValidateIdentifier(r.SessionID) != nil || ValidateIdentifier(r.AccountID) != nil || ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.ConnectorID) != nil || ValidateIdentifier(r.HostID) != nil || ValidateIdentityKey(r.IdentityKeyID, r.IdentityKeyThumbprint) != nil || r.ProcessGeneration == 0 || r.CredentialGeneration == 0 || len(r.Nonce) < 16 || len(r.Nonce) > MaxNonceBytes || strings.TrimSpace(r.Nonce) != r.Nonce || strings.ContainsAny(r.Nonce, "\r\n") || r.RequestedAt.IsZero() || requireProof && ValidateProof(r.SignedProof) != nil {
		return ErrInvalidInput
	}
	return nil
}

type Lease struct {
	SessionID           string    `json:"session_id"`
	ExpiresAt           time.Time `json:"expires_at"`
	HeartbeatIntervalMS uint32    `json:"heartbeat_interval_ms"`
}

func (l Lease) Validate(now time.Time) error {
	if ValidateIdentifier(l.SessionID) != nil || l.ExpiresAt.IsZero() || l.HeartbeatIntervalMS == 0 {
		return ErrInvalidInput
	}
	if !now.IsZero() && (!l.ExpiresAt.After(now) || l.ExpiresAt.Sub(now) > MaxLease || time.Duration(l.HeartbeatIntervalMS)*time.Millisecond >= l.ExpiresAt.Sub(now)) {
		return ErrInvalidInput
	}
	return nil
}

type Hello struct {
	Protocol          string      `json:"protocol"`
	MinVersion        string      `json:"min_version"`
	MaxVersion        string      `json:"max_version"`
	AccountID         string      `json:"account_id"`
	TunnelID          string      `json:"tunnel_id"`
	ConnectorID       string      `json:"connector_id"`
	HostID            string      `json:"host_id"`
	ProcessGeneration uint64      `json:"process_generation"`
	Capabilities      []string    `json:"capabilities"`
	Auth              AuthRequest `json:"auth"`
}

func (h Hello) Validate(now time.Time) error {
	if h.Protocol != ProtocolName || h.MinVersion == "" || h.MaxVersion == "" || ValidateIdentifier(h.AccountID) != nil || ValidateIdentifier(h.TunnelID) != nil || ValidateIdentifier(h.ConnectorID) != nil || ValidateIdentifier(h.HostID) != nil || h.ProcessGeneration == 0 {
		return ErrInvalidInput
	}
	if _, err := NegotiateVersion(h.MinVersion, h.MaxVersion); err != nil {
		return err
	}
	if err := ValidateCapabilities(h.Capabilities); err != nil {
		return err
	}
	if h.Auth.AccountID != h.AccountID || h.Auth.TunnelID != h.TunnelID || h.Auth.ConnectorID != h.ConnectorID || h.Auth.HostID != h.HostID || h.Auth.ProcessGeneration != h.ProcessGeneration {
		return codeError(ErrIdentityMismatch, ReasonAuthentication, false, nil)
	}
	return h.Auth.Validate(now)
}

type Welcome struct {
	Protocol         string    `json:"protocol"`
	Version          string    `json:"version"`
	SessionID        string    `json:"session_id"`
	Capabilities     []string  `json:"capabilities"`
	Lease            Lease     `json:"lease"`
	RequiresSnapshot bool      `json:"requires_snapshot"`
	ServerTime       time.Time `json:"server_time"`
}

func (w Welcome) Validate(now time.Time) error {
	if w.Protocol != ProtocolName || w.Version != ProtocolVersion || ValidateIdentifier(w.SessionID) != nil || !w.RequiresSnapshot || ValidateCapabilities(w.Capabilities) != nil || w.ServerTime.IsZero() || w.Lease.SessionID != w.SessionID {
		return ErrInvalidInput
	}
	return w.Lease.Validate(now)
}

type Snapshot struct {
	AccountID         string          `json:"account_id,omitempty"`
	TunnelID          string          `json:"tunnel_id"`
	ConnectorID       string          `json:"connector_id,omitempty"`
	SessionID         string          `json:"session_id,omitempty"`
	ProcessGeneration uint64          `json:"process_generation,omitempty"`
	Generation        uint64          `json:"generation"`
	ContentHash       string          `json:"content_hash"`
	Payload           json.RawMessage `json:"payload"`
}

func NewSnapshot(tunnelID string, generation uint64, payload []byte) (Snapshot, error) {
	if ValidateIdentifier(tunnelID) != nil || generation == 0 || len(payload) == 0 || len(payload) > MaxSnapshotBytes {
		return Snapshot{}, ErrInvalidInput
	}
	canonical, err := canonicalJSON(payload, MaxSnapshotBytes)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateConfigSnapshotPayload(canonical, tunnelID, generation); err != nil {
		return Snapshot{}, err
	}
	digest := sha256.Sum256(canonical)
	return Snapshot{TunnelID: tunnelID, Generation: generation, ContentHash: "sha256:" + hex.EncodeToString(digest[:]), Payload: canonical}, nil
}

func (s Snapshot) Validate() error {
	if ValidateIdentifier(s.TunnelID) != nil || s.AccountID != "" && ValidateIdentifier(s.AccountID) != nil || s.SessionID != "" && ValidateIdentifier(s.SessionID) != nil || s.Generation == 0 || !hashPattern.MatchString(s.ContentHash) || len(s.Payload) == 0 || len(s.Payload) > MaxSnapshotBytes {
		return ErrInvalidInput
	}
	canonical, err := canonicalJSON(s.Payload, MaxSnapshotBytes)
	if err != nil || !bytes.Equal(canonical, s.Payload) {
		return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, err)
	}
	digest := sha256.Sum256(canonical)
	if s.ContentHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return codeError(ErrContentHashMismatch, ReasonSnapshotRejected, false, nil)
	}
	if err := validateConfigSnapshotPayload(canonical, s.TunnelID, s.Generation); err != nil {
		return codeError(ErrSnapshotRejected, ReasonSnapshotRejected, false, err)
	}
	return nil
}

type wireConfigSnapshot struct {
	Schema         string            `json:"schema"`
	Kind           string            `json:"kind"`
	TunnelID       string            `json:"tunnel_id"`
	Generation     uint64            `json:"generation"`
	Name           string            `json:"name"`
	DesiredState   string            `json:"desired_state"`
	AccessMode     string            `json:"access_mode"`
	StableEndpoint string            `json:"stable_endpoint"`
	ExpiresAt      *time.Time        `json:"expires_at"`
	Routes         []wireConfigRoute `json:"routes"`
}

type wireConfigRoute struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	Protocol                string  `json:"protocol"`
	MatchType               string  `json:"match_type"`
	MatchHostname           string  `json:"match_hostname,omitempty"`
	WildcardSuffix          string  `json:"wildcard_suffix,omitempty"`
	PathPrefix              *string `json:"path_prefix"`
	OriginScheme            string  `json:"origin_scheme"`
	OriginAddress           string  `json:"origin_address"`
	PreserveHost            bool    `json:"preserve_host"`
	HostOverride            *string `json:"host_override"`
	TLSVerification         string  `json:"tls_verification"`
	TLSServerName           *string `json:"tls_server_name"`
	CAReference             *string `json:"ca_reference"`
	MTLSCredentialReference *string `json:"mtls_credential_reference"`
	ConnectTimeoutMs        int32   `json:"connect_timeout_ms"`
	IdleTimeoutMs           int32   `json:"idle_timeout_ms"`
	MaxConcurrentStreams    int32   `json:"max_concurrent_streams"`
	DesiredState            string  `json:"desired_state"`
}

func validateConfigSnapshotPayload(payload []byte, tunnelID string, generation uint64) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return ErrSnapshotRejected
	}
	for _, field := range []string{"schema", "kind", "tunnel_id", "generation", "name", "desired_state", "access_mode", "stable_endpoint", "expires_at", "routes"} {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("%w: snapshot field %s is required", ErrSnapshotRejected, field)
		}
	}
	var snapshot wireConfigSnapshot
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: snapshot shape: %v", ErrSnapshotRejected, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrSnapshotRejected
	}
	if snapshot.Schema != "paperboat.preview-tunnel/v1" || snapshot.Kind != "tunnel_config_snapshot" || snapshot.TunnelID != tunnelID || snapshot.Generation != generation || strings.TrimSpace(snapshot.Name) != snapshot.Name || len(snapshot.Name) == 0 || len(snapshot.Name) > 80 || snapshot.DesiredState != "active" && snapshot.DesiredState != "paused" && snapshot.DesiredState != "deleted" || snapshot.AccessMode != "public" && snapshot.AccessMode != "private" || snapshot.Routes == nil || !validWireStableEndpoint(snapshot.StableEndpoint) {
		return ErrSnapshotRejected
	}
	var rawRoutes []json.RawMessage
	if err := json.Unmarshal(fields["routes"], &rawRoutes); err != nil || len(rawRoutes) != len(snapshot.Routes) {
		return ErrSnapshotRejected
	}
	for index, route := range snapshot.Routes {
		var routeFields map[string]json.RawMessage
		if err := json.Unmarshal(rawRoutes[index], &routeFields); err != nil || routeFields == nil {
			return ErrSnapshotRejected
		}
		for _, field := range []string{"id", "name", "protocol", "match_type", "path_prefix", "origin_scheme", "origin_address", "preserve_host", "host_override", "tls_verification", "tls_server_name", "ca_reference", "mtls_credential_reference", "connect_timeout_ms", "idle_timeout_ms", "max_concurrent_streams", "desired_state"} {
			if _, ok := routeFields[field]; !ok {
				return fmt.Errorf("%w: route field %s is required", ErrSnapshotRejected, field)
			}
		}
		if err := validateWireConfigRoute(route); err != nil {
			return fmt.Errorf("%w: route %d: %v", ErrSnapshotRejected, index, err)
		}
	}
	return nil
}

func validWireStableEndpoint(value string) bool {
	if len(value) < len("https://a") || len(value) > 264 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" || parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) || !wireHostnamePattern(parsed.Host) {
		return false
	}
	return true
}

func wireHostnamePattern(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for index, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-') || index == 0 && char == '-' || index == len(value)-1 && char == '-' {
			return false
		}
	}
	return true
}

func validateWireConfigRoute(route wireConfigRoute) error {
	if ValidateIdentifier(route.ID) != nil || strings.TrimSpace(route.Name) != route.Name || len(route.Name) == 0 || len(route.Name) > 80 || strings.TrimSpace(route.OriginAddress) != route.OriginAddress || len(route.OriginAddress) == 0 || len(route.OriginAddress) > 512 || strings.ContainsAny(route.OriginAddress, "\r\n@") {
		return ErrInvalidInput
	}
	switch route.Protocol {
	case "http":
		if route.OriginScheme == "tcp" {
			return ErrInvalidInput
		}
	case "tcp_private":
		if route.OriginScheme != "tcp" {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	switch route.MatchType {
	case "managed_exact", "exact":
		if route.MatchHostname == "" || route.WildcardSuffix != "" || !wireHostnamePattern(route.MatchHostname) {
			return ErrInvalidInput
		}
	case "one_label_wildcard":
		if route.MatchHostname != "" || route.WildcardSuffix == "" || !wireHostnamePattern(route.WildcardSuffix) {
			return ErrInvalidInput
		}
	case "catch_all":
		if route.MatchHostname != "" || route.WildcardSuffix != "" {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	switch route.OriginScheme {
	case "http", "https", "h2c", "unix", "tcp":
	default:
		return ErrInvalidInput
	}
	switch route.TLSVerification {
	case "not_applicable", "system", "custom_ca", "mutual_tls", "insecure_development":
	default:
		return ErrInvalidInput
	}
	if route.OriginScheme != "https" && route.TLSVerification != "not_applicable" {
		return ErrInvalidInput
	}
	if route.PathPrefix != nil && (len(*route.PathPrefix) == 0 || len(*route.PathPrefix) > 512 || !strings.HasPrefix(*route.PathPrefix, "/") || strings.ContainsAny(*route.PathPrefix, "\r\n")) {
		return ErrInvalidInput
	}
	if route.HostOverride != nil && (len(*route.HostOverride) == 0 || len(*route.HostOverride) > 253 || strings.TrimSpace(*route.HostOverride) != *route.HostOverride) {
		return ErrInvalidInput
	}
	if route.TLSServerName != nil && (len(*route.TLSServerName) == 0 || len(*route.TLSServerName) > 253 || strings.TrimSpace(*route.TLSServerName) != *route.TLSServerName || strings.ContainsAny(*route.TLSServerName, "\r\n")) {
		return ErrInvalidInput
	}
	for _, reference := range []*string{route.CAReference, route.MTLSCredentialReference} {
		if reference != nil && ValidateCredentialReference(*reference) != nil {
			return ErrInvalidInput
		}
	}
	if route.ConnectTimeoutMs < 100 || route.ConnectTimeoutMs > 120000 || route.IdleTimeoutMs < 1000 || route.IdleTimeoutMs > 3600000 || route.MaxConcurrentStreams < 1 || route.MaxConcurrentStreams > 100000 || route.DesiredState != "active" && route.DesiredState != "disabled" && route.DesiredState != "deleted" {
		return ErrInvalidInput
	}
	return nil
}

// ValidateBound requires the identity envelope present on connector wire
// messages. NewSnapshot and server-side sources intentionally remain able to
// construct an unbound value until the authenticated session binds it.
func (s Snapshot) ValidateBound() error {
	if ValidateIdentifier(s.AccountID) != nil || ValidateIdentifier(s.ConnectorID) != nil || ValidateIdentifier(s.SessionID) != nil || s.ProcessGeneration == 0 {
		return ErrInvalidInput
	}
	return s.Validate()
}

type Delta struct {
	AccountID           string          `json:"account_id,omitempty"`
	TunnelID            string          `json:"tunnel_id"`
	ConnectorID         string          `json:"connector_id,omitempty"`
	SessionID           string          `json:"session_id,omitempty"`
	ProcessGeneration   uint64          `json:"process_generation,omitempty"`
	PreviousGeneration  uint64          `json:"previous_generation"`
	Generation          uint64          `json:"generation"`
	PreviousContentHash string          `json:"previous_content_hash"`
	ContentHash         string          `json:"content_hash"`
	Payload             json.RawMessage `json:"payload"`
}

func NewDelta(tunnelID string, previous Snapshot, generation uint64, payload []byte) (Delta, error) {
	if err := previous.Validate(); err != nil || generation != previous.Generation+1 {
		return Delta{}, codeError(ErrGenerationGap, ReasonGenerationGap, false, err)
	}
	snapshot, err := NewSnapshot(tunnelID, generation, payload)
	if err != nil {
		return Delta{}, err
	}
	return Delta{TunnelID: tunnelID, PreviousGeneration: previous.Generation, Generation: generation, PreviousContentHash: previous.ContentHash, ContentHash: snapshot.ContentHash, Payload: snapshot.Payload}, nil
}

func (d Delta) Validate() error {
	if ValidateIdentifier(d.TunnelID) != nil || d.AccountID != "" && ValidateIdentifier(d.AccountID) != nil || d.SessionID != "" && ValidateIdentifier(d.SessionID) != nil || !hashPattern.MatchString(d.PreviousContentHash) || !hashPattern.MatchString(d.ContentHash) || len(d.Payload) == 0 || len(d.Payload) > MaxDeltaBytes {
		return ErrInvalidInput
	}
	if d.PreviousGeneration == 0 || d.Generation != d.PreviousGeneration+1 {
		return codeError(ErrGenerationGap, ReasonGenerationGap, true, nil)
	}
	canonical, err := canonicalJSON(d.Payload, MaxDeltaBytes)
	if err != nil || !bytes.Equal(canonical, d.Payload) {
		return codeError(ErrContentHashMismatch, ReasonGenerationGap, false, err)
	}
	digest := sha256.Sum256(canonical)
	if d.ContentHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return codeError(ErrContentHashMismatch, ReasonGenerationGap, false, nil)
	}
	if err := validateConfigSnapshotPayload(canonical, d.TunnelID, d.Generation); err != nil {
		return codeError(ErrDeltaRejected, ReasonGenerationGap, false, err)
	}
	return nil
}

func (d Delta) ValidateBound() error {
	if ValidateIdentifier(d.AccountID) != nil || ValidateIdentifier(d.ConnectorID) != nil || ValidateIdentifier(d.SessionID) != nil || d.ProcessGeneration == 0 {
		return ErrInvalidInput
	}
	return d.Validate()
}

type AckKind string

const (
	AckSnapshot AckKind = "snapshot"
	AckDelta    AckKind = "delta"
	AckReady    AckKind = "ready"
	AckRenewal  AckKind = "auth_renew"
)

type AckStatus string

const (
	AckApplied          AckStatus = "applied"
	AckDuplicate        AckStatus = "duplicate"
	AckRejected         AckStatus = "rejected"
	AckSnapshotRequired AckStatus = "snapshot_required"
)

type Ack struct {
	AccountID         string    `json:"account_id"`
	TunnelID          string    `json:"tunnel_id"`
	ConnectorID       string    `json:"connector_id"`
	SessionID         string    `json:"session_id"`
	ProcessGeneration uint64    `json:"process_generation"`
	Kind              AckKind   `json:"kind"`
	Status            AckStatus `json:"status"`
	Generation        uint64    `json:"generation"`
	ContentHash       string    `json:"content_hash"`
	Code              Code      `json:"code,omitempty"`
}

func (a Ack) Validate() error {
	if ValidateIdentifier(a.AccountID) != nil || ValidateIdentifier(a.TunnelID) != nil || ValidateIdentifier(a.ConnectorID) != nil || ValidateIdentifier(a.SessionID) != nil || a.ProcessGeneration == 0 || (a.Kind != AckSnapshot && a.Kind != AckDelta && a.Kind != AckReady && a.Kind != AckRenewal) || (a.Status != AckApplied && a.Status != AckDuplicate && a.Status != AckRejected && a.Status != AckSnapshotRequired) || a.Generation == 0 || !hashPattern.MatchString(a.ContentHash) {
		return ErrInvalidInput
	}
	if a.Status == AckRejected && (a.Code == "" || !validCode(a.Code)) || a.Status != AckRejected && a.Code != "" {
		return ErrInvalidInput
	}
	return nil
}

type Readiness struct {
	AccountID         string `json:"account_id"`
	SessionID         string `json:"session_id"`
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	ProcessGeneration uint64 `json:"process_generation"`
	Generation        uint64 `json:"generation"`
	ContentHash       string `json:"content_hash"`
	EdgeReady         bool   `json:"edge_ready"`
	RouteReady        bool   `json:"route_ready"`
	OriginReady       bool   `json:"origin_ready"`
}

func (r Readiness) Validate() error {
	if ValidateIdentifier(r.AccountID) != nil || ValidateIdentifier(r.SessionID) != nil || ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.ConnectorID) != nil || r.ProcessGeneration == 0 || r.Generation == 0 || !hashPattern.MatchString(r.ContentHash) {
		return ErrInvalidInput
	}
	return nil
}

type Heartbeat struct {
	AccountID             string    `json:"account_id"`
	SessionID             string    `json:"session_id"`
	TunnelID              string    `json:"tunnel_id"`
	ConnectorID           string    `json:"connector_id"`
	ProcessGeneration     uint64    `json:"process_generation"`
	LastAppliedGeneration uint64    `json:"last_applied_generation"`
	LastAppliedHash       string    `json:"last_applied_content_hash"`
	SentAt                time.Time `json:"sent_at"`
}

func (h Heartbeat) Validate() error {
	if ValidateIdentifier(h.AccountID) != nil || ValidateIdentifier(h.SessionID) != nil || ValidateIdentifier(h.TunnelID) != nil || ValidateIdentifier(h.ConnectorID) != nil || h.ProcessGeneration == 0 || h.LastAppliedGeneration == 0 || !hashPattern.MatchString(h.LastAppliedHash) || h.SentAt.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

type HeartbeatAck struct {
	AccountID         string    `json:"account_id"`
	TunnelID          string    `json:"tunnel_id"`
	ConnectorID       string    `json:"connector_id"`
	SessionID         string    `json:"session_id"`
	ProcessGeneration uint64    `json:"process_generation"`
	LeaseExpiresAt    time.Time `json:"lease_expires_at"`
	ServerTime        time.Time `json:"server_time"`
}

func (h HeartbeatAck) Validate(now time.Time) error {
	if ValidateIdentifier(h.AccountID) != nil || ValidateIdentifier(h.TunnelID) != nil || ValidateIdentifier(h.ConnectorID) != nil || ValidateIdentifier(h.SessionID) != nil || h.ProcessGeneration == 0 || h.LeaseExpiresAt.IsZero() || !h.LeaseExpiresAt.After(now) || h.ServerTime.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

// DrainStatus is the finite state reported by a connector while it stops
// admitting new streams and lets existing streams finish.
type DrainStatus string

const (
	DrainAccepted  DrainStatus = "accepted"
	DrainProgress  DrainStatus = "progress"
	DrainCompleted DrainStatus = "completed"
	DrainForced    DrainStatus = "forced_close"
	DrainRejected  DrainStatus = "rejected"
)

const MaxActiveStreams = 1 << 20

// Drain is a server-to-connector request. The target generation and hash are
// part of the request so a stale process cannot drain a replacement session or
// a different configuration. StopNewStreams is deliberately required: a
// request that only looks like a status probe is not a drain operation.
type Drain struct {
	AccountID          string    `json:"account_id"`
	TunnelID           string    `json:"tunnel_id"`
	ConnectorID        string    `json:"connector_id"`
	SessionID          string    `json:"session_id"`
	ProcessGeneration  uint64    `json:"process_generation"`
	DrainID            string    `json:"drain_id"`
	Generation         uint64    `json:"generation"`
	ContentHash        string    `json:"content_hash"`
	Deadline           time.Time `json:"deadline"`
	StopNewStreams     bool      `json:"stop_new_streams"`
	ForceAfterDeadline bool      `json:"force_after_deadline"`
}

func (d Drain) Validate(now time.Time) error {
	if ValidateIdentifier(d.AccountID) != nil || ValidateIdentifier(d.TunnelID) != nil || ValidateIdentifier(d.ConnectorID) != nil || ValidateIdentifier(d.SessionID) != nil || ValidateIdentifier(d.DrainID) != nil || d.ProcessGeneration == 0 || d.Generation == 0 || !hashPattern.MatchString(d.ContentHash) || d.Deadline.IsZero() || !d.StopNewStreams {
		return ErrInvalidInput
	}
	if !now.IsZero() && (!d.Deadline.After(now) || d.Deadline.Sub(now) > MaxLease) {
		return ErrInvalidInput
	}
	return nil
}

// DrainAck is emitted first when the connector accepts the drain and again as
// streams leave. Completion is explicit. A forced close is represented by a
// distinct status and code, so callers do not have to infer it from a message.
type DrainAck struct {
	AccountID         string      `json:"account_id"`
	TunnelID          string      `json:"tunnel_id"`
	ConnectorID       string      `json:"connector_id"`
	SessionID         string      `json:"session_id"`
	ProcessGeneration uint64      `json:"process_generation"`
	DrainID           string      `json:"drain_id"`
	Generation        uint64      `json:"generation"`
	ContentHash       string      `json:"content_hash"`
	Status            DrainStatus `json:"status"`
	ActiveStreams     uint32      `json:"active_streams"`
	ForcedClose       bool        `json:"forced_close"`
	Code              Code        `json:"code,omitempty"`
}

func (a DrainAck) Validate(now time.Time) error {
	if ValidateIdentifier(a.AccountID) != nil || ValidateIdentifier(a.TunnelID) != nil || ValidateIdentifier(a.ConnectorID) != nil || ValidateIdentifier(a.SessionID) != nil || ValidateIdentifier(a.DrainID) != nil || a.ProcessGeneration == 0 || a.Generation == 0 || !hashPattern.MatchString(a.ContentHash) || a.ActiveStreams > MaxActiveStreams {
		return ErrInvalidInput
	}
	switch a.Status {
	case DrainAccepted, DrainProgress:
		if a.ForcedClose || a.Code != "" {
			return ErrInvalidInput
		}
	case DrainCompleted:
		if a.ActiveStreams != 0 || a.ForcedClose || a.Code != "" {
			return ErrInvalidInput
		}
	case DrainForced:
		if !a.ForcedClose || a.Code != CodeDrainTimeout || a.ActiveStreams != 0 {
			return ErrInvalidInput
		}
	case DrainRejected:
		if a.ForcedClose || a.Code != CodeDrainRejected {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	if a.Code != "" && !validCode(a.Code) {
		return ErrInvalidInput
	}
	_ = now
	return nil
}

type Disconnect struct {
	AccountID         string           `json:"account_id"`
	TunnelID          string           `json:"tunnel_id"`
	ConnectorID       string           `json:"connector_id"`
	SessionID         string           `json:"session_id"`
	ProcessGeneration uint64           `json:"process_generation"`
	Reason            DisconnectReason `json:"reason"`
	Retryable         bool             `json:"retryable"`
	Message           string           `json:"message,omitempty"`
}

type Reject struct {
	AccountID         string           `json:"account_id"`
	TunnelID          string           `json:"tunnel_id"`
	ConnectorID       string           `json:"connector_id"`
	SessionID         string           `json:"session_id"`
	ProcessGeneration uint64           `json:"process_generation"`
	Code              Code             `json:"code"`
	Reason            DisconnectReason `json:"reason"`
	Retryable         bool             `json:"retryable"`
	Message           string           `json:"message,omitempty"`
}

func (r Reject) Validate() error {
	if ValidateIdentifier(r.AccountID) != nil || ValidateIdentifier(r.TunnelID) != nil || ValidateIdentifier(r.ConnectorID) != nil || ValidateIdentifier(r.SessionID) != nil || r.ProcessGeneration == 0 || !validCode(r.Code) || !validDisconnectReason(r.Reason) || len(r.Message) > MaxReasonMessage {
		return ErrInvalidInput
	}
	return nil
}

func (d Disconnect) Validate() error {
	if ValidateIdentifier(d.AccountID) != nil || ValidateIdentifier(d.TunnelID) != nil || ValidateIdentifier(d.ConnectorID) != nil || ValidateIdentifier(d.SessionID) != nil || d.ProcessGeneration == 0 || !validDisconnectReason(d.Reason) || len(d.Message) > MaxReasonMessage {
		return ErrInvalidInput
	}
	return nil
}

func validDisconnectReason(reason DisconnectReason) bool {
	switch reason {
	case ReasonProtocolMismatch, ReasonCapabilityMissing, ReasonMalformed, ReasonAuthentication, ReasonCredentialExpired, ReasonLeaseExpired, ReasonHeartbeatTimeout, ReasonSessionReplaced, ReasonStaleGeneration, ReasonSnapshotRejected, ReasonGenerationGap, ReasonCredentialRotation, ReasonCanceled, ReasonServerShutdown, ReasonProtocolClosed:
		return true
	default:
		return false
	}
}

func validCode(code Code) bool {
	switch code {
	case CodeInvalidInput, CodeMalformedFrame, CodeFrameTooLarge, CodeProtocolIncompatible, CodeCapabilityMissing, CodeAuthenticationFailed, CodeCredentialExpired, CodeIdentityMismatch, CodeSessionConflict, CodeSessionClosed, CodeLeaseExpired, CodeHeartbeatTimeout, CodeSnapshotRequired, CodeGenerationGap, CodeStaleGeneration, CodeContentHashMismatch, CodeSnapshotRejected, CodeDeltaRejected, CodeNotReady, CodeCanceled, CodeStaleSession, CodeUnsupportedMessage, CodeDrainRejected, CodeDrainTimeout, CodeCredentialRotationRejected, CodeCredentialRotationNotReady, CodeCredentialRotationFailed:
		return true
	default:
		return false
	}
}

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// PreparedConfig is a two-phase configuration change. Prepare must stage the
// candidate without changing active traffic. Activate is called only after
// edge, route, and origin readiness have all been observed. Abort is safe to
// call after any failed preparation or activation.
type PreparedConfig interface {
	Activate(context.Context) error
	Abort(context.Context) error
}

type ConfigApplier interface {
	PrepareSnapshot(context.Context, Snapshot) (PreparedConfig, error)
	PrepareDelta(context.Context, Delta) (PreparedConfig, error)
}

// canonicalJSON validates duplicate keys, depth, trailing data and forbidden
// secret-bearing fields before a payload is hashed or handed to an applier.
func canonicalJSON(data []byte, limit int) ([]byte, error) {
	if len(data) == 0 || len(data) > limit || rejectDuplicateKeys(data) != nil {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidInput
	}
	if err := rejectSecretFields(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > limit {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > MaxJSONDepth {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key := keyToken.(string)
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			values := make([]any, 0)
			for decoder.More() {
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				values = append(values, child)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return values, nil
		default:
			return nil, errors.New("invalid delimiter")
		}
	default:
		return token, nil
	}
}

func rejectSecretFields(value any) error {
	var visit func(any) error
	visit = func(current any) error {
		switch value := current.(type) {
		case map[string]any:
			for key, child := range value {
				normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
				switch normalized {
				case "accesstoken", "apikey", "authorization", "clientsecret", "cookie", "headers", "password", "privatekey", "refreshtoken", "requestbody", "requestheaders", "responsebody", "responseheaders", "secret", "sessiontoken", "setcookie", "token":
					return ErrInvalidInput
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := visit(child); err != nil {
					return err
				}
			}
		case string:
			upper := strings.ToUpper(strings.TrimSpace(value))
			if strings.HasPrefix(upper, "BEARER ") || strings.Contains(upper, "BEGIN PRIVATE KEY") {
				return ErrInvalidInput
			}
			if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() {
				if parsed.User != nil {
					return ErrInvalidInput
				}
				for key := range parsed.Query() {
					normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
					switch normalized {
					case "accesstoken", "apikey", "authorization", "clientsecret", "password", "refreshtoken", "secret", "sessiontoken", "token":
						return ErrInvalidInput
					}
				}
			}
		}
		return nil
	}
	return visit(value)
}

func newOpaqueID(prefix string) (string, error) {
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(random[:]), nil
}
