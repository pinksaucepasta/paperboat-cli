package peerquic

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

const (
	exporterLabel = "EXPORTER-paperboat-e2ee-v1"
	bindingSize   = 32
	firstHeader   = 36 // version, flags, binding, payload length
	recordVersion = 1
)

func CandidateBinding(state tls.ConnectionState, transport peercontext.Transport) ([bindingSize]byte, error) {
	encoded, err := transport.MarshalBinary()
	if err != nil {
		return [bindingSize]byte{}, err
	}
	return exporterBinding(state, append([]byte("PBCANDIDATE\x00"), encoded...))
}

var (
	ErrBinding = errors.New("peer QUIC exporter binding mismatch")
	ErrRecord  = errors.New("invalid peer QUIC first record")
)

// ExporterBinding derives the per-connection binding used by the first
// application record. The context is the canonical identity/intent tuple
// constructed by the caller; it is never sent separately on the wire.
func ExporterBinding(state tls.ConnectionState, context peercontext.Context) ([bindingSize]byte, error) {
	encoded, err := context.MarshalBinary()
	if err != nil {
		return [bindingSize]byte{}, err
	}
	return exporterBinding(state, encoded)
}

// ExporterBindingForStream binds one authorized operation stream to a reusable
// peer transport. The embedded transport hash must match the supplied carrier.
func ExporterBindingForStream(state tls.ConnectionState, transport peercontext.Transport, stream peercontext.Stream) ([bindingSize]byte, error) {
	transportEncoded, err := transport.MarshalBinary()
	if err != nil {
		return [bindingSize]byte{}, err
	}
	transportHash, err := transport.Hash()
	if err != nil || subtle.ConstantTimeCompare(transportHash[:], stream.TransportHash[:]) != 1 {
		return [bindingSize]byte{}, ErrBinding
	}
	streamEncoded, err := stream.MarshalBinary()
	if err != nil {
		return [bindingSize]byte{}, err
	}
	encoded := append(append([]byte{'P', 'B', 'Q', 'S', 1}, transportEncoded...), streamEncoded...)
	return exporterBinding(state, encoded)
}

func exporterBinding(state tls.ConnectionState, encoded []byte) ([bindingSize]byte, error) {
	var binding [bindingSize]byte
	if !state.HandshakeComplete {
		return binding, errors.New("TLS handshake is incomplete")
	}
	value, err := state.ExportKeyingMaterial(exporterLabel, encoded, bindingSize)
	if err != nil {
		return binding, fmt.Errorf("export peer QUIC E2EE binding: %w", err)
	}
	copy(binding[:], value)
	return binding, nil
}

// SealFirstRecord binds the initial private header and bytes to the TLS
// connection. The binding is authenticated by TLS; the record itself is a
// bounded, deterministic wrapper so dispatch cannot occur before validation.
func SealFirstRecord(binding [bindingSize]byte, payload []byte) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, ErrRecord
	}
	record := make([]byte, firstHeader+len(payload))
	record[0] = recordVersion
	copy(record[4:36], binding[:])
	binary.BigEndian.PutUint16(record[2:4], uint16(len(payload)))
	copy(record[firstHeader:], payload)
	return record, nil
}

// OpenFirstRecord validates the version, exact binding, and length before
// exposing any application bytes. Mismatch is terminal for the QUIC stream.
func OpenFirstRecord(expected [bindingSize]byte, record []byte) ([]byte, error) {
	if len(record) < firstHeader || record[0] != recordVersion || record[1] != 0 {
		return nil, ErrRecord
	}
	length := int(binary.BigEndian.Uint16(record[2:4]))
	if length != len(record)-firstHeader {
		return nil, ErrRecord
	}
	if subtle.ConstantTimeCompare(expected[:], record[4:36]) != 1 {
		return nil, ErrBinding
	}
	return append([]byte(nil), record[firstHeader:]...), nil
}

func ReadFirstRecord(reader io.Reader, expected [bindingSize]byte) ([]byte, error) {
	return ReadFirstRecordAuthorized(reader, func([]byte) ([bindingSize]byte, error) { return expected, nil })
}

// ReadFirstRecordAuthorized reads only the bounded first record, derives its
// expected binding from the still-untrusted payload, and authenticates the
// complete record before returning payload bytes to the caller.
func ReadFirstRecordAuthorized(reader io.Reader, authorize func([]byte) ([bindingSize]byte, error)) ([]byte, error) {
	if reader == nil || authorize == nil {
		return nil, ErrRecord
	}
	header := make([]byte, firstHeader)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	record := make([]byte, firstHeader+length)
	copy(record, header)
	if _, err := io.ReadFull(reader, record[firstHeader:]); err != nil {
		return nil, err
	}
	expected, err := authorize(append([]byte(nil), record[firstHeader:]...))
	if err != nil {
		return nil, err
	}
	return OpenFirstRecord(expected, record)
}
