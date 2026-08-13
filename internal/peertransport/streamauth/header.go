// Package streamauth owns the canonical authorization header for one
// operation opened over a reusable peer transport.
package streamauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
)

const (
	Version           = 1
	MaximumHeaderSize = 24 << 10
	MaximumCredential = 16 << 10
)

var ErrInvalid = errors.New("invalid peer stream authorization header")

type Header struct {
	Version      int    `json:"version"`
	OperationID  string `json:"operation_id"`
	Consumer     string `json:"consumer"`
	StreamID     string `json:"stream_id"`
	Credential   string `json:"credential"`
	DeadlineUnix int64  `json:"deadline_unix"`
	MaximumBytes uint64 `json:"maximum_bytes"`
	Resumable    bool   `json:"resumable"`
}

func New(operationID, consumer, streamID, credential string, deadline time.Time, maximumBytes uint64) (Header, error) {
	value := Header{Version: Version, OperationID: operationID, Consumer: consumer, StreamID: streamID, Credential: credential, DeadlineUnix: deadline.UTC().Unix(), MaximumBytes: maximumBytes}
	if value.Validate(time.Time{}) != nil {
		return Header{}, ErrInvalid
	}
	return value, nil
}

func (h Header) Validate(now time.Time) error {
	if h.Version != Version || h.OperationID == "" || len(h.OperationID) > 128 || h.Consumer == "" || len(h.Consumer) > 128 || h.StreamID == "" || len(h.StreamID) > 128 || h.Credential == "" || len(h.Credential) > MaximumCredential || h.DeadlineUnix <= 0 || h.MaximumBytes == 0 {
		return ErrInvalid
	}
	deadline := time.Unix(h.DeadlineUnix, 0)
	if !now.IsZero() && !deadline.After(now) {
		return ErrInvalid
	}
	return nil
}

func (h Header) MarshalBinary() ([]byte, error) {
	if h.Validate(time.Time{}) != nil {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(h)
	if err != nil || len(encoded) > MaximumHeaderSize {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func Parse(encoded []byte, now time.Time) (Header, error) {
	if len(encoded) == 0 || len(encoded) > MaximumHeaderSize {
		return Header{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value Header
	if err := decoder.Decode(&value); err != nil || value.Validate(now) != nil {
		return Header{}, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		return Header{}, ErrInvalid
	}
	canonical, err := value.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Header{}, ErrInvalid
	}
	return value, nil
}

func (h Header) Grant() peersession.StreamGrant {
	return peersession.StreamGrant{OperationID: h.OperationID, Consumer: h.Consumer, StreamID: h.StreamID, Credential: []byte(h.Credential), Deadline: time.Unix(h.DeadlineUnix, 0).UTC(), MaximumBytes: h.MaximumBytes}
}
