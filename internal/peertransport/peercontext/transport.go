package peercontext

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	transportContextVersion = 1
	streamContextVersion    = 1
)

// Transport identifies a reusable authenticated carrier. Operation and
// consumer authority deliberately do not belong to this context.
type Transport struct {
	AccountID                string
	UserID                   string
	DeviceID                 string
	MachineID                string
	InitiatorCertificateHash [32]byte
	ResponderCertificateHash [32]byte
	HostGeneration           uint64
	AuthorizationGeneration  uint64
	TransportID              string
	InitiatorRole            string
	ResponderRole            string
	AttemptGeneration        uint64
}

func (c Transport) MarshalBinary() ([]byte, error) {
	values := []string{c.AccountID, c.UserID, c.DeviceID, c.MachineID, c.TransportID, c.InitiatorRole, c.ResponderRole}
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return nil, errors.New("invalid peer transport identifier")
		}
	}
	if c.HostGeneration == 0 || c.AuthorizationGeneration == 0 || c.AttemptGeneration == 0 || allZero(c.InitiatorCertificateHash[:]) || allZero(c.ResponderCertificateHash[:]) {
		return nil, errors.New("invalid peer transport binding")
	}
	encoded := []byte{'P', 'B', 'P', 'T', transportContextVersion}
	for _, value := range values[:4] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, c.InitiatorCertificateHash[:]...)
	encoded = append(encoded, c.ResponderCertificateHash[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, c.HostGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, c.AuthorizationGeneration)
	for _, value := range values[4:] {
		encoded = appendString(encoded, value)
	}
	return binary.BigEndian.AppendUint64(encoded, c.AttemptGeneration), nil
}

func (c Transport) Hash() ([32]byte, error) {
	encoded, err := c.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// Stream binds one application operation and its credential to a reusable
// transport. CredentialHash is the hash of the exact opaque credential bytes;
// the host still verifies that credential through the existing verifier.
type Stream struct {
	TransportHash  [32]byte
	OperationID    string
	Consumer       string
	StreamID       string
	CredentialHash [32]byte
	DeadlineUnix   int64
	MaximumBytes   uint64
}

func (c Stream) MarshalBinary() ([]byte, error) {
	if allZero(c.TransportHash[:]) || allZero(c.CredentialHash[:]) || !identifierPattern.MatchString(c.OperationID) || !identifierPattern.MatchString(c.Consumer) || !identifierPattern.MatchString(c.StreamID) || c.DeadlineUnix <= 0 || c.MaximumBytes == 0 {
		return nil, errors.New("invalid peer stream binding")
	}
	encoded := []byte{'P', 'B', 'P', 'S', streamContextVersion}
	encoded = append(encoded, c.TransportHash[:]...)
	encoded = appendString(encoded, c.OperationID)
	encoded = appendString(encoded, c.Consumer)
	encoded = appendString(encoded, c.StreamID)
	encoded = append(encoded, c.CredentialHash[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(c.DeadlineUnix))
	return binary.BigEndian.AppendUint64(encoded, c.MaximumBytes), nil
}

func (c Stream) Hash() ([32]byte, error) {
	encoded, err := c.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
