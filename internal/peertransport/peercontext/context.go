// Package peercontext owns the canonical endpoint, authorization, operation,
// and generation tuple bound into every private peer transport.
package peercontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
)

const Version = 1

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Context struct {
	AccountID                string
	UserID                   string
	DeviceID                 string
	MachineID                string
	InitiatorCertificateHash [32]byte
	ResponderCertificateHash [32]byte
	HostGeneration           uint64
	AuthorizationGeneration  uint64
	IntentID                 string
	OperationID              string
	Consumer                 string
	InitiatorRole            string
	ResponderRole            string
	AttemptGeneration        uint64
}

func (c Context) MarshalBinary() ([]byte, error) {
	strings := []string{c.AccountID, c.UserID, c.DeviceID, c.MachineID, c.IntentID, c.OperationID, c.Consumer, c.InitiatorRole, c.ResponderRole}
	names := [...]string{"account_id", "user_id", "device_id", "machine_id", "intent_id", "operation_id", "consumer", "initiator_role", "responder_role"}
	for index, value := range strings {
		if !identifierPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid peer context identifier: %s (%s)", names[index], identifierIssue(value))
		}
	}
	if c.HostGeneration == 0 || c.AuthorizationGeneration == 0 || c.AttemptGeneration == 0 {
		return nil, errors.New("invalid peer context generation")
	}
	if allZero(c.InitiatorCertificateHash[:]) || allZero(c.ResponderCertificateHash[:]) {
		return nil, errors.New("peer context certificate hashes must not be zero")
	}
	encoded := []byte{'P', 'B', 'P', 'C', Version}
	for _, value := range strings[:4] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, c.InitiatorCertificateHash[:]...)
	encoded = append(encoded, c.ResponderCertificateHash[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, c.HostGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, c.AuthorizationGeneration)
	for _, value := range strings[4:] {
		encoded = appendString(encoded, value)
	}
	return binary.BigEndian.AppendUint64(encoded, c.AttemptGeneration), nil
}

func ParseBinary(encoded []byte) (Context, error) {
	if len(encoded) < 5 || !bytes.Equal(encoded[:5], []byte{'P', 'B', 'P', 'C', Version}) {
		return Context{}, errors.New("invalid peer context encoding")
	}
	reader := bytes.NewReader(encoded[5:])
	readString := func() (string, error) {
		var size uint16
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size == 0 || int(size) > reader.Len() {
			return "", errors.New("invalid peer context string")
		}
		value := make([]byte, int(size))
		if _, err := reader.Read(value); err != nil {
			return "", err
		}
		return string(value), nil
	}
	var result Context
	strings := []*string{&result.AccountID, &result.UserID, &result.DeviceID, &result.MachineID}
	for _, value := range strings {
		parsed, err := readString()
		if err != nil {
			return Context{}, err
		}
		*value = parsed
	}
	if reader.Len() < 32+32+8+8 {
		return Context{}, errors.New("invalid peer context encoding")
	}
	_, _ = reader.Read(result.InitiatorCertificateHash[:])
	_, _ = reader.Read(result.ResponderCertificateHash[:])
	_ = binary.Read(reader, binary.BigEndian, &result.HostGeneration)
	_ = binary.Read(reader, binary.BigEndian, &result.AuthorizationGeneration)
	strings = []*string{&result.IntentID, &result.OperationID, &result.Consumer, &result.InitiatorRole, &result.ResponderRole}
	for _, value := range strings {
		parsed, err := readString()
		if err != nil {
			return Context{}, err
		}
		*value = parsed
	}
	if reader.Len() != 8 || binary.Read(reader, binary.BigEndian, &result.AttemptGeneration) != nil {
		return Context{}, errors.New("invalid peer context encoding")
	}
	canonical, err := result.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Context{}, errors.New("invalid peer context encoding")
	}
	return result, nil
}

func identifierIssue(value string) string {
	if value == "" {
		return "empty"
	}
	if len(value) > 128 {
		return fmt.Sprintf("length=%d", len(value))
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '_' || character == '.' || character == ':' || character == '-') {
			continue
		}
		return fmt.Sprintf("byte[%d]=0x%02x", index, character)
	}
	return "non-canonical"
}

func (c Context) Hash() ([32]byte, error) {
	encoded, err := c.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func appendString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint16(target, uint16(len(value)))
	return append(target, value...)
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
