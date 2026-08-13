package transfercrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

const (
	maxControlPayload = 512
	controlVersion    = 1
)

var ErrControlRejected = errors.New("transfer key control rejected")

type KeyControlBinding struct {
	OperationID string
	TransferID  string
	Generation  uint64
	ExpiresAt   time.Time
}

func DeliverKey(writer io.ReadWriter, binding KeyControlBinding, material KeyMaterial) error {
	if writer == nil {
		return ErrInvalid
	}
	payload, err := marshalKeyControl(binding, material)
	if err != nil {
		return err
	}
	if err := writeControlFrame(writer, payload); err != nil {
		return fmt.Errorf("send transfer key: %w", err)
	}
	want := controlAcknowledgement(payload)
	ack := make([]byte, len(want))
	if _, err := io.ReadFull(writer, ack); err != nil {
		return fmt.Errorf("read transfer key acknowledgement: %w", err)
	}
	if !bytes.Equal(ack, want[:]) {
		return ErrControlRejected
	}
	return nil
}

func ReceiveKey(writer io.ReadWriter, expected KeyControlBinding, context peercontext.Context, vault *KeyVault) error {
	if writer == nil || vault == nil || validateControlBinding(expected) != nil || context.OperationID != expected.OperationID || context.Consumer != "file_transfer_key" {
		return ErrInvalid
	}
	payload, err := readControlFrame(writer)
	if err != nil {
		return fmt.Errorf("read transfer key: %w", err)
	}
	binding, material, err := parseKeyControl(payload)
	if err != nil || binding.OperationID != expected.OperationID || binding.TransferID != expected.TransferID || binding.Generation != expected.Generation || !binding.ExpiresAt.Equal(expected.ExpiresAt.UTC().Truncate(time.Second)) {
		return ErrControlRejected
	}
	if err := vault.SaveBound(binding.TransferID, binding.Generation, material, binding.ExpiresAt, context); err != nil {
		return fmt.Errorf("store transfer key: %w", err)
	}
	ack := controlAcknowledgement(payload)
	if err := writeAll(writer, ack[:]); err != nil {
		return fmt.Errorf("acknowledge transfer key: %w", err)
	}
	return nil
}

func marshalKeyControl(binding KeyControlBinding, material KeyMaterial) ([]byte, error) {
	if err := validateControlBinding(binding); err != nil || !material.Valid() {
		return nil, ErrInvalid
	}
	key, err := material.MarshalBinary()
	if err != nil {
		return nil, err
	}
	payload := []byte{'P', 'B', 'K', 'C', controlVersion}
	payload = appendControlString(payload, binding.OperationID)
	payload = appendControlString(payload, binding.TransferID)
	payload = binary.BigEndian.AppendUint64(payload, binding.Generation)
	payload = binary.BigEndian.AppendUint64(payload, uint64(binding.ExpiresAt.UTC().Truncate(time.Second).Unix()))
	payload = append(payload, key...)
	if len(payload) > maxControlPayload {
		return nil, ErrInvalid
	}
	return payload, nil
}

func parseKeyControl(payload []byte) (KeyControlBinding, KeyMaterial, error) {
	if len(payload) < 5 || len(payload) > maxControlPayload || !bytes.Equal(payload[:5], []byte{'P', 'B', 'K', 'C', controlVersion}) {
		return KeyControlBinding{}, KeyMaterial{}, ErrInvalid
	}
	reader := bytes.NewReader(payload[5:])
	operationID, err := readControlString(reader)
	if err != nil {
		return KeyControlBinding{}, KeyMaterial{}, err
	}
	transferID, err := readControlString(reader)
	if err != nil {
		return KeyControlBinding{}, KeyMaterial{}, err
	}
	var generation, expiresUnix uint64
	if binary.Read(reader, binary.BigEndian, &generation) != nil || binary.Read(reader, binary.BigEndian, &expiresUnix) != nil || expiresUnix > uint64(1<<63-1) {
		return KeyControlBinding{}, KeyMaterial{}, ErrInvalid
	}
	key := make([]byte, reader.Len())
	if _, err := io.ReadFull(reader, key); err != nil {
		return KeyControlBinding{}, KeyMaterial{}, ErrInvalid
	}
	material, err := ParseKeyMaterial(key)
	binding := KeyControlBinding{OperationID: operationID, TransferID: transferID, Generation: generation, ExpiresAt: time.Unix(int64(expiresUnix), 0).UTC()}
	if err != nil || validateControlBinding(binding) != nil {
		return KeyControlBinding{}, KeyMaterial{}, ErrInvalid
	}
	return binding, material, nil
}

func validateControlBinding(value KeyControlBinding) error {
	if !validTransferID(value.OperationID) || !validTransferID(value.TransferID) || value.Generation == 0 || value.ExpiresAt.IsZero() || value.ExpiresAt.Nanosecond() != 0 || value.ExpiresAt.Unix() <= 0 {
		return ErrInvalid
	}
	return nil
}

func appendControlString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint16(target, uint16(len(value)))
	return append(target, value...)
}

func readControlString(reader *bytes.Reader) (string, error) {
	var size uint16
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || int(size) > reader.Len() {
		return "", ErrInvalid
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", ErrInvalid
	}
	return string(value), nil
}

func writeControlFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxControlPayload {
		return ErrInvalid
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readControlFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(header[:])
	if size == 0 || size > maxControlPayload {
		return nil, ErrInvalid
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func controlAcknowledgement(payload []byte) [37]byte {
	digest := sha256.Sum256(payload)
	var result [37]byte
	copy(result[:5], []byte{'P', 'B', 'K', 'A', controlVersion})
	copy(result[5:], digest[:])
	return result
}
