package environmente2ee

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var (
	canonicalEnc cbor.EncMode
	strictDec    cbor.DecMode
)

func init() {
	var err error
	canonicalEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strictDec, err = (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  16,
		MaxArrayElements: 1024,
		MaxMapPairs:      16,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		IntDec:           cbor.IntDecConvertSignedOrFail,
		UTF8:             cbor.UTF8RejectInvalid,
		BignumTag:        cbor.BignumTagForbidden,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func encode(value any) ([]byte, error) {
	encoded, err := canonicalEnc.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical CBOR: %w", err)
	}
	return encoded, nil
}

func decodeCanonical(raw []byte, max int, target any) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	if err := strictDec.Unmarshal(raw, target); err != nil {
		return ErrInvalid
	}
	reencoded, err := canonicalEnc.Marshal(reflect.ValueOf(target).Elem().Interface())
	if err != nil || !bytes.Equal(raw, reencoded) {
		return ErrInvalid
	}
	return nil
}

func array(value any, length int) ([]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) != length {
		return nil, ErrInvalid
	}
	return items, nil
}

func text(value any) (string, error) {
	v, ok := value.(string)
	if !ok {
		return "", ErrInvalid
	}
	return v, nil
}

func bytesValue(value any, length int) ([]byte, error) {
	v, ok := value.([]byte)
	if !ok || length >= 0 && len(v) != length {
		return nil, ErrInvalid
	}
	return append([]byte(nil), v...), nil
}

func uintValue(value any, allowZero bool) (uint64, error) {
	var result uint64
	switch v := value.(type) {
	case int64:
		if v < 0 {
			return 0, ErrInvalid
		}
		result = uint64(v)
	case uint64:
		result = v
	default:
		return 0, ErrInvalid
	}
	if result > MaximumContractInteger || !allowZero && result == 0 {
		return 0, ErrInvalid
	}
	return result, nil
}

func nullableText(value any) (*string, error) {
	if value == nil {
		return nil, nil
	}
	v, err := text(value)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func nullableBytes(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return bytesValue(value, -1)
}

func requireDomain(items []any, domain string, version uint64) error {
	got, err := text(items[0])
	if err != nil || got != domain {
		return ErrInvalid
	}
	v, err := uintValue(items[1], false)
	if err != nil || v != version {
		return ErrInvalid
	}
	return nil
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }

var ErrInvalid = errors.New("invalid environment E2EE document")
