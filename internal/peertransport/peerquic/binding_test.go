package peerquic

import (
	"bytes"
	"errors"
	"testing"
)

func TestFirstRecordRequiresExactExporterBinding(t *testing.T) {
	var binding [bindingSize]byte
	copy(binding[:], bytes.Repeat([]byte{7}, bindingSize))
	payload := []byte("private-header-and-initial-bytes")
	record, err := SealFirstRecord(binding, payload)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenFirstRecord(binding, record)
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	opened[0] ^= 1
	if bytes.Equal(opened, record[firstHeader:]) {
		t.Fatal("opened payload aliases record")
	}

	wrong := binding
	wrong[0] ^= 1
	if _, err := OpenFirstRecord(wrong, record); !errors.Is(err, ErrBinding) {
		t.Fatalf("binding mismatch err=%v", err)
	}
}

func TestReadFirstRecordHandlesFragmentedInput(t *testing.T) {
	var binding [32]byte
	binding[0] = 9
	record, err := SealFirstRecord(binding, []byte("native-preface"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ReadFirstRecord(&oneByteReader{reader: bytes.NewReader(record)}, binding)
	if err != nil || string(payload) != "native-preface" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
}

func TestReadFirstRecordAuthorizedAuthenticatesAfterBoundedInspection(t *testing.T) {
	want := [bindingSize]byte{1, 2, 3}
	record, err := SealFirstRecord(want, []byte("stream-header"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	payload, err := ReadFirstRecordAuthorized(bytes.NewReader(record), func(value []byte) ([bindingSize]byte, error) {
		called = true
		if string(value) != "stream-header" {
			t.Fatalf("payload=%q", value)
		}
		return want, nil
	})
	if err != nil || !called || string(payload) != "stream-header" {
		t.Fatalf("payload=%q called=%t err=%v", payload, called, err)
	}
}

type oneByteReader struct{ reader *bytes.Reader }

func (r *oneByteReader) Read(target []byte) (int, error) {
	if len(target) > 1 {
		target = target[:1]
	}
	return r.reader.Read(target)
}

func TestFirstRecordRejectsMalformedFraming(t *testing.T) {
	var binding [bindingSize]byte
	binding[0] = 1
	record, err := SealFirstRecord(binding, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"short":    func(value []byte) []byte { return value[:firstHeader-1] },
		"version":  func(value []byte) []byte { value[0]++; return value },
		"reserved": func(value []byte) []byte { value[1] = 1; return value },
		"length":   func(value []byte) []byte { value[3]++; return value },
	} {
		t.Run(name, func(t *testing.T) {
			changed := mutate(append([]byte(nil), record...))
			if _, err := OpenFirstRecord(binding, changed); !errors.Is(err, ErrRecord) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := SealFirstRecord(binding, make([]byte, 65536)); !errors.Is(err, ErrRecord) {
		t.Fatalf("oversized err=%v", err)
	}
}
