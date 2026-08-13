package recoverykey

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRecoveryKeyRoundTripAndCanonicalForm(t *testing.T) {
	seed := make([]byte, SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	encoded, err := Encode(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, Prefix) || encoded != strings.ToLower(encoded) {
		t.Fatalf("non-canonical encoding %q", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(decoded)
	if !bytes.Equal(decoded, seed) {
		t.Fatal("decoded seed differs")
	}
}

func TestRecoveryKeyRejectsInvalidInput(t *testing.T) {
	if _, err := Encode(make([]byte, SeedSize-1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short seed error = %v", err)
	}
	valid, err := Encode(make([]byte, SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	last := valid[len(valid)-1]
	if last == 'a' {
		last = 'b'
	} else {
		last = 'a'
	}
	mutated := valid[:len(valid)-1] + string(last)
	for _, value := range []string{"", " " + valid, strings.ToUpper(valid), strings.Replace(valid, Prefix, "pb-e2ee-recovery-v2-", 1), mutated} {
		if decoded, err := Decode(value); !errors.Is(err, ErrInvalid) || decoded != nil {
			t.Fatalf("Decode(%q) = %x, %v", value, decoded, err)
		}
	}
}
