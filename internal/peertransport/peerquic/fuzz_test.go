package peerquic

import (
	"bytes"
	"testing"
)

func FuzzOpenFirstRecord(f *testing.F) {
	var binding [bindingSize]byte
	binding[0] = 1
	valid, err := SealFirstRecord(binding, []byte("private-header-and-initial-bytes"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add(make([]byte, firstHeader))

	f.Fuzz(func(t *testing.T, record []byte) {
		payload, err := OpenFirstRecord(binding, record)
		if err != nil {
			return
		}
		canonical, err := SealFirstRecord(binding, payload)
		if err != nil {
			t.Fatalf("accepted first record cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, record) {
			t.Fatal("accepted first record is not canonical")
		}
		if len(payload) > 0 {
			payload[0] ^= 1
			if bytes.Equal(payload, record[firstHeader:]) {
				t.Fatal("opened payload aliases wire record")
			}
		}
	})
}

func FuzzParseLifetimeFrame(f *testing.F) {
	var nonce [16]byte
	nonce[0] = 1
	valid := lifetimeFrame(lifetimeProbeRequest, nonce)
	f.Add(valid[:])
	f.Add([]byte(nil))
	f.Add(make([]byte, lifetimeProbeSize))

	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) != lifetimeProbeSize {
			return
		}
		var frame [lifetimeProbeSize]byte
		copy(frame[:], value)
		parsed, idle, err := parseLifetimeFrameWithIdle(frame, lifetimeProbeRequest)
		if err != nil {
			return
		}
		canonical := lifetimeFrameWithIdle(lifetimeProbeRequest, parsed, idle)
		if !bytes.Equal(canonical[:], value) {
			t.Fatal("accepted lifetime frame is not canonical")
		}
	})
}
