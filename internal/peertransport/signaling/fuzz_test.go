package signaling

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzDecode(f *testing.F) {
	binding := testBinding()
	valid, err := Encode(Message{
		Schema:            Schema,
		IntentID:          binding.IntentID,
		AttemptGeneration: binding.AttemptGeneration,
		NetworkGeneration: binding.NetworkGeneration,
		Role:              binding.Role,
		Sequence:          1,
		Kind:              KindCredentials,
		Ufrag:             "ufrag01",
		Password:          strings.Repeat("p", 22),
	}, binding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte(`{"schema":"paperboat.peer-signaling/v1"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		message, err := Decode(raw, binding)
		if err != nil {
			return
		}
		canonical, err := Encode(message, binding)
		if err != nil {
			t.Fatalf("accepted message cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, raw) {
			t.Fatal("accepted signaling message is not canonical")
		}
	})
}
