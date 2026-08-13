package signaling

import "testing"

func TestCanonicalSubstrateURLCollapsesDefaultTLSPort(t *testing.T) {
	first, err := canonicalSubstrateURL("wss://SIGNAL.example.test/v1/peer-signaling")
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalSubstrateURL("wss://signal.example.test:443/v1/peer-signaling")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent signaling URLs differ: %q != %q", first, second)
	}
}
