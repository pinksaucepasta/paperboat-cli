package contracttest

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCredentialContractVector(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/fixtures/credentials/terminal-operation.ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TestOnly bool `json:"test_only"`
		Key      struct {
			Public string `json:"public_base64url"`
		} `json:"key"`
		Claims struct {
			Audience string   `json:"aud"`
			Scopes   []string `json:"scope"`
		} `json:"claims"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(vector.Token, ".")
	if !vector.TestOnly || len(parts) != 3 || vector.Claims.Audience != "paperboat-helper" || len(vector.Claims.Scopes) != 1 || vector.Claims.Scopes[0] != "terminal:operate" {
		t.Fatalf("invalid terminal credential vector")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(vector.Key.Public)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("credential signature is invalid")
	}
}

func TestCredentialRejectionsNeverMutate(t *testing.T) {
	f, err := os.Open("../../testdata/contracts/fixtures/credentials/negative.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var vector struct {
			Valid   bool   `json:"valid"`
			Error   string `json:"error"`
			Mutated bool   `json:"mutated"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if vector.Valid || vector.Error == "" || vector.Mutated {
			t.Fatalf("unsafe credential rejection: %#v", vector)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 8 {
		t.Fatalf("credential rejection cases=%d, want at least 8", count)
	}
}
