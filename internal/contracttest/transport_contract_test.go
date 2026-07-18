package contracttest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestHelperTransportVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/fixtures/helper/transport.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Case       string   `json:"case"`
			Valid      bool     `json:"valid"`
			WireChunks []string `json:"wire_chunks_base64"`
			Error      string   `json:"error"`
			CloseCode  int      `json:"close_code"`
			Count      int      `json:"expected_count"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	valid, invalid := 0, 0
	for _, vector := range fixture.Cases {
		if vector.Valid {
			valid++
		} else {
			invalid++
			if vector.Error == "" || vector.CloseCode == 0 {
				t.Errorf("%s: rejection lacks typed error or close code", vector.Case)
			}
		}
		switch vector.Case {
		case "structured-fragmented":
			if count, err := decodeStructuredFrames(vector.WireChunks); err != nil || count != 1 {
				t.Fatalf("fragmented structured frame count=%d err=%v", count, err)
			}
		case "structured-coalesced":
			if count, err := decodeStructuredFrames(vector.WireChunks); err != nil || count != vector.Count {
				t.Fatalf("coalesced structured frame count=%d err=%v", count, err)
			}
		case "binary-fragmented":
			wire, err := joinChunks(vector.WireChunks)
			if err != nil || len(wire) != 16 || binary.BigEndian.Uint32(wire[:4]) != 12 || binary.BigEndian.Uint64(wire[5:13]) != 42 {
				t.Fatalf("invalid binary vector: %x err=%v", wire, err)
			}
		}
	}
	if valid == 0 || invalid == 0 {
		t.Fatal("transport contract requires positive and negative vectors")
	}
}

func joinChunks(chunks []string) ([]byte, error) {
	var wire []byte
	for _, chunk := range chunks {
		decoded, err := base64.StdEncoding.DecodeString(chunk)
		if err != nil {
			return nil, err
		}
		wire = append(wire, decoded...)
	}
	return wire, nil
}

func decodeStructuredFrames(chunks []string) (int, error) {
	wire, err := joinChunks(chunks)
	if err != nil {
		return 0, err
	}
	count := 0
	for len(wire) > 0 {
		if len(wire) < 4 {
			return count, fmt.Errorf("truncated length")
		}
		length := int(binary.BigEndian.Uint32(wire[:4]))
		wire = wire[4:]
		if length > 65536 || len(wire) < length || !json.Valid(wire[:length]) {
			return count, fmt.Errorf("invalid structured frame")
		}
		wire = wire[length:]
		count++
	}
	return count, nil
}
