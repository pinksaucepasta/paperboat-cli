package main

import (
	"encoding/json"
	"testing"
)

func TestCanonicalDocumentIsSortedAndBounded(t *testing.T) {
	data, err := canonicalDocument()
	if err != nil {
		t.Fatal(err)
	}
	var value document
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != schemaVersion || len(value.Metrics) == 0 {
		t.Fatalf("document=%+v", value)
	}
	for index, item := range value.Metrics {
		if index > 0 && value.Metrics[index-1].Name >= item.Name {
			t.Fatalf("metrics are not uniquely sorted at %q", item.Name)
		}
		for label, allowed := range item.Labels {
			if len(allowed) == 0 {
				t.Fatalf("metric %q label %q is unbounded", item.Name, label)
			}
			for valueIndex := 1; valueIndex < len(allowed); valueIndex++ {
				if allowed[valueIndex-1] >= allowed[valueIndex] {
					t.Fatalf("metric %q label %q values are not uniquely sorted", item.Name, label)
				}
			}
		}
	}
}

func TestRealMetricHandlerMatchesDescriptors(t *testing.T) {
	if err := verifyHandler(); err != nil {
		t.Fatal(err)
	}
}
