package hoststate

import (
	"errors"
	"testing"
)

func TestCredentialReferenceAllowsOpaqueLocalReferenceBeforeServerConnectorID(t *testing.T) {
	for _, reference := range []string{
		"keychain://paperboat/connectors/local-key_01",
		"credential-manager://paperboat/connectors/local-key_02",
		"secret-service://paperboat/connectors/local-key_03",
		"protected-file://paperboat/connectors/credential_01J8Z4D7JQ2F5M8N0R3S6T9V",
		"tpm://paperboat/connectors/tpm-key_05",
	} {
		t.Run(reference, func(t *testing.T) {
			value := CredentialReference{Reference: reference, Generation: 4}
			for _, connectorID := range []string{"con_server_assigned", "con_other_assigned"} {
				if err := value.validate(connectorID); err != nil {
					t.Fatalf("reference %q with server connector %q: %v", reference, connectorID, err)
				}
			}
		})
	}
}

func TestCredentialReferenceRejectsUnsafeLocalReference(t *testing.T) {
	tests := []struct {
		name      string
		reference string
	}{
		{name: "empty", reference: ""},
		{name: "wrong scheme", reference: "https://paperboat/connectors/credential_01"},
		{name: "wrong host", reference: "protected-file://attacker/connectors/credential_01"},
		{name: "userinfo", reference: "protected-file://user:secret@paperboat/connectors/credential_01"},
		{name: "opaque url", reference: "protected-file:paperboat/connectors/credential_01"},
		{name: "missing segment", reference: "protected-file://paperboat/connectors/"},
		{name: "nested segment", reference: "protected-file://paperboat/connectors/credential_01/extra"},
		{name: "parent traversal", reference: "protected-file://paperboat/connectors/../credential_01"},
		{name: "encoded parent traversal", reference: "protected-file://paperboat/connectors/%2e%2e/credential_01"},
		{name: "encoded slash", reference: "protected-file://paperboat/connectors/credential%2fextra"},
		{name: "encoded backslash", reference: "protected-file://paperboat/connectors/credential%5cextra"},
		{name: "query", reference: "protected-file://paperboat/connectors/credential_01?token=secret"},
		{name: "fragment", reference: "protected-file://paperboat/connectors/credential_01#fragment"},
		{name: "double slash", reference: "protected-file://paperboat//connectors/credential_01"},
		{name: "trailing slash", reference: "protected-file://paperboat/connectors/credential_01/"},
		{name: "dot segment", reference: "protected-file://paperboat/connectors/."},
		{name: "backslash", reference: "protected-file://paperboat/connectors/credential_01\\extra"},
		{name: "space", reference: "protected-file://paperboat/connectors/credential 01"},
		{name: "control", reference: "protected-file://paperboat/connectors/credential\x01"},
		{name: "empty host", reference: "protected-file:///connectors/credential_01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := CredentialReference{Reference: test.reference, Generation: 4}
			if err := value.validate("con_server_assigned"); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("reference %q error = %v, want ErrInvalidState", test.reference, err)
			}
		})
	}
	if err := (CredentialReference{Reference: "protected-file://paperboat/connectors/credential_01"}).validate("con_server_assigned"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("zero-generation reference error = %v, want ErrInvalidState", err)
	}
}
