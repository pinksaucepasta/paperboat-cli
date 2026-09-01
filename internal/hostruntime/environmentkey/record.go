package environmentkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

const linuxCredentialMetadataSchema = "paperboat.environment-host-credential/v1"

type credentialMetadata struct {
	Schema     string `json:"schema"`
	MachineID  string `json:"machine_id"`
	Generation uint64 `json:"generation"`
	PrivateKey string `json:"private_key"`
}

func parseCredentialRecord(body []byte) (credentialMetadata, []byte, error) {
	var metadata credentialMetadata
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF || metadata.Schema != linuxCredentialMetadataSchema ||
		!validIdentity(metadata.MachineID) || metadata.Generation == 0 {
		return credentialMetadata{}, nil, ErrInvalid
	}
	private, err := base64.RawURLEncoding.Strict().DecodeString(metadata.PrivateKey)
	if err != nil || len(private) != privateKeySize || metadata.PrivateKey != base64.RawURLEncoding.EncodeToString(private) {
		clear(private)
		return credentialMetadata{}, nil, ErrInvalid
	}
	return metadata, private, nil
}
