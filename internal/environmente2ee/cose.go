package environmente2ee

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

const (
	coseSign1Tag = uint64(18)
	coseAlgEdDSA = int64(-8)
)

type signedDocument struct {
	Raw         []byte
	Body        []byte
	Protected   []byte
	KeyID       string
	ContentType string
	Signature   []byte
}

func signDocument(contentType, keyID string, body []byte, private ed25519.PrivateKey) ([]byte, error) {
	if !validKeyID(keyID) || len(private) != ed25519.PrivateKeySize || len(body) == 0 {
		return nil, ErrInvalid
	}
	protected, err := encode(map[int64]any{1: coseAlgEdDSA, 3: contentType, 4: []byte(keyID)})
	if err != nil {
		return nil, err
	}
	toSign, err := encode([]any{"Signature1", protected, []byte{}, body})
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(private, toSign)
	return encode(cbor.Tag{Number: coseSign1Tag, Content: []any{protected, map[any]any{}, body, signature}})
}

func parseDocument(raw []byte, max int, expectedContentType string) (signedDocument, error) {
	var tagged interface{}
	if err := decodeCanonical(raw, max, &tagged); err != nil {
		return signedDocument{}, err
	}
	tag, ok := tagged.(cbor.Tag)
	if !ok || tag.Number != coseSign1Tag {
		return signedDocument{}, ErrInvalid
	}
	items, err := array(tag.Content, 4)
	if err != nil {
		return signedDocument{}, err
	}
	protected, err := bytesValue(items[0], -1)
	if err != nil {
		return signedDocument{}, err
	}
	if unprotected, ok := items[1].(map[any]any); !ok || len(unprotected) != 0 {
		if typed, ok := items[1].(map[interface{}]interface{}); !ok || len(typed) != 0 {
			return signedDocument{}, ErrInvalid
		}
	}
	body, err := bytesValue(items[2], -1)
	if err != nil {
		return signedDocument{}, err
	}
	signature, err := bytesValue(items[3], ed25519.SignatureSize)
	if err != nil {
		return signedDocument{}, err
	}
	var headers map[int64]any
	if err := decodeCanonical(protected, 1024, &headers); err != nil || len(headers) != 3 {
		return signedDocument{}, ErrInvalid
	}
	alg, ok := headers[1].(int64)
	if !ok || alg != coseAlgEdDSA {
		return signedDocument{}, ErrInvalid
	}
	contentType, err := text(headers[3])
	if err != nil || contentType != expectedContentType {
		return signedDocument{}, ErrInvalid
	}
	kidBytes, err := bytesValue(headers[4], -1)
	if err != nil || len(kidBytes) == 0 {
		return signedDocument{}, ErrInvalid
	}
	kid := string(kidBytes)
	if !validKeyID(kid) {
		return signedDocument{}, ErrInvalid
	}
	return signedDocument{Raw: cloneBytes(raw), Body: body, Protected: protected, KeyID: kid, ContentType: contentType, Signature: signature}, nil
}

func verifyDocument(document signedDocument, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	toSign, err := encode([]any{"Signature1", document.Protected, []byte{}, document.Body})
	if err != nil || !ed25519.Verify(public, toSign, document.Signature) {
		return ErrInvalid
	}
	return nil
}

func documentDigest(raw []byte) [sha256.Size]byte { return sha256.Sum256(raw) }
