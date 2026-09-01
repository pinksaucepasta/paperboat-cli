package environmente2ee

import "crypto/ed25519"

type AuthorityTransitionAbortClaims struct {
	AccountID         string
	ActiveAuthorityID DocumentID
	TransitionID      DocumentID
	OperationID       [16]byte
}

type AuthorityTransitionAbort struct {
	AuthorityTransitionAbortClaims
	RootKeyID string
	ID        DocumentID
	Raw       []byte
}

func SignAuthorityTransitionAbort(claims AuthorityTransitionAbortClaims, rootKeyID string, rootPrivate ed25519.PrivateKey) ([]byte, error) {
	if len(rootPrivate) != ed25519.PrivateKeySize || !rootKeyMatches(rootKeyID, rootPrivate.Public().(ed25519.PublicKey)) || validateAbortClaims(claims) != nil {
		return nil, ErrInvalid
	}
	body, err := encode(abortArray(claims))
	if err != nil {
		return nil, err
	}
	return signDocument(contentAbort, rootKeyID, body, rootPrivate)
}

func ParseAuthorityTransitionAbort(raw []byte, roots RootKeys) (AuthorityTransitionAbort, error) {
	document, err := parseDocument(raw, MaximumAbortBytes, contentAbort)
	if err != nil {
		return AuthorityTransitionAbort{}, err
	}
	root, exists := roots[document.KeyID]
	if !exists || !rootKeyMatches(document.KeyID, root) || verifyDocument(document, root) != nil {
		return AuthorityTransitionAbort{}, ErrInvalid
	}
	claims, err := parseAbortBody(document.Body)
	if err != nil || validateAbortClaims(claims) != nil {
		return AuthorityTransitionAbort{}, ErrInvalid
	}
	return AuthorityTransitionAbort{
		AuthorityTransitionAbortClaims: claims,
		RootKeyID:                      document.KeyID,
		ID:                             DocumentID(documentDigest(raw)),
		Raw:                            cloneBytes(raw),
	}, nil
}

func abortArray(claims AuthorityTransitionAbortClaims) []any {
	return []any{
		"paperboat.environment.authority-transition-abort", uint64(1),
		claims.AccountID, claims.ActiveAuthorityID[:], claims.TransitionID[:],
		claims.OperationID[:],
	}
}

func parseAbortBody(raw []byte) (AuthorityTransitionAbortClaims, error) {
	var value any
	if decodeCanonical(raw, MaximumAbortBytes, &value) != nil {
		return AuthorityTransitionAbortClaims{}, ErrInvalid
	}
	items, err := array(value, 6)
	if err != nil || requireDomain(items, "paperboat.environment.authority-transition-abort", 1) != nil {
		return AuthorityTransitionAbortClaims{}, ErrInvalid
	}
	account, e1 := text(items[2])
	active, e2 := bytesValue(items[3], 32)
	transition, e3 := bytesValue(items[4], 32)
	operation, e4 := bytesValue(items[5], 16)
	if anyError(e1, e2, e3, e4) {
		return AuthorityTransitionAbortClaims{}, ErrInvalid
	}
	claims := AuthorityTransitionAbortClaims{AccountID: account}
	copy(claims.ActiveAuthorityID[:], active)
	copy(claims.TransitionID[:], transition)
	copy(claims.OperationID[:], operation)
	return claims, nil
}

func validateAbortClaims(claims AuthorityTransitionAbortClaims) error {
	if !validIdentifier(claims.AccountID) || allZero(claims.ActiveAuthorityID[:]) || allZero(claims.TransitionID[:]) || allZero(claims.OperationID[:]) {
		return ErrInvalid
	}
	return nil
}
