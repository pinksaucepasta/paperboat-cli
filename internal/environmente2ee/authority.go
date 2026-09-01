package environmente2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type RootKeys map[string]ed25519.PublicKey

type KeyBindingClaims struct {
	AccountID           string
	SubjectKind         SubjectKind
	SubjectID           string
	SubjectGeneration   uint64
	KeyGeneration       uint64
	EndpointCertificate []byte
	SigningPublic       ed25519.PublicKey
	SigningKeyID        string
	RecipientPublic     []byte
	RecipientKeyID      string
	NotBefore           uint64
	NotAfter            *uint64
	Serial              uint64
}

type KeyBinding struct {
	KeyBindingClaims
	RootKeyID string
	ID        DocumentID
	Raw       []byte
}

func SignKeyBinding(claims KeyBindingClaims, rootKeyID string, rootPrivate ed25519.PrivateKey) ([]byte, error) {
	if len(rootPrivate) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if err := validateBindingClaims(claims, rootPrivate.Public().(ed25519.PublicKey), rootKeyID); err != nil {
		return nil, err
	}
	body, err := encode(bindingArray(claims))
	if err != nil {
		return nil, err
	}
	return signDocument(contentKeyBinding, rootKeyID, body, rootPrivate)
}

func ParseKeyBinding(raw []byte, roots RootKeys) (KeyBinding, error) {
	document, err := parseDocument(raw, MaximumBindingBytes, contentKeyBinding)
	if err != nil {
		return KeyBinding{}, err
	}
	root, exists := roots[document.KeyID]
	if !exists || !rootKeyMatches(document.KeyID, root) || verifyDocument(document, root) != nil {
		return KeyBinding{}, ErrInvalid
	}
	claims, err := parseBindingBody(document.Body)
	if err != nil || validateBindingClaims(claims, root, document.KeyID) != nil || verifyEndpointCertificate(claims, roots) != nil {
		return KeyBinding{}, ErrInvalid
	}
	return KeyBinding{KeyBindingClaims: claims, RootKeyID: document.KeyID, ID: DocumentID(documentDigest(raw)), Raw: cloneBytes(raw)}, nil
}

func bindingArray(claims KeyBindingClaims) []any {
	var endpoint, signingPublic, signingID, notAfter any
	if claims.EndpointCertificate != nil {
		endpoint = claims.EndpointCertificate
	}
	if claims.SigningPublic != nil {
		signingPublic = []byte(claims.SigningPublic)
	}
	if claims.SigningKeyID != "" {
		signingID = claims.SigningKeyID
	}
	if claims.NotAfter != nil {
		notAfter = *claims.NotAfter
	}
	return []any{"paperboat.environment.key-binding", uint64(1), claims.AccountID, uint64(claims.SubjectKind), claims.SubjectID,
		claims.SubjectGeneration, claims.KeyGeneration, endpoint, signingPublic, signingID, claims.RecipientPublic,
		claims.RecipientKeyID, claims.NotBefore, notAfter, claims.Serial}
}

func parseBindingBody(raw []byte) (KeyBindingClaims, error) {
	var value any
	if err := decodeCanonical(raw, MaximumBindingBytes, &value); err != nil {
		return KeyBindingClaims{}, err
	}
	items, err := array(value, 15)
	if err != nil || requireDomain(items, "paperboat.environment.key-binding", 1) != nil {
		return KeyBindingClaims{}, ErrInvalid
	}
	account, e1 := text(items[2])
	kind, e2 := uintValue(items[3], false)
	subject, e3 := text(items[4])
	subjectGen, e4 := uintValue(items[5], false)
	keyGen, e5 := uintValue(items[6], false)
	endpoint, e6 := nullableBytes(items[7])
	signing, e7 := nullableBytes(items[8])
	signingID, e8 := nullableText(items[9])
	recipient, e9 := bytesValue(items[10], 32)
	recipientID, e10 := text(items[11])
	notBefore, e11 := uintValue(items[12], false)
	var notAfter *uint64
	if items[13] != nil {
		v, e := uintValue(items[13], false)
		if e != nil {
			return KeyBindingClaims{}, ErrInvalid
		}
		notAfter = &v
	}
	serial, e12 := uintValue(items[14], false)
	if anyError(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12) {
		return KeyBindingClaims{}, ErrInvalid
	}
	claims := KeyBindingClaims{AccountID: account, SubjectKind: SubjectKind(kind), SubjectID: subject, SubjectGeneration: subjectGen, KeyGeneration: keyGen,
		EndpointCertificate: endpoint, RecipientPublic: recipient, RecipientKeyID: recipientID, NotBefore: notBefore, NotAfter: notAfter, Serial: serial}
	if signing != nil {
		claims.SigningPublic = ed25519.PublicKey(signing)
	}
	if signingID != nil {
		claims.SigningKeyID = *signingID
	}
	return claims, nil
}

func validateBindingClaims(claims KeyBindingClaims, root ed25519.PublicKey, rootKeyID string) error {
	if !validIdentifier(claims.AccountID) || !validIdentifier(claims.SubjectID) || claims.SubjectGeneration == 0 || claims.SubjectGeneration > MaximumContractInteger ||
		claims.KeyGeneration == 0 || claims.KeyGeneration > MaximumContractInteger || claims.Serial == 0 || claims.Serial > MaximumContractInteger || claims.NotBefore == 0 || claims.NotBefore > MaximumContractInteger || claims.NotAfter != nil {
		return ErrInvalid
	}
	recipientID, err := KeyIDX25519(claims.RecipientPublic)
	if err != nil || recipientID != claims.RecipientKeyID {
		return ErrInvalid
	}
	switch claims.SubjectKind {
	case SubjectManagerCLI, SubjectManagerBrowser:
		signingID, err := KeyIDEd25519(claims.SigningPublic)
		if err != nil || signingID != claims.SigningKeyID {
			return ErrInvalid
		}
	case SubjectHost, SubjectRecovery:
		if len(claims.SigningPublic) != 0 || claims.SigningKeyID != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if claims.SubjectKind == SubjectManagerCLI || claims.SubjectKind == SubjectHost {
		if len(claims.EndpointCertificate) == 0 || len(root) != ed25519.PublicKeySize {
			return ErrInvalid
		}
		role := endpointidentity.RoleCLI
		if claims.SubjectKind == SubjectHost {
			role = endpointidentity.RoleMachine
		}
		certificate, err := endpointidentity.Parse(claims.EndpointCertificate)
		notBefore := time.Unix(int64(claims.NotBefore), 0).UTC()
		if err != nil || certificate.Claims.AccountID != claims.AccountID || certificate.Claims.Role != role ||
			certificate.Claims.EndpointID != claims.SubjectID || certificate.Claims.Generation != claims.SubjectGeneration ||
			notBefore.Before(certificate.Claims.IssuedAt) || !notBefore.Before(certificate.Claims.ExpiresAt) {
			return ErrInvalid
		}
	} else if len(claims.EndpointCertificate) != 0 {
		return ErrInvalid
	}
	if claims.SubjectKind == SubjectRecovery && claims.SubjectID != "environment_recovery" {
		return ErrInvalid
	}
	if !validKeyID(rootKeyID) || len(root) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	digest := sha256.Sum256(root)
	if rootKeyID != "aek_"+hex.EncodeToString(digest[:]) {
		return ErrInvalid
	}
	return nil
}

// verifyEndpointCertificate deliberately considers every authorized account
// root. Accounts may have multiple active E2EE roots, so the root authorizing
// an ENV binding does not have to be the root that issued the endpoint
// certificate embedded in that binding.
func verifyEndpointCertificate(claims KeyBindingClaims, roots RootKeys) error {
	if claims.SubjectKind != SubjectManagerCLI && claims.SubjectKind != SubjectHost {
		return nil
	}
	role := endpointidentity.RoleCLI
	if claims.SubjectKind == SubjectHost {
		role = endpointidentity.RoleMachine
	}
	expected := endpointidentity.Expected{
		AccountID: claims.AccountID, Role: role, EndpointID: claims.SubjectID, Generation: claims.SubjectGeneration,
	}
	now := time.Unix(int64(claims.NotBefore), 0).UTC()
	for _, root := range roots {
		if verified, err := endpointidentity.Verify(claims.EndpointCertificate, root, expected, now); err == nil && !verified.Claims.IssuedAt.After(now) {
			return nil
		}
	}
	return ErrInvalid
}

type ResetScope struct {
	Scope     ScopeKind
	MachineID string
}

type AuthorityClaims struct {
	AccountID    string
	Generation   uint64
	PreviousID   *DocumentID
	OperationID  [16]byte
	BindingBytes [][]byte
	ResetScopes  []ResetScope
}

type Authority struct {
	AuthorityClaims
	RootKeyID string
	ID        DocumentID
	Raw       []byte
	Bindings  []KeyBinding
}

func SignAuthority(claims AuthorityClaims, rootKeyID string, rootPrivate ed25519.PrivateKey) ([]byte, error) {
	if len(rootPrivate) != ed25519.PrivateKeySize || !rootKeyMatches(rootKeyID, rootPrivate.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	sorted, err := SortKeyBindings(claims.BindingBytes)
	if err != nil {
		return nil, err
	}
	claims.BindingBytes = sorted
	claims.ResetScopes = append([]ResetScope(nil), claims.ResetScopes...)
	sort.Slice(claims.ResetScopes, func(i, j int) bool { return resetLess(claims.ResetScopes[i], claims.ResetScopes[j]) })
	if err := validateAuthorityClaims(claims, nil); err != nil {
		return nil, err
	}
	body, err := encode(authorityArray(claims))
	if err != nil {
		return nil, err
	}
	return signDocument(contentAuthority, rootKeyID, body, rootPrivate)
}

func SortKeyBindings(values [][]byte) ([][]byte, error) {
	type item struct {
		binding KeyBinding
		raw     []byte
	}
	items := make([]item, len(values))
	for i, raw := range values {
		doc, err := parseDocument(raw, MaximumBindingBytes, contentKeyBinding)
		if err != nil {
			return nil, ErrInvalid
		}
		claims, err := parseBindingBody(doc.Body)
		if err != nil {
			return nil, ErrInvalid
		}
		items[i] = item{binding: KeyBinding{KeyBindingClaims: claims, RootKeyID: doc.KeyID, ID: DocumentID(documentDigest(raw)), Raw: cloneBytes(raw)}, raw: cloneBytes(raw)}
	}
	sort.Slice(items, func(i, j int) bool { return bindingLess(items[i].binding, items[j].binding) })
	out := make([][]byte, len(items))
	for i := range items {
		out[i] = items[i].raw
		if i > 0 && !bindingLess(items[i-1].binding, items[i].binding) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}

func ParseAuthority(raw []byte, roots RootKeys) (Authority, error) {
	doc, err := parseDocument(raw, MaximumAuthorityBytes, contentAuthority)
	if err != nil {
		return Authority{}, err
	}
	root, ok := roots[doc.KeyID]
	if !ok || !rootKeyMatches(doc.KeyID, root) || verifyDocument(doc, root) != nil {
		return Authority{}, ErrInvalid
	}
	claims, err := parseAuthorityBody(doc.Body)
	if err != nil {
		return Authority{}, err
	}
	bindings := make([]KeyBinding, len(claims.BindingBytes))
	for i, encoded := range claims.BindingBytes {
		binding, e := ParseKeyBinding(encoded, roots)
		if e != nil {
			return Authority{}, ErrInvalid
		}
		bindings[i] = binding
	}
	if validateAuthorityClaims(claims, bindings) != nil {
		return Authority{}, ErrInvalid
	}
	return Authority{AuthorityClaims: claims, RootKeyID: doc.KeyID, ID: DocumentID(documentDigest(raw)), Raw: cloneBytes(raw), Bindings: bindings}, nil
}

func ValidateAuthorityTransition(previous *Authority, next Authority) error {
	if previous == nil {
		if next.Generation != 1 || next.PreviousID != nil {
			return ErrInvalid
		}
		return nil
	}
	if next.AccountID != previous.AccountID || next.Generation != previous.Generation+1 || next.PreviousID == nil || *next.PreviousID != previous.ID {
		return ErrInvalid
	}
	return nil
}

func authorityArray(c AuthorityClaims) []any {
	var previous any
	if c.PreviousID != nil {
		previous = c.PreviousID[:]
	}
	bindings := make([]any, len(c.BindingBytes))
	for i := range c.BindingBytes {
		bindings[i] = c.BindingBytes[i]
	}
	resets := make([]any, len(c.ResetScopes))
	for i, s := range c.ResetScopes {
		var machine any
		if s.Scope == ScopeMachine {
			machine = s.MachineID
		}
		resets[i] = []any{uint64(s.Scope), machine}
	}
	return []any{"paperboat.environment.authority", uint64(1), c.AccountID, c.Generation, previous, c.OperationID[:], bindings, resets}
}

func parseAuthorityBody(raw []byte) (AuthorityClaims, error) {
	var value any
	if decodeCanonical(raw, MaximumAuthorityBytes, &value) != nil {
		return AuthorityClaims{}, ErrInvalid
	}
	items, err := array(value, 8)
	if err != nil || requireDomain(items, "paperboat.environment.authority", 1) != nil {
		return AuthorityClaims{}, ErrInvalid
	}
	account, e1 := text(items[2])
	gen, e2 := uintValue(items[3], false)
	prevBytes, e3 := nullableBytes(items[4])
	op, e4 := bytesValue(items[5], 16)
	bindingValues, e5 := arrayAny(items[6])
	resetValues, e6 := arrayAny(items[7])
	if anyError(e1, e2, e3, e4, e5, e6) {
		return AuthorityClaims{}, ErrInvalid
	}
	c := AuthorityClaims{AccountID: account, Generation: gen}
	copy(c.OperationID[:], op)
	if prevBytes != nil {
		if len(prevBytes) != 32 {
			return AuthorityClaims{}, ErrInvalid
		}
		id := DocumentID{}
		copy(id[:], prevBytes)
		c.PreviousID = &id
	}
	c.BindingBytes = make([][]byte, len(bindingValues))
	for i, v := range bindingValues {
		b, e := bytesValue(v, -1)
		if e != nil {
			return AuthorityClaims{}, ErrInvalid
		}
		c.BindingBytes[i] = b
	}
	c.ResetScopes = make([]ResetScope, len(resetValues))
	for i, v := range resetValues {
		pair, e := array(v, 2)
		if e != nil {
			return AuthorityClaims{}, ErrInvalid
		}
		scope, e := uintValue(pair[0], true)
		if e != nil || scope > 1 {
			return AuthorityClaims{}, ErrInvalid
		}
		r := ResetScope{Scope: ScopeKind(scope)}
		if r.Scope == ScopeGlobal {
			if pair[1] != nil {
				return AuthorityClaims{}, ErrInvalid
			}
		} else {
			r.MachineID, e = text(pair[1])
			if e != nil {
				return AuthorityClaims{}, ErrInvalid
			}
		}
		c.ResetScopes[i] = r
	}
	return c, nil
}

func validateAuthorityClaims(c AuthorityClaims, bindings []KeyBinding) error {
	if !validIdentifier(c.AccountID) || c.Generation == 0 || c.Generation > MaximumContractInteger || allZero(c.OperationID[:]) || c.Generation == 1 != (c.PreviousID == nil) {
		return ErrInvalid
	}
	if len(c.BindingBytes) < 2 || len(c.BindingBytes) > MaximumManagers+MaximumHosts+1 {
		return ErrInvalid
	}
	if bindings == nil {
		bindings = make([]KeyBinding, len(c.BindingBytes))
		for i, raw := range c.BindingBytes {
			doc, err := parseDocument(raw, MaximumBindingBytes, contentKeyBinding)
			if err != nil {
				return ErrInvalid
			}
			claims, err := parseBindingBody(doc.Body)
			if err != nil {
				return ErrInvalid
			}
			bindings[i] = KeyBinding{KeyBindingClaims: claims, RootKeyID: doc.KeyID, ID: DocumentID(documentDigest(raw)), Raw: cloneBytes(raw)}
		}
	}
	for _, b := range c.BindingBytes {
		if len(b) == 0 || len(b) > MaximumBindingBytes {
			return ErrInvalid
		}
	}
	if bindings != nil {
		managers, hosts, recovery := 0, 0, 0
		subjects := map[string]bool{}
		keys := map[string]bool{}
		for i, b := range bindings {
			if b.AccountID != c.AccountID {
				return ErrInvalid
			}
			if i > 0 && !bindingLess(bindings[i-1], b) {
				return ErrInvalid
			}
			subject := string(rune(b.SubjectKind)) + "\x00" + b.SubjectID
			if subjects[subject] || keys[b.RecipientKeyID] || b.SigningKeyID != "" && keys[b.SigningKeyID] {
				return ErrInvalid
			}
			subjects[subject] = true
			keys[b.RecipientKeyID] = true
			if b.SigningKeyID != "" {
				keys[b.SigningKeyID] = true
			}
			switch b.SubjectKind {
			case SubjectManagerCLI, SubjectManagerBrowser:
				managers++
			case SubjectHost:
				hosts++
			case SubjectRecovery:
				recovery++
			}
		}
		if managers < 1 || managers > MaximumManagers || hosts > MaximumHosts || recovery != 1 {
			return ErrInvalid
		}
	}
	for i, r := range c.ResetScopes {
		if r.Scope == ScopeGlobal {
			if r.MachineID != "" {
				return ErrInvalid
			}
		} else if r.Scope == ScopeMachine {
			if !validIdentifier(r.MachineID) {
				return ErrInvalid
			}
		} else {
			return ErrInvalid
		}
		if i > 0 && !resetLess(c.ResetScopes[i-1], r) {
			return ErrInvalid
		}
	}
	return nil
}

func bindingLess(a, b KeyBinding) bool {
	if a.SubjectKind != b.SubjectKind {
		return a.SubjectKind < b.SubjectKind
	}
	if a.SubjectID != b.SubjectID {
		return a.SubjectID < b.SubjectID
	}
	if a.KeyGeneration != b.KeyGeneration {
		return a.KeyGeneration < b.KeyGeneration
	}
	return bytes.Compare(a.ID[:], b.ID[:]) < 0
}

func resetLess(a, b ResetScope) bool {
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	return a.MachineID < b.MachineID
}

func arrayAny(value any) ([]any, error) {
	v, ok := value.([]any)
	if !ok {
		return nil, ErrInvalid
	}
	return v, nil
}
func anyError(errors ...error) bool {
	for _, err := range errors {
		if err != nil {
			return true
		}
	}
	return false
}
func rootKeyMatches(id string, public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize {
		return false
	}
	sum := sha256.Sum256(public)
	return id == "aek_"+hex.EncodeToString(sum[:])
}
