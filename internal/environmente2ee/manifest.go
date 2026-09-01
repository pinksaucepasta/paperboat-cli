package environmente2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

type Recipient struct {
	Kind          RecipientKind
	SubjectID     string
	KeyGeneration uint64
	KeyID         string
	PublicKey     []byte
}

type RecipientPrivate struct {
	Kind          RecipientKind
	SubjectID     string
	KeyGeneration uint64
	KeyID         string
	PrivateKey    []byte
}

type RecipientWrap struct {
	Kind            RecipientKind
	SubjectID       string
	KeyGeneration   uint64
	KeyID           string
	EncapsulatedKey []byte
	Ciphertext      []byte
}

type ManifestClaims struct {
	AccountID           string
	AuthorityGeneration uint64
	AuthorityID         DocumentID
	Scope               ScopeKind
	MachineID           string
	State               ScopeState
	PreviousVersion     uint64
	Version             uint64
	KeyEpoch            uint64
	OperationID         [16]byte
	Salt                []byte
	Nonce               []byte
	Mutation            MutationKind
	ChangedNames        []string
	Names               []string
	CiphertextSHA256    DocumentID
	Ciphertext          []byte
	Wraps               []RecipientWrap
}

type Manifest struct {
	ManifestClaims
	SignerKeyID string
	ID          DocumentID
	Raw         []byte
}

type BuildManifestInput struct {
	Claims        ManifestClaims
	Values        map[string][]byte
	ScopeKey      []byte
	Recipients    []Recipient
	SignerKeyID   string
	SignerPrivate ed25519.PrivateKey
	Random        io.Reader
}

type DecryptedScope struct {
	Values   map[string][]byte
	ScopeKey []byte
}

type FirstHostDelivery struct {
	Global    DecryptedScope
	Machine   DecryptedScope
	Effective map[string][]byte
}

func GenerateRecipientKey() (private, public []byte, err error) {
	key, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	private, err = key.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return private, key.PublicKey().Bytes(), nil
}

func BuildManifest(input BuildManifestInput) ([]byte, error) {
	random := input.Random
	if random == nil {
		random = rand.Reader
	}
	c := input.Claims
	if len(input.ScopeKey) != 32 || len(input.SignerPrivate) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	signerID, err := KeyIDEd25519(input.SignerPrivate.Public().(ed25519.PublicKey))
	if err != nil || signerID != input.SignerKeyID {
		return nil, ErrInvalid
	}
	names, plaintext, err := encodeScope(input.Values)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	c.Names = names
	c.Salt = make([]byte, 32)
	c.Nonce = make([]byte, 12)
	if _, err = io.ReadFull(random, c.Salt); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(random, c.Nonce); err != nil {
		return nil, err
	}
	padded, err := padPlaintext(random, plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(padded)
	key, err := payloadKey(c, input.ScopeKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad, err := payloadAAD(c)
	if err != nil {
		return nil, err
	}
	c.Ciphertext = aead.Seal(nil, c.Nonce, padded, aad)
	digest := sha256.Sum256(c.Ciphertext)
	c.CiphertextSHA256 = DocumentID(digest)
	recipients := append([]Recipient(nil), input.Recipients...)
	sort.Slice(recipients, func(i, j int) bool { return recipientLess(recipients[i], recipients[j]) })
	c.Wraps = make([]RecipientWrap, len(recipients))
	for i, r := range recipients {
		wrap, e := WrapScopeKey(c, r, input.ScopeKey)
		if e != nil {
			return nil, e
		}
		c.Wraps[i] = wrap
	}
	if err = validateManifestClaims(c, nil); err != nil {
		return nil, err
	}
	body, err := encode(manifestArray(c))
	if err != nil {
		return nil, err
	}
	return signDocument(contentManifest, input.SignerKeyID, body, input.SignerPrivate)
}

func ParseManifest(raw []byte, authority Authority) (Manifest, error) {
	doc, err := parseDocument(raw, MaximumManifestBytes, contentManifest)
	if err != nil {
		return Manifest{}, err
	}
	var signer ed25519.PublicKey
	for _, binding := range authority.Bindings {
		if (binding.SubjectKind == SubjectManagerCLI || binding.SubjectKind == SubjectManagerBrowser) && binding.SigningKeyID == doc.KeyID {
			signer = binding.SigningPublic
			break
		}
	}
	if signer == nil || verifyDocument(doc, signer) != nil {
		return Manifest{}, ErrInvalid
	}
	claims, err := parseManifestBody(doc.Body)
	if err != nil {
		return Manifest{}, err
	}
	if claims.AccountID != authority.AccountID || claims.AuthorityGeneration != authority.Generation || claims.AuthorityID != authority.ID || validateManifestClaims(claims, &authority) != nil {
		return Manifest{}, ErrInvalid
	}
	return Manifest{ManifestClaims: claims, SignerKeyID: doc.KeyID, ID: DocumentID(documentDigest(raw)), Raw: cloneBytes(raw)}, nil
}

func DecryptManifest(manifest Manifest, recipient RecipientPrivate) (DecryptedScope, error) {
	var selected *RecipientWrap
	for i := range manifest.Wraps {
		w := &manifest.Wraps[i]
		if w.Kind == recipient.Kind && w.SubjectID == recipient.SubjectID && w.KeyGeneration == recipient.KeyGeneration && w.KeyID == recipient.KeyID {
			if selected != nil {
				return DecryptedScope{}, ErrInvalid
			}
			selected = w
		}
	}
	if selected == nil {
		return DecryptedScope{}, ErrInvalid
	}
	scopeKey, err := OpenScopeKey(manifest.ManifestClaims, *selected, recipient.PrivateKey)
	if err != nil {
		return DecryptedScope{}, ErrInvalid
	}
	key, err := payloadKey(manifest.ManifestClaims, scopeKey)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	aad, err := payloadAAD(manifest.ManifestClaims)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	padded, err := aead.Open(nil, manifest.Nonce, manifest.Ciphertext, aad)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	plain, err := unpadPlaintext(padded)
	clear(padded)
	if err != nil {
		clear(scopeKey)
		return DecryptedScope{}, ErrInvalid
	}
	values, names, err := decodeScope(plain)
	clear(plain)
	if err != nil || !equalStrings(names, manifest.Names) {
		clear(scopeKey)
		clearValues(values)
		return DecryptedScope{}, ErrInvalid
	}
	return DecryptedScope{Values: values, ScopeKey: scopeKey}, nil
}

func WrapScopeKey(c ManifestClaims, recipient Recipient, scopeKey []byte) (RecipientWrap, error) {
	if len(scopeKey) != 32 || validateRecipient(recipient) != nil {
		return RecipientWrap{}, ErrInvalid
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(recipient.PublicKey)
	if err != nil {
		return RecipientWrap{}, ErrInvalid
	}
	info, err := hpkeInfo(c)
	if err != nil {
		return RecipientWrap{}, err
	}
	aad, err := wrapAAD(c, recipient.Kind, recipient.SubjectID, recipient.KeyGeneration, recipient.KeyID)
	if err != nil {
		return RecipientWrap{}, err
	}
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return RecipientWrap{}, ErrInvalid
	}
	ciphertext, err := sender.Seal(aad, scopeKey)
	if err != nil {
		return RecipientWrap{}, ErrInvalid
	}
	if len(enc) != 32 || len(ciphertext) != 48 {
		return RecipientWrap{}, ErrInvalid
	}
	return RecipientWrap{Kind: recipient.Kind, SubjectID: recipient.SubjectID, KeyGeneration: recipient.KeyGeneration, KeyID: recipient.KeyID, EncapsulatedKey: enc, Ciphertext: ciphertext}, nil
}

func OpenScopeKey(c ManifestClaims, wrap RecipientWrap, privateBytes []byte) ([]byte, error) {
	if len(privateBytes) != 32 || len(wrap.EncapsulatedKey) != 32 || len(wrap.Ciphertext) != 48 {
		return nil, ErrInvalid
	}
	private, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(privateBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	public := private.PublicKey().Bytes()
	kid, err := KeyIDX25519(public)
	if err != nil || kid != wrap.KeyID {
		return nil, ErrInvalid
	}
	info, err := hpkeInfo(c)
	if err != nil {
		return nil, err
	}
	aad, err := wrapAAD(c, wrap.Kind, wrap.SubjectID, wrap.KeyGeneration, wrap.KeyID)
	if err != nil {
		return nil, err
	}
	receiver, err := hpke.NewRecipient(wrap.EncapsulatedKey, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, ErrInvalid
	}
	plain, err := receiver.Open(aad, wrap.Ciphertext)
	if err != nil || len(plain) != 32 {
		clear(plain)
		return nil, ErrInvalid
	}
	return plain, nil
}

func payloadKey(c ManifestClaims, scopeKey []byte) ([]byte, error) {
	info, err := encode([]any{"paperboat.environment.payload-key", uint64(1), c.AccountID, c.AuthorityID[:], uint64(c.Scope), machineValue(c), uint64(c.State), c.PreviousVersion, c.Version, c.KeyEpoch, c.OperationID[:]})
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, scopeKey, c.Salt, string(info), 32)
}
func payloadAAD(c ManifestClaims) ([]byte, error) {
	return encode([]any{"paperboat.environment.payload-aad", uint64(1), uint64(1), c.AccountID, c.AuthorityGeneration, c.AuthorityID[:], uint64(c.Scope), machineValue(c), uint64(c.State), c.PreviousVersion, c.Version, c.KeyEpoch, c.OperationID[:], c.Salt, c.Nonce, uint64(c.Mutation), stringsAny(c.ChangedNames), stringsAny(c.Names)})
}
func hpkeInfo(c ManifestClaims) ([]byte, error) {
	return encode([]any{"paperboat.environment.hpke-info", uint64(1), uint64(1), c.AccountID, c.AuthorityID[:], uint64(c.Scope), machineValue(c), uint64(c.State), c.KeyEpoch, c.Version, c.OperationID[:]})
}
func wrapAAD(c ManifestClaims, kind RecipientKind, subject string, generation uint64, kid string) ([]byte, error) {
	return encode([]any{"paperboat.environment.wrap-aad", uint64(1), uint64(1), c.AccountID, c.AuthorityGeneration, c.AuthorityID[:], uint64(c.Scope), machineValue(c), uint64(c.State), c.PreviousVersion, c.Version, c.KeyEpoch, c.OperationID[:], c.Salt, c.CiphertextSHA256[:], uint64(kind), subject, generation, kid})
}

func manifestArray(c ManifestClaims) []any {
	wraps := make([]any, len(c.Wraps))
	for i, w := range c.Wraps {
		wraps[i] = []any{uint64(w.Kind), w.SubjectID, w.KeyGeneration, w.KeyID, w.EncapsulatedKey, w.Ciphertext}
	}
	return []any{"paperboat.environment.scope-manifest", uint64(1), uint64(1), c.AccountID, c.AuthorityGeneration, c.AuthorityID[:], uint64(c.Scope), machineValue(c), uint64(c.State), c.PreviousVersion, c.Version, c.KeyEpoch, c.OperationID[:], c.Salt, c.Nonce, uint64(c.Mutation), stringsAny(c.ChangedNames), stringsAny(c.Names), c.CiphertextSHA256[:], c.Ciphertext, wraps}
}

func parseManifestBody(raw []byte) (ManifestClaims, error) {
	var v any
	if decodeCanonical(raw, MaximumManifestBytes, &v) != nil {
		return ManifestClaims{}, ErrInvalid
	}
	a, e := array(v, 21)
	if e != nil || requireDomain(a, "paperboat.environment.scope-manifest", 1) != nil {
		return ManifestClaims{}, ErrInvalid
	}
	profile, e0 := uintValue(a[2], false)
	account, e1 := text(a[3])
	agen, e2 := uintValue(a[4], false)
	aid, e3 := bytesValue(a[5], 32)
	scope, e4 := uintValue(a[6], true)
	machine, e5 := nullableText(a[7])
	state, e6 := uintValue(a[8], true)
	prev, e7 := uintValue(a[9], true)
	version, e8 := uintValue(a[10], false)
	epoch, e9 := uintValue(a[11], false)
	op, e10 := bytesValue(a[12], 16)
	salt, e11 := bytesValue(a[13], 32)
	nonce, e12 := bytesValue(a[14], 12)
	mutation, e13 := uintValue(a[15], true)
	changed, e14 := parseStringArray(a[16])
	names, e15 := parseStringArray(a[17])
	hash, e16 := bytesValue(a[18], 32)
	ciphertext, e17 := bytesValue(a[19], -1)
	wrapValues, e18 := arrayAny(a[20])
	if anyError(e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18) || profile != 1 {
		return ManifestClaims{}, ErrInvalid
	}
	c := ManifestClaims{AccountID: account, AuthorityGeneration: agen, Scope: ScopeKind(scope), State: ScopeState(state), PreviousVersion: prev, Version: version, KeyEpoch: epoch, Salt: salt, Nonce: nonce, Mutation: MutationKind(mutation), ChangedNames: changed, Names: names, Ciphertext: ciphertext}
	copy(c.AuthorityID[:], aid)
	copy(c.OperationID[:], op)
	copy(c.CiphertextSHA256[:], hash)
	if machine != nil {
		c.MachineID = *machine
	}
	c.Wraps = make([]RecipientWrap, len(wrapValues))
	for i, x := range wrapValues {
		p, e := array(x, 6)
		if e != nil {
			return ManifestClaims{}, ErrInvalid
		}
		kind, e1 := uintValue(p[0], false)
		subject, e2 := text(p[1])
		gen, e3 := uintValue(p[2], false)
		kid, e4 := text(p[3])
		enc, e5 := bytesValue(p[4], 32)
		ct, e6 := bytesValue(p[5], 48)
		if anyError(e1, e2, e3, e4, e5, e6) {
			return ManifestClaims{}, ErrInvalid
		}
		c.Wraps[i] = RecipientWrap{Kind: RecipientKind(kind), SubjectID: subject, KeyGeneration: gen, KeyID: kid, EncapsulatedKey: enc, Ciphertext: ct}
	}
	return c, nil
}

func validateManifestClaims(c ManifestClaims, authority *Authority) error {
	if !validIdentifier(c.AccountID) || c.AuthorityGeneration == 0 || c.Version == 0 || c.Version > MaximumContractInteger || c.PreviousVersion > MaximumContractInteger || c.KeyEpoch == 0 || c.KeyEpoch > MaximumContractInteger || allZero(c.OperationID[:]) || len(c.Salt) != 32 || len(c.Nonce) != 12 || c.Scope > ScopeMachine || c.State > ScopeRetired || c.Mutation > MutationReset {
		return ErrInvalid
	}
	if c.Scope == ScopeGlobal {
		if c.MachineID != "" || c.State != ScopeActive {
			return ErrInvalid
		}
	} else if !validIdentifier(c.MachineID) {
		return ErrInvalid
	}
	if validateNames(c.Names) != nil || validateNames(c.ChangedNames) != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(c.Ciphertext)
	if DocumentID(digest) != c.CiphertextSHA256 || !validCiphertextLength(len(c.Ciphertext)) {
		return ErrInvalid
	}
	if len(c.Wraps) == 0 || len(c.Wraps) > MaximumManagers+MaximumHosts+1 {
		return ErrInvalid
	}
	for i, w := range c.Wraps {
		if validateWrap(w) != nil {
			return ErrInvalid
		}
		if i > 0 && !wrapLess(c.Wraps[i-1], w) {
			return ErrInvalid
		}
	}
	if authority != nil {
		if c.Scope == ScopeMachine {
			hasTargetHost := false
			for _, binding := range authority.Bindings {
				if binding.SubjectKind == SubjectHost && binding.SubjectID == c.MachineID {
					hasTargetHost = true
					break
				}
			}
			if hasTargetHost != (c.State == ScopeActive) {
				return ErrInvalid
			}
		}
		expected, err := authority.ExpectedRecipients(c.Scope, c.State, c.MachineID)
		if err != nil || !equalWrapRecipients(c.Wraps, expected) {
			return ErrInvalid
		}
	}
	return nil
}

func (a Authority) ExpectedRecipients(scope ScopeKind, state ScopeState, machineID string) ([]Recipient, error) {
	result := []Recipient{}
	for _, b := range a.Bindings {
		r := Recipient{SubjectID: b.SubjectID, KeyGeneration: b.KeyGeneration, KeyID: b.RecipientKeyID, PublicKey: cloneBytes(b.RecipientPublic)}
		switch b.SubjectKind {
		case SubjectManagerCLI, SubjectManagerBrowser:
			r.Kind = RecipientManager
		case SubjectRecovery:
			r.Kind = RecipientRecovery
		case SubjectHost:
			if scope == ScopeGlobal {
				r.Kind = RecipientHost
			} else if state == ScopeActive && b.SubjectID == machineID {
				r.Kind = RecipientHost
			} else {
				continue
			}
		default:
			return nil, ErrInvalid
		}
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool { return recipientLess(result[i], result[j]) })
	if scope == ScopeMachine && state == ScopeActive {
		hosts := 0
		for _, r := range result {
			if r.Kind == RecipientHost {
				hosts++
			}
		}
		if hosts != 1 {
			return nil, ErrInvalid
		}
	}
	return result, nil
}

func ValidateManifestSuccessor(old *Manifest, next Manifest, authorityTransition bool) error {
	c := next.ManifestClaims
	if old == nil {
		return boolError(c.Mutation == MutationInitialize && c.PreviousVersion == 0 && c.Version == 1 && c.KeyEpoch == 1 && len(c.Names) == 0 && len(c.ChangedNames) == 0)
	}
	o := old.ManifestClaims
	if c.AccountID != o.AccountID || c.Scope != o.Scope || c.MachineID != o.MachineID || c.PreviousVersion != o.Version || c.Version != o.Version+1 {
		return ErrInvalid
	}
	if authorityTransition {
		if c.AuthorityGeneration != o.AuthorityGeneration+1 || c.AuthorityID == o.AuthorityID {
			return ErrInvalid
		}
	} else if c.AuthorityGeneration != o.AuthorityGeneration || c.AuthorityID != o.AuthorityID {
		return ErrInvalid
	}
	sameNames := equalStrings(c.Names, o.Names)
	switch c.Mutation {
	case MutationSet:
		if authorityTransition || c.KeyEpoch != o.KeyEpoch || c.State != o.State || len(c.ChangedNames) != 1 || !contains(c.Names, c.ChangedNames[0]) || !(sameNames || addedOne(o.Names, c.Names, c.ChangedNames[0])) {
			return ErrInvalid
		}
	case MutationUnset:
		if authorityTransition || c.KeyEpoch != o.KeyEpoch || c.State != o.State || len(c.ChangedNames) != 1 || contains(c.Names, c.ChangedNames[0]) || !removedOne(o.Names, c.Names, c.ChangedNames[0]) {
			return ErrInvalid
		}
	case MutationReauthorize:
		if !authorityTransition || !sameNames || len(c.ChangedNames) != 0 || c.KeyEpoch != o.KeyEpoch || !(c.State == o.State || o.State == ScopeRetired && c.State == ScopeActive) {
			return ErrInvalid
		}
	case MutationRotate:
		if !sameNames || len(c.ChangedNames) != 0 || c.KeyEpoch != o.KeyEpoch+1 || !(c.State == o.State || o.State == ScopeActive && c.State == ScopeRetired) {
			return ErrInvalid
		}
	case MutationReset:
		if !authorityTransition || len(c.Names) != 0 || !equalStrings(c.ChangedNames, o.Names) || c.KeyEpoch != o.KeyEpoch+1 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// ValidateManifestTransition validates a manifest together with the authority
// state that grants its signer and recipients. It is the validation entry point
// for clients and hosts applying a scope update. ValidateManifestSuccessor is
// retained as the narrower public-claim state-machine check.
func ValidateManifestTransition(old *Manifest, next Manifest, previousAuthority *Authority, proposed Authority) error {
	parsedNext, err := ParseManifest(next.Raw, proposed)
	if err != nil || parsedNext.ID != next.ID {
		return ErrInvalid
	}
	next = parsedNext

	authorityTransition := false
	if previousAuthority == nil {
		if ValidateAuthorityTransition(nil, proposed) != nil {
			return ErrInvalid
		}
	} else if previousAuthority.ID == proposed.ID {
		if previousAuthority.Generation != proposed.Generation {
			return ErrInvalid
		}
	} else {
		if ValidateAuthorityTransition(previousAuthority, proposed) != nil {
			return ErrInvalid
		}
		authorityTransition = true
	}

	resetAuthorized := authorityHasReset(proposed, next.Scope, next.MachineID)
	if old == nil {
		switch next.Mutation {
		case MutationInitialize:
			globalGenesis := previousAuthority == nil && proposed.Generation == 1 && next.Scope == ScopeGlobal
			machineEnrollment := authorityTransition && next.Scope == ScopeMachine
			if resetAuthorized || !globalGenesis && !machineEnrollment {
				return ErrInvalid
			}
			return ValidateManifestSuccessor(nil, next, authorityTransition)
		case MutationReset:
			if !authorityTransition || !resetAuthorized || next.PreviousVersion != 0 || next.Version != 1 || next.KeyEpoch != 1 || len(next.Names) != 0 || len(next.ChangedNames) != 0 {
				return ErrInvalid
			}
			return nil
		default:
			return ErrInvalid
		}
	}

	if previousAuthority == nil {
		return ErrInvalid
	}
	parsedOld, err := ParseManifest(old.Raw, *previousAuthority)
	if err != nil || parsedOld.ID != old.ID {
		return ErrInvalid
	}
	old = &parsedOld
	if old.AuthorityGeneration != previousAuthority.Generation || old.AuthorityID != previousAuthority.ID {
		return ErrInvalid
	}
	if resetAuthorized != (next.Mutation == MutationReset) {
		return ErrInvalid
	}
	if next.Mutation == MutationReset {
		if !authorityTransition {
			return ErrInvalid
		}
	} else if authorityTransition && removedRecipient(old.Wraps, next.Wraps) && next.Mutation != MutationRotate {
		return ErrInvalid
	}
	return ValidateManifestSuccessor(old, next, authorityTransition)
}

// MergeScopes returns a detached effective environment. Exact-name machine
// entries override global entries. ASCII case-fold collisions with different
// spellings are rejected, as are invalid or oversized merged environments.
func MergeScopes(global, machine map[string][]byte) (map[string][]byte, error) {
	if _, _, err := encodeScope(global); err != nil {
		return nil, ErrInvalid
	}
	if _, _, err := encodeScope(machine); err != nil {
		return nil, ErrInvalid
	}
	result := make(map[string][]byte, len(global)+len(machine))
	folded := make(map[string]string, len(global)+len(machine))
	for name, value := range global {
		result[name] = cloneBytes(value)
		folded[strings.ToUpper(name)] = name
	}
	for name, value := range machine {
		fold := strings.ToUpper(name)
		if existing, ok := folded[fold]; ok && existing != name {
			clearValues(result)
			return nil, ErrInvalid
		}
		result[name] = cloneBytes(value)
		folded[fold] = name
	}
	if _, raw, err := encodeScope(result); err != nil {
		clearValues(result)
		return nil, ErrInvalid
	} else {
		clear(raw)
	}
	return result, nil
}

// ValidateFirstHostDelivery validates the atomic global+machine bootstrap pair
// for a host whose exact recipient binding first appears in currentAuthority.
// The host has no prior manifest high-water, so this rule is rooted in the
// sequential account authority transition and both manager signatures.
func ValidateFirstHostDelivery(previousAuthority *Authority, currentAuthority Authority, global, machine Manifest, recipient RecipientPrivate) (FirstHostDelivery, error) {
	if ValidateAuthorityTransition(previousAuthority, currentAuthority) != nil || recipient.Kind != RecipientHost {
		return FirstHostDelivery{}, ErrInvalid
	}
	wasBound, isBound := false, false
	if previousAuthority != nil {
		for _, binding := range previousAuthority.Bindings {
			if binding.SubjectKind == SubjectHost && binding.SubjectID == recipient.SubjectID && binding.KeyGeneration == recipient.KeyGeneration && binding.RecipientKeyID == recipient.KeyID {
				wasBound = true
			}
		}
	}
	for _, binding := range currentAuthority.Bindings {
		if binding.SubjectKind == SubjectHost && binding.SubjectID == recipient.SubjectID && binding.KeyGeneration == recipient.KeyGeneration && binding.RecipientKeyID == recipient.KeyID {
			isBound = true
		}
	}
	if wasBound || !isBound {
		return FirstHostDelivery{}, ErrInvalid
	}
	parsedGlobal, err := ParseManifest(global.Raw, currentAuthority)
	if err != nil || parsedGlobal.ID != global.ID {
		return FirstHostDelivery{}, ErrInvalid
	}
	parsedMachine, err := ParseManifest(machine.Raw, currentAuthority)
	if err != nil || parsedMachine.ID != machine.ID {
		return FirstHostDelivery{}, ErrInvalid
	}
	global = parsedGlobal
	machine = parsedMachine
	// Reset is destructive and is authorized only by the root-signed scope
	// list on this authority transition. The generic manifest state-machine
	// check enforces this for managers, but hosts use the pair-delivery
	// validators below and must apply the same gate before decrypting.
	if global.Mutation == MutationReset && !authorityHasReset(currentAuthority, ScopeGlobal, "") ||
		machine.Mutation == MutationReset && !authorityHasReset(currentAuthority, ScopeMachine, recipient.SubjectID) {
		return FirstHostDelivery{}, ErrInvalid
	}
	validGlobal := global.Scope == ScopeGlobal && global.State == ScopeActive
	if previousAuthority == nil {
		validGlobal = validGlobal && global.Mutation == MutationInitialize && global.PreviousVersion == 0 && global.Version == 1 && global.KeyEpoch == 1 && len(global.Names) == 0 && len(global.ChangedNames) == 0
	} else {
		validGlobal = validGlobal && global.PreviousVersion > 0 && global.Version == global.PreviousVersion+1 && global.KeyEpoch > 0 &&
			(global.Mutation == MutationReauthorize || global.Mutation == MutationRotate || global.Mutation == MutationReset) &&
			(global.Mutation != MutationReauthorize && global.Mutation != MutationRotate || len(global.ChangedNames) == 0) &&
			(global.Mutation != MutationReset || len(global.Names) == 0)
	}
	if !validGlobal {
		return FirstHostDelivery{}, ErrInvalid
	}
	validMachine := machine.Scope == ScopeMachine && machine.MachineID == recipient.SubjectID && machine.State == ScopeActive
	if previousAuthority == nil {
		validMachine = validMachine && machine.Mutation == MutationInitialize && machine.PreviousVersion == 0 && machine.Version == 1 && machine.KeyEpoch == 1 && len(machine.Names) == 0 && len(machine.ChangedNames) == 0
	} else {
		validMachine = validMachine && validFirstPairTransitionShape(machine)
	}
	if !validMachine {
		return FirstHostDelivery{}, ErrInvalid
	}
	openedGlobal, err := DecryptManifest(global, recipient)
	if err != nil {
		return FirstHostDelivery{}, ErrInvalid
	}
	openedMachine, err := DecryptManifest(machine, recipient)
	if err != nil {
		clearValues(openedGlobal.Values)
		clear(openedGlobal.ScopeKey)
		return FirstHostDelivery{}, ErrInvalid
	}
	effective, err := MergeScopes(openedGlobal.Values, openedMachine.Values)
	if err != nil {
		clearValues(openedGlobal.Values)
		clear(openedGlobal.ScopeKey)
		clearValues(openedMachine.Values)
		clear(openedMachine.ScopeKey)
		return FirstHostDelivery{}, ErrInvalid
	}
	return FirstHostDelivery{Global: openedGlobal, Machine: openedMachine, Effective: effective}, nil
}

// ValidateLatestAfterFirstDelivery validates and decrypts the latest pair
// after a retained first-host bootstrap pair has established manifest version
// floors. The caller must already have verified the complete sequential
// authority chain between bootstrapAuthority and currentAuthority.
func ValidateLatestAfterFirstDelivery(bootstrapGlobal, bootstrapMachine, latestGlobal, latestMachine Manifest, bootstrapAuthority, currentAuthority Authority, recipient RecipientPrivate) (FirstHostDelivery, error) {
	if recipient.Kind != RecipientHost || bootstrapAuthority.AccountID != currentAuthority.AccountID || currentAuthority.Generation < bootstrapAuthority.Generation {
		return FirstHostDelivery{}, ErrInvalid
	}
	sameAuthority := currentAuthority.Generation == bootstrapAuthority.Generation
	if sameAuthority && currentAuthority.ID != bootstrapAuthority.ID {
		return FirstHostDelivery{}, ErrInvalid
	}
	bound := false
	for _, binding := range currentAuthority.Bindings {
		if binding.SubjectKind == SubjectHost && binding.SubjectID == recipient.SubjectID && binding.KeyGeneration == recipient.KeyGeneration && binding.RecipientKeyID == recipient.KeyID {
			bound = true
			break
		}
	}
	if !bound {
		return FirstHostDelivery{}, ErrInvalid
	}
	parsedGlobal, err := ParseManifest(latestGlobal.Raw, currentAuthority)
	if err != nil || parsedGlobal.ID != latestGlobal.ID {
		return FirstHostDelivery{}, ErrInvalid
	}
	parsedMachine, err := ParseManifest(latestMachine.Raw, currentAuthority)
	if err != nil || parsedMachine.ID != latestMachine.ID {
		return FirstHostDelivery{}, ErrInvalid
	}
	latestGlobal, latestMachine = parsedGlobal, parsedMachine
	// A reset must be authorized by the root-signed scope list. Genesis cannot
	// carry a reset manifest, but a reset authority can also be the bootstrap
	// authority for a newly appearing host binding, so do not require the
	// latest pair to be newer than bootstrapAuthority here.
	if latestGlobal.Mutation == MutationReset && (currentAuthority.Generation == 1 || !authorityHasReset(currentAuthority, ScopeGlobal, "") || sameAuthority && latestGlobal.ID != bootstrapGlobal.ID) ||
		latestMachine.Mutation == MutationReset && (currentAuthority.Generation == 1 || !authorityHasReset(currentAuthority, ScopeMachine, recipient.SubjectID) || sameAuthority && latestMachine.ID != bootstrapMachine.ID) {
		return FirstHostDelivery{}, ErrInvalid
	}
	// Genesis mutations can only be the exact bootstrap pair. A newer
	// authority already has the bootstrap scope as its predecessor, so an
	// initialize or PreviousVersion=0 reset there would bypass the manifest
	// transition state machine and could erase a host's established values.
	if !sameAuthority && (latestGlobal.Mutation == MutationInitialize || latestGlobal.Mutation == MutationReset && latestGlobal.PreviousVersion == 0 ||
		latestMachine.Mutation == MutationInitialize || latestMachine.Mutation == MutationReset && latestMachine.PreviousVersion == 0) {
		return FirstHostDelivery{}, ErrInvalid
	}
	if latestGlobal.Scope != ScopeGlobal || latestGlobal.State != ScopeActive || latestMachine.Scope != ScopeMachine || latestMachine.MachineID != recipient.SubjectID || latestMachine.State != ScopeActive ||
		latestGlobal.Version < bootstrapGlobal.Version || latestMachine.Version < bootstrapMachine.Version ||
		latestGlobal.Version == bootstrapGlobal.Version && latestGlobal.ID != bootstrapGlobal.ID ||
		latestMachine.Version == bootstrapMachine.Version && latestMachine.ID != bootstrapMachine.ID ||
		!validStandaloneManifestMutationShape(latestGlobal) || !validStandaloneManifestMutationShape(latestMachine) {
		return FirstHostDelivery{}, ErrInvalid
	}
	openedGlobal, err := DecryptManifest(latestGlobal, recipient)
	if err != nil {
		return FirstHostDelivery{}, ErrInvalid
	}
	openedMachine, err := DecryptManifest(latestMachine, recipient)
	if err != nil {
		clearValues(openedGlobal.Values)
		clear(openedGlobal.ScopeKey)
		return FirstHostDelivery{}, ErrInvalid
	}
	effective, err := MergeScopes(openedGlobal.Values, openedMachine.Values)
	if err != nil {
		clearValues(openedGlobal.Values)
		clear(openedGlobal.ScopeKey)
		clearValues(openedMachine.Values)
		clear(openedMachine.ScopeKey)
		return FirstHostDelivery{}, ErrInvalid
	}
	return FirstHostDelivery{Global: openedGlobal, Machine: openedMachine, Effective: effective}, nil
}

// ValidateLatestAfterHighWater applies the same monotonic latest-pair rule for
// an existing host whose durable old pair is already trusted. The caller must
// first verify and persist every sequential authority document through
// currentAuthority.
func ValidateLatestAfterHighWater(oldGlobal, oldMachine, latestGlobal, latestMachine Manifest, oldAuthority, currentAuthority Authority, recipient RecipientPrivate) (FirstHostDelivery, error) {
	return ValidateLatestAfterFirstDelivery(oldGlobal, oldMachine, latestGlobal, latestMachine, oldAuthority, currentAuthority, recipient)
}

func validFirstPairTransitionShape(manifest Manifest) bool {
	if manifest.Mutation == MutationInitialize {
		return manifest.PreviousVersion == 0 && manifest.Version == 1 && manifest.KeyEpoch == 1 && len(manifest.Names) == 0 && len(manifest.ChangedNames) == 0
	}
	if manifest.Mutation == MutationReset && manifest.PreviousVersion == 0 {
		// A root-authorized reset can initialize a scope that has no prior
		// manifest, such as a newly enrolled machine. ValidateFirstHostDelivery
		// applies the reset-scope authorization gate before reaching this shape
		// check, so this does not make an unauthorized genesis acceptable.
		return manifest.Version == 1 && manifest.KeyEpoch == 1 && len(manifest.Names) == 0 && len(manifest.ChangedNames) == 0
	}
	return manifest.PreviousVersion > 0 && manifest.Version == manifest.PreviousVersion+1 && manifest.KeyEpoch > 0 &&
		(manifest.Mutation == MutationReauthorize || manifest.Mutation == MutationRotate || manifest.Mutation == MutationReset) &&
		(manifest.Mutation != MutationReauthorize && manifest.Mutation != MutationRotate || len(manifest.ChangedNames) == 0) &&
		(manifest.Mutation != MutationReset || len(manifest.Names) == 0)
}

func validStandaloneManifestMutationShape(manifest Manifest) bool {
	if manifest.PreviousVersion+1 != manifest.Version || manifest.KeyEpoch == 0 {
		return false
	}
	switch manifest.Mutation {
	case MutationInitialize:
		return manifest.PreviousVersion == 0 && manifest.Version == 1 && manifest.KeyEpoch == 1 && len(manifest.Names) == 0 && len(manifest.ChangedNames) == 0
	case MutationSet:
		return len(manifest.ChangedNames) == 1 && contains(manifest.Names, manifest.ChangedNames[0])
	case MutationUnset:
		return len(manifest.ChangedNames) == 1 && !contains(manifest.Names, manifest.ChangedNames[0])
	case MutationReauthorize, MutationRotate:
		return len(manifest.ChangedNames) == 0
	case MutationReset:
		if manifest.PreviousVersion == 0 {
			return manifest.Version == 1 && manifest.KeyEpoch == 1 && len(manifest.Names) == 0 && len(manifest.ChangedNames) == 0
		}
		return len(manifest.Names) == 0
	default:
		return false
	}
}

func authorityHasReset(authority Authority, scope ScopeKind, machineID string) bool {
	for _, reset := range authority.ResetScopes {
		if reset.Scope == scope && reset.MachineID == machineID {
			return true
		}
	}
	return false
}

func removedRecipient(old, next []RecipientWrap) bool {
	for _, prior := range old {
		found := false
		for _, candidate := range next {
			if prior.Kind == candidate.Kind && prior.SubjectID == candidate.SubjectID && prior.KeyGeneration == candidate.KeyGeneration && prior.KeyID == candidate.KeyID {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func encodeScope(values map[string][]byte) ([]string, []byte, error) {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	if validateNames(names) != nil {
		return nil, nil, ErrInvalid
	}
	entries := make([]any, len(names))
	total := 0
	for i, name := range names {
		value := values[name]
		if len(value) > MaximumValueBytes || bytes.IndexByte(value, 0) >= 0 || !utf8.Valid(value) {
			return nil, nil, ErrInvalid
		}
		total += len(name) + len(value)
		entries[i] = []any{name, value}
	}
	raw, err := encode([]any{"paperboat.environment.scope-plaintext", uint64(1), entries})
	if err != nil || len(raw) > MaximumScopeBytes || total > MaximumScopeBytes {
		return nil, nil, ErrInvalid
	}
	return names, raw, nil
}
func decodeScope(raw []byte) (map[string][]byte, []string, error) {
	var v any
	if decodeCanonical(raw, MaximumScopeBytes, &v) != nil {
		return nil, nil, ErrInvalid
	}
	a, e := array(v, 3)
	if e != nil || requireDomain(a, "paperboat.environment.scope-plaintext", 1) != nil {
		return nil, nil, ErrInvalid
	}
	entries, e := arrayAny(a[2])
	if e != nil || len(entries) > MaximumVariables {
		return nil, nil, ErrInvalid
	}
	values := make(map[string][]byte, len(entries))
	names := make([]string, len(entries))
	for i, x := range entries {
		p, e := array(x, 2)
		if e != nil {
			return nil, nil, ErrInvalid
		}
		name, e1 := text(p[0])
		value, e2 := bytesValue(p[1], -1)
		if e1 != nil || e2 != nil || len(value) > MaximumValueBytes || bytes.IndexByte(value, 0) >= 0 || !utf8.Valid(value) {
			return nil, nil, ErrInvalid
		}
		names[i] = name
		values[name] = value
	}
	if validateNames(names) != nil {
		return nil, nil, ErrInvalid
	}
	return values, names, nil
}

var paddingBuckets = []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 512 << 10}

func padPlaintext(random io.Reader, plain []byte) ([]byte, error) {
	needed := 4 + len(plain)
	bucket := 0
	for _, size := range paddingBuckets {
		if needed <= size {
			bucket = size
			break
		}
	}
	if bucket == 0 {
		return nil, ErrInvalid
	}
	out := make([]byte, bucket)
	binary.BigEndian.PutUint32(out, uint32(len(plain)))
	copy(out[4:], plain)
	if _, err := io.ReadFull(random, out[4+len(plain):]); err != nil {
		return nil, err
	}
	return out, nil
}
func unpadPlaintext(padded []byte) ([]byte, error) {
	if !containsInt(paddingBuckets, len(padded)) || len(padded) < 4 {
		return nil, ErrInvalid
	}
	length := int(binary.BigEndian.Uint32(padded))
	if length <= 0 || length > len(padded)-4 || length > MaximumScopeBytes {
		return nil, ErrInvalid
	}
	return cloneBytes(padded[4 : 4+length]), nil
}
func validCiphertextLength(n int) bool {
	for _, b := range paddingBuckets {
		if n == b+16 {
			return true
		}
	}
	return false
}

func validateRecipient(r Recipient) error {
	kid, e := KeyIDX25519(r.PublicKey)
	if e != nil || kid != r.KeyID || !validIdentifier(r.SubjectID) || r.KeyGeneration == 0 || r.KeyGeneration > MaximumContractInteger || r.Kind < RecipientManager || r.Kind > RecipientRecovery {
		return ErrInvalid
	}
	return nil
}
func validateWrap(w RecipientWrap) error {
	if !validIdentifier(w.SubjectID) || !validKeyID(w.KeyID) || w.KeyGeneration == 0 || w.KeyGeneration > MaximumContractInteger || w.Kind < RecipientManager || w.Kind > RecipientRecovery || len(w.EncapsulatedKey) != 32 || len(w.Ciphertext) != 48 {
		return ErrInvalid
	}
	return nil
}
func recipientLess(a, b Recipient) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.SubjectID != b.SubjectID {
		return a.SubjectID < b.SubjectID
	}
	if a.KeyGeneration != b.KeyGeneration {
		return a.KeyGeneration < b.KeyGeneration
	}
	return a.KeyID < b.KeyID
}
func wrapLess(a, b RecipientWrap) bool {
	return recipientLess(Recipient{Kind: a.Kind, SubjectID: a.SubjectID, KeyGeneration: a.KeyGeneration, KeyID: a.KeyID}, Recipient{Kind: b.Kind, SubjectID: b.SubjectID, KeyGeneration: b.KeyGeneration, KeyID: b.KeyID})
}
func equalWrapRecipients(w []RecipientWrap, r []Recipient) bool {
	if len(w) != len(r) {
		return false
	}
	for i := range w {
		if w[i].Kind != r[i].Kind || w[i].SubjectID != r[i].SubjectID || w[i].KeyGeneration != r[i].KeyGeneration || w[i].KeyID != r[i].KeyID {
			return false
		}
	}
	return true
}
func machineValue(c ManifestClaims) any {
	if c.Scope == ScopeMachine {
		return c.MachineID
	}
	return nil
}
func stringsAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
func parseStringArray(v any) ([]string, error) {
	items, e := arrayAny(v)
	if e != nil {
		return nil, e
	}
	out := make([]string, len(items))
	for i, x := range items {
		out[i], e = text(x)
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func contains(a []string, x string) bool {
	i := sort.SearchStrings(a, x)
	return i < len(a) && a[i] == x
}
func addedOne(old, next []string, name string) bool {
	copyOld := append([]string(nil), old...)
	copyOld = append(copyOld, name)
	sort.Strings(copyOld)
	return equalStrings(copyOld, next)
}
func removedOne(old, next []string, name string) bool {
	out := make([]string, 0, len(old)-1)
	removed := false
	for _, x := range old {
		if x == name && !removed {
			removed = true
			continue
		}
		out = append(out, x)
	}
	return removed && equalStrings(out, next)
}
func containsInt(a []int, x int) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}
func boolError(ok bool) error {
	if !ok {
		return ErrInvalid
	}
	return nil
}
func clearValues(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}
