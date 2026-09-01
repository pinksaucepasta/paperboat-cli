package environmente2ee

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

const (
	ProtocolVersion        = uint64(1)
	CryptoProfile          = uint64(1)
	MaximumContractInteger = uint64(1<<53 - 1)
	MaximumManagers        = 32
	MaximumHosts           = 512
	MaximumVariables       = 128
	MaximumNameBytes       = 128
	MaximumValueBytes      = 32767
	MaximumScopeBytes      = 256 << 10
	MaximumEnrollmentBytes = 8 << 10
	MaximumAbortBytes      = 2 << 10
	MaximumBindingBytes    = 2 << 10
	MaximumAuthorityBytes  = 2 << 20
	MaximumManifestBytes   = 1 << 20
)

const (
	contentKeyBinding = "application/paperboat.environment.key-binding+cbor;v=1"
	contentAuthority  = "application/paperboat.environment.authority+cbor;v=1"
	contentManifest   = "application/paperboat.environment.scope-manifest+cbor;v=1"
	contentAbort      = "application/paperboat.environment.authority-transition-abort+cbor;v=1"
)

type SubjectKind uint64

const (
	SubjectManagerCLI SubjectKind = iota + 1
	SubjectManagerBrowser
	SubjectHost
	SubjectRecovery
)

type ScopeKind uint64

const (
	ScopeGlobal ScopeKind = iota
	ScopeMachine
)

type ScopeState uint64

const (
	ScopeActive ScopeState = iota
	ScopeRetired
)

type MutationKind uint64

const (
	MutationInitialize MutationKind = iota
	MutationSet
	MutationUnset
	MutationReauthorize
	MutationRotate
	MutationReset
)

type RecipientKind uint64

const (
	RecipientManager RecipientKind = iota + 1
	RecipientHost
	RecipientRecovery
)

type DocumentID [sha256.Size]byte

func (id DocumentID) String() string { return "sha256:" + hex.EncodeToString(id[:]) }

func ParseDocumentID(value string) (DocumentID, error) {
	var result DocumentID
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return result, ErrInvalid
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || hex.EncodeToString(decoded) != value[len("sha256:"):] {
		return result, ErrInvalid
	}
	copy(result[:], decoded)
	return result, nil
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var variablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func validVariableName(value string) bool {
	if len(value) == 0 || len(value) > MaximumNameBytes || !variablePattern.MatchString(value) {
		return false
	}
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "PAPERBOAT_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return false
	}
	switch upper {
	case "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "GOTRACEBACK":
		return false
	}
	return true
}

func validateNames(names []string) error {
	if len(names) > MaximumVariables || !sort.StringsAreSorted(names) {
		return ErrInvalid
	}
	seenFold := make(map[string]struct{}, len(names))
	previous := ""
	for index, name := range names {
		fold := strings.ToUpper(name)
		if !validVariableName(name) || index > 0 && name == previous {
			return ErrInvalid
		}
		if _, exists := seenFold[fold]; exists {
			return ErrInvalid
		}
		seenFold[fold] = struct{}{}
		previous = name
	}
	return nil
}

func KeyIDEd25519(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	return jwkThumbprint("Ed25519", public, "sigk_"), nil
}

func KeyIDX25519(public []byte) (string, error) {
	if len(public) != 32 || allZero(public) {
		return "", ErrInvalid
	}
	return jwkThumbprint("X25519", public, "envk_"), nil
}

func jwkThumbprint(curve string, public []byte, prefix string) string {
	x := base64.RawURLEncoding.EncodeToString(public)
	canonical := `{"crv":"` + curve + `","kty":"OKP","x":"` + x + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return prefix + base64.RawURLEncoding.EncodeToString(digest[:])
}

func validKeyID(value string) bool {
	if strings.HasPrefix(value, "aek_") {
		if len(value) != 4+64 {
			return false
		}
		decoded, err := hex.DecodeString(value[4:])
		return err == nil && hex.EncodeToString(decoded) == value[4:]
	}
	if !strings.HasPrefix(value, "sigk_") && !strings.HasPrefix(value, "envk_") {
		return false
	}
	prefixLen := 5
	if len(value) != prefixLen+43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value[prefixLen:])
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value[prefixLen:]
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
