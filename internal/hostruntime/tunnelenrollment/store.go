package tunnelenrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
)

const maximumJournalBytes = 256 << 10

type FileCredentialStore struct {
	root     string
	secrets  config.SecretStore
	mu       sync.Mutex
	failSave int
}

func NewFileCredentialStore(stateRoot string) (*FileCredentialStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return nil, ErrInvalid
	}
	root := filepath.Join(stateRoot, "tunnel-enrollment")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.Join(ErrSecretStore, err)
	}
	return &FileCredentialStore{root: root, secrets: config.FileSecretStore{Dir: filepath.Join(root, "credentials")}}, nil
}

func (s *FileCredentialStore) CreateKey(ctx context.Context, refID string) (Credential, error) {
	if s == nil || ctx == nil || !safeID(refID) {
		return Credential{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credential{}, err
	}
	defer clear(private)
	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		return Credential{}, err
	}
	reference := "protected-file://paperboat/connectors/" + refID
	if err := s.secrets.Set(keyRef(reference), base64.RawURLEncoding.EncodeToString(private)); err != nil {
		return Credential{}, errors.Join(ErrSecretStore, err)
	}
	return Credential{Reference: reference, KeyID: "ed25519:" + thumbprint, Thumbprint: thumbprint, PublicKey: append([]byte(nil), public...)}, nil
}

// Put implements connectorrotation.KeyStore without returning private bytes.
// The caller clears its generated key after this method transfers it into the
// protected store.
func (s *FileCredentialStore) Put(ctx context.Context, private ed25519.PrivateKey) (connectorrotation.KeyReference, error) {
	if s == nil || ctx == nil || len(private) != ed25519.PrivateKeySize {
		return connectorrotation.KeyReference{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return connectorrotation.KeyReference{}, err
	}
	refID, err := randomID("credential")
	if err != nil {
		return connectorrotation.KeyReference{}, err
	}
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		return connectorrotation.KeyReference{}, err
	}
	reference := "protected-file://paperboat/connectors/" + refID
	if err := s.secrets.Set(keyRef(reference), base64.RawURLEncoding.EncodeToString(private)); err != nil {
		return connectorrotation.KeyReference{}, errors.Join(ErrSecretStore, err)
	}
	return connectorrotation.KeyReference{Reference: reference, KeyID: "ed25519:" + thumbprint, Thumbprint: thumbprint, PublicKey: public}, nil
}

// Delete is idempotent for a protected connector credential reference.
func (s *FileCredentialStore) Delete(ctx context.Context, reference string) error {
	if s == nil || ctx == nil || connectorprotocol.ValidateCredentialReference(reference) != nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.secrets.Delete(keyRef(reference)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrSecretStore, err)
	}
	return nil
}

func (s *FileCredentialStore) Sign(ctx context.Context, reference string, payload []byte) ([]byte, error) {
	if s == nil || ctx == nil || connectorprotocol.ValidateCredentialReference(reference) != nil || len(payload) == 0 || len(payload) > 64<<10 {
		return nil, ErrInvalid
	}
	encoded, err := s.secrets.Get(keyRef(reference))
	if err != nil {
		return nil, errors.Join(ErrSecretStore, err)
	}
	private, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		clear(private)
		return nil, ErrSecretStore
	}
	defer clear(private)
	return ed25519.Sign(ed25519.PrivateKey(private), payload), nil
}

func (s *FileCredentialStore) PutEnrollmentToken(ctx context.Context, refID, token string) (string, error) {
	if s == nil || ctx == nil || !safeID(refID) || len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token {
		return "", ErrInvalid
	}
	reference := "token-" + refID
	if err := s.secrets.Set(reference, token); err != nil {
		return "", errors.Join(ErrSecretStore, err)
	}
	return reference, nil
}
func (s *FileCredentialStore) EnrollmentToken(ctx context.Context, reference string) (string, error) {
	if s == nil || ctx == nil || !safeID(reference) {
		return "", ErrInvalid
	}
	value, err := s.secrets.Get(reference)
	if err != nil || len(value) < 32 || len(value) > 256 {
		return "", errors.Join(ErrSecretStore, err)
	}
	return value, nil
}
func (s *FileCredentialStore) DeleteEnrollmentToken(ctx context.Context, reference string) error {
	if s == nil || ctx == nil || !safeID(reference) {
		return ErrInvalid
	}
	return s.secrets.Delete(reference)
}

func keyRef(reference string) string {
	parsed, _ := url.Parse(reference)
	return "connector-key-" + strings.TrimPrefix(parsed.Path, "/connectors/")
}

type journal struct {
	Version int               `json:"version"`
	Records map[string]record `json:"records"`
}
type record struct {
	AccountID            string      `json:"account_id,omitempty"`
	TunnelID             string      `json:"tunnel_id"`
	HostID               string      `json:"host_id"`
	LocalKey             string      `json:"local_idempotency_key"`
	IssueKey             string      `json:"issue_idempotency_key"`
	ExchangeKey          string      `json:"exchange_idempotency_key"`
	Credential           Credential  `json:"credential"`
	EnrollmentID         string      `json:"enrollment_id,omitempty"`
	TokenReference       string      `json:"token_reference,omitempty"`
	ConnectorID          string      `json:"connector_id,omitempty"`
	OperationID          string      `json:"operation_id,omitempty"`
	StableEndpointID     string      `json:"stable_endpoint_id,omitempty"`
	CredentialGeneration uint64      `json:"credential_generation,omitempty"`
	ProcessGeneration    uint64      `json:"process_generation,omitempty"`
	Phase                string      `json:"phase"`
	Projection           *Projection `json:"projection,omitempty"`
}

func (r record) activationRequest() ActivationRequest {
	return ActivationRequest{
		AccountID: r.AccountID, TunnelID: r.TunnelID, HostID: r.HostID, ConnectorID: r.ConnectorID,
		OperationID: r.OperationID, StableEndpointID: r.StableEndpointID, CredentialReference: r.Credential.Reference,
		CredentialKeyID: r.Credential.KeyID, CredentialThumbprint: r.Credential.Thumbprint,
		CredentialPublicKey:  append([]byte(nil), r.Credential.PublicKey...),
		CredentialGeneration: r.CredentialGeneration, ProcessGeneration: r.ProcessGeneration,
	}
}

func (s *FileCredentialStore) promoteCredential(tunnelID string, previous, next ActivationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadJournalLocked()
	if err != nil {
		return err
	}
	recordValue, ok := state.Records[tunnelID]
	if ok && recordValue.AccountID == next.AccountID && recordValue.HostID == next.HostID && recordValue.ConnectorID == next.ConnectorID && recordValue.StableEndpointID == next.StableEndpointID && recordValue.Credential.Reference == next.CredentialReference && recordValue.CredentialGeneration == next.CredentialGeneration && recordValue.ProcessGeneration == next.ProcessGeneration {
		return nil
	}
	if !ok || recordValue.AccountID != previous.AccountID || recordValue.HostID != previous.HostID || recordValue.ConnectorID != previous.ConnectorID || recordValue.StableEndpointID != previous.StableEndpointID || recordValue.Credential.Reference != previous.CredentialReference || recordValue.CredentialGeneration != previous.CredentialGeneration || recordValue.ProcessGeneration != previous.ProcessGeneration || next.AccountID != previous.AccountID || next.TunnelID != previous.TunnelID || next.HostID != previous.HostID || next.ConnectorID != previous.ConnectorID || next.StableEndpointID != previous.StableEndpointID || next.CredentialGeneration != previous.CredentialGeneration+1 || next.ProcessGeneration <= previous.ProcessGeneration {
		return ErrConflict
	}
	recordValue.Credential = Credential{Reference: next.CredentialReference, KeyID: next.CredentialKeyID, Thumbprint: next.CredentialThumbprint, PublicKey: append([]byte(nil), next.CredentialPublicKey...)}
	recordValue.CredentialGeneration = next.CredentialGeneration
	recordValue.ProcessGeneration = next.ProcessGeneration
	if recordValue.Projection != nil {
		recordValue.Projection.CredentialReference = next.CredentialReference
		recordValue.Projection.CredentialGeneration = next.CredentialGeneration
	}
	state.Records[tunnelID] = recordValue
	return s.saveJournalLocked(state)
}

func (s *FileCredentialStore) loadJournal() (journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadJournalLocked()
}
func (s *FileCredentialStore) saveJournal(value journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveJournalLocked(value)
}
func (s *FileCredentialStore) loadJournalLocked() (journal, error) {
	value := journal{Version: 1, Records: map[string]record{}}
	data, err := os.ReadFile(filepath.Join(s.root, "journal.json"))
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil || len(data) > maximumJournalBytes || rejectDuplicateJSON(data) != nil {
		return journal{}, ErrConflict
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != 1 || value.Records == nil || len(value.Records) > 256 {
		return journal{}, ErrConflict
	}
	for tunnelID, record := range value.Records {
		if !record.valid(tunnelID) {
			return journal{}, ErrConflict
		}
	}
	return value, nil
}
func (s *FileCredentialStore) saveJournalLocked(value journal) error {
	if s.failSave > 0 {
		s.failSave--
		return ErrSecretStore
	}
	if value.Version != 1 || value.Records == nil || len(value.Records) > 256 {
		return ErrConflict
	}
	for tunnelID, record := range value.Records {
		if !record.valid(tunnelID) {
			return ErrConflict
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maximumJournalBytes {
		return ErrConflict
	}
	return atomicfile.Write(filepath.Join(s.root, "journal.json"), append(encoded, '\n'), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var scan func() error
	scan = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, e := decoder.Token()
				if e != nil {
					return e
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrConflict
				}
				if _, ok := seen[key]; ok {
					return ErrConflict
				}
				seen[key] = struct{}{}
				if e = scan(); e != nil {
					return e
				}
			}
			_, err = decoder.Token()
			return err
		case json.Delim('['):
			for decoder.More() {
				if err = scan(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return nil
		}
	}
	return scan()
}

func safeID(value string) bool {
	if len(value) < 3 || len(value) > 180 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func (r record) valid(tunnelID string) bool {
	if r.TunnelID != tunnelID || connectorprotocol.ValidateIdentifier(r.TunnelID) != nil || connectorprotocol.ValidateIdentifier(r.HostID) != nil || !safeID(r.LocalKey) || !safeID(r.IssueKey) || !safeID(r.ExchangeKey) || !r.Credential.valid() {
		return false
	}
	switch r.Phase {
	case "prepared":
		return r.AccountID == "" && r.EnrollmentID == "" && r.TokenReference == "" && r.ConnectorID == "" && r.OperationID == "" && r.CredentialGeneration == 0 && r.ProcessGeneration == 0 && r.Projection == nil
	case "issued":
		return r.AccountID == "" && safeID(r.EnrollmentID) && safeID(r.TokenReference) && r.ConnectorID == "" && r.OperationID == "" && r.CredentialGeneration == 0 && r.ProcessGeneration == 0 && r.Projection == nil
	case "exchanged":
		return connectorprotocol.ValidateIdentifier(r.AccountID) == nil && safeID(r.EnrollmentID) && safeID(r.TokenReference) && connectorprotocol.ValidateIdentifier(r.ConnectorID) == nil && safeID(r.OperationID) && r.CredentialGeneration > 0 && r.ProcessGeneration > 0 && r.Projection == nil
	case "active":
		return connectorprotocol.ValidateIdentifier(r.AccountID) == nil && safeID(r.EnrollmentID) && safeID(r.TokenReference) && connectorprotocol.ValidateIdentifier(r.ConnectorID) == nil && safeID(r.OperationID) && r.CredentialGeneration > 0 && r.ProcessGeneration > 0 && r.Projection != nil && r.Projection.valid() && r.Projection.CredentialGeneration == r.CredentialGeneration && r.Projection.TunnelID == r.TunnelID && r.Projection.HostID == r.HostID && r.Projection.ConnectorID == r.ConnectorID && r.Projection.OperationID == r.OperationID && r.Projection.CredentialReference == r.Credential.Reference
	default:
		return false
	}
}

var _ connectorrotation.KeyStore = (*FileCredentialStore)(nil)
