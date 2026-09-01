package envinject

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type CryptoProcessorConfig struct {
	AccountID              string
	MachineID              string
	InstallationGeneration uint64
	HostKeyGeneration      uint64
	HostRecipientKeyID     string
	RootKeyID              string
	RootPublicKey          ed25519.PublicKey
	// TrustedKeys is the complete account E2EE root set authenticated during
	// machine endpoint enrollment. RootPublicKey remains the endpoint
	// certificate issuer and must be a member of this set. ENV authority
	// documents may be signed by another enrolled account root.
	TrustedKeys []endpointidentity.TrustedKey
	Keys        environmentkey.Source
}

type CryptoProcessor struct{ config CryptoProcessorConfig }

func NewCryptoProcessor(config CryptoProcessorConfig) (*CryptoProcessor, error) {
	if !validIdentifier(config.AccountID) || !validIdentifier(config.MachineID) || config.InstallationGeneration == 0 ||
		config.HostKeyGeneration == 0 || !validKeyID(config.HostRecipientKeyID) || config.Keys == nil ||
		len(config.RootPublicKey) != ed25519.PublicKeySize || !strings.HasPrefix(config.RootKeyID, "aek_") {
		return nil, ErrInvalidSnapshot
	}
	rootFingerprint := sha256.Sum256(config.RootPublicKey)
	if config.RootKeyID != "aek_"+hex.EncodeToString(rootFingerprint[:]) {
		return nil, ErrInvalidSnapshot
	}
	trusted, err := normalizeTrustedKeys(config.RootKeyID, config.RootPublicKey, config.TrustedKeys)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	config.RootPublicKey = append(ed25519.PublicKey(nil), config.RootPublicKey...)
	config.TrustedKeys = trusted
	return &CryptoProcessor{config: config}, nil
}

func (p *CryptoProcessor) Restore(ctx context.Context, cache Cache) (Verified, error) {
	if p == nil || ctx == nil || !p.matches(cache) {
		return Verified{}, ErrInvalidSnapshot
	}
	authorities, err := p.parseAuthorities(cache.AuthorityDocuments)
	if err != nil || len(authorities) == 0 || cache.Authority == nil {
		if cache.Authority == nil && len(cache.AuthorityDocuments) == 0 && cache.GlobalManifest == nil && cache.MachineManifest == nil && !cache.Revoked {
			return Verified{}, nil
		}
		return Verified{}, ErrInvalidSnapshot
	}
	head := authorities[len(authorities)-1]
	if head.Generation != cache.Authority.Generation || head.ID.String() != cache.Authority.AuthorityID {
		return Verified{}, ErrInvalidSnapshot
	}
	if cache.Revoked {
		if p.hostAuthorized(head) || cache.GlobalManifest != nil || cache.MachineManifest != nil {
			return Verified{}, ErrInvalidSnapshot
		}
		return Verified{Authority: cloneCursor(cache.Authority), Revoked: true}, nil
	}
	if cache.GlobalManifest == nil && cache.MachineManifest == nil {
		return Verified{Authority: cloneCursor(cache.Authority)}, nil
	}
	if cache.GlobalManifest == nil || cache.MachineManifest == nil || !p.hostAuthorized(head) {
		return Verified{}, ErrInvalidSnapshot
	}
	global, _, err := parseCachedManifest(cache.GlobalManifest, authorities)
	if err != nil || global.Scope != environmente2ee.ScopeGlobal || global.State != environmente2ee.ScopeActive {
		return Verified{}, ErrInvalidSnapshot
	}
	machine, _, err := parseCachedManifest(cache.MachineManifest, authorities)
	if err != nil || machine.Scope != environmente2ee.ScopeMachine || machine.MachineID != p.config.MachineID || machine.State != environmente2ee.ScopeActive {
		return Verified{}, ErrInvalidSnapshot
	}
	variables, err := p.decrypt(ctx, global, machine)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Authority: cloneCursor(cache.Authority), Global: manifestCursor(global), Machine: manifestCursor(machine),
		Variables: variables, Ready: true,
	}, nil
}

func (p *CryptoProcessor) Apply(ctx context.Context, cache Cache, bundle Bundle) (Cache, Verified, error) {
	if p == nil || ctx == nil || !p.matches(cache) || bundle.Schema != BundleSchema || !validAuthorityCursor(bundle.AuthorityHead) || len(bundle.AuthorityDocuments) > 4 {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	if len(bundle.AuthorityDocuments) > 0 {
		if bundle.Bootstrap != nil || bundle.GlobalManifest != nil || bundle.MachineManifest != nil {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		current, err := p.parseAuthorities(cache.AuthorityDocuments)
		if err != nil && cache.Authority != nil {
			return Cache{}, Verified{}, err
		}
		var previous *environmente2ee.Authority
		if len(current) > 0 {
			previous = &current[len(current)-1]
		}
		decodedBytes := 0
		pageAuthorities := make([]environmente2ee.Authority, 0, len(bundle.AuthorityDocuments))
		expectedRootID := ""
		if len(current) > 0 {
			expectedRootID = current[0].RootKeyID
		}
		for _, encoded := range bundle.AuthorityDocuments {
			raw, err := decodeCanonicalBase64(encoded, environmente2ee.MaximumAuthorityBytes)
			if err != nil {
				return Cache{}, Verified{}, err
			}
			decodedBytes += len(raw)
			if decodedBytes > 4<<20 {
				clear(raw)
				return Cache{}, Verified{}, ErrInvalidSnapshot
			}
			next, err := environmente2ee.ParseAuthority(raw, p.roots())
			clear(raw)
			if err != nil || next.AccountID != p.config.AccountID || environmente2ee.ValidateAuthorityTransition(previous, next) != nil {
				return Cache{}, Verified{}, ErrInvalidSnapshot
			}
			// The current ENV authority signer is pinned at genesis. A future
			// root-set evolution must be an explicit cross-signed transition,
			// never an implicit signer change in a runtime page.
			if expectedRootID != "" && next.RootKeyID != expectedRootID {
				return Cache{}, Verified{}, ErrInvalidSnapshot
			}
			if expectedRootID == "" {
				expectedRootID = next.RootKeyID
			}
			value := next
			previous = &value
			pageAuthorities = append(pageAuthorities, next)
		}
		if previous == nil || previous.Generation > bundle.AuthorityHead.Generation ||
			previous.Generation == bundle.AuthorityHead.Generation && previous.ID.String() != bundle.AuthorityHead.AuthorityID ||
			bundle.AuthorityHasMore != (previous.Generation < bundle.AuthorityHead.Generation) {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		cache.Authority = &Cursor{Generation: previous.Generation, AuthorityID: previous.ID.String()}
		cache.AuthorityDocuments, err = p.compactAuthorityDocuments(cache, current, pageAuthorities, bundle.AuthorityDocuments)
		if err != nil {
			return Cache{}, Verified{}, err
		}
		if bundle.RevocationOnly {
			if !bundle.AuthorityHasMore && previous.Generation != bundle.AuthorityHead.Generation {
				return Cache{}, Verified{}, ErrInvalidSnapshot
			}
			if !p.hostAuthorized(*previous) {
				cache.Revoked = true
				cache.GlobalManifest, cache.MachineManifest = nil, nil
				cache.AuthorityDocuments = []string{bundle.AuthorityDocuments[len(bundle.AuthorityDocuments)-1]}
				return cache, Verified{Authority: cloneCursor(cache.Authority), Revoked: true}, nil
			}
			if !bundle.AuthorityHasMore {
				return Cache{}, Verified{}, ErrInvalidSnapshot
			}
		}
		if !p.hostAuthorized(*previous) && previous.Generation == bundle.AuthorityHead.Generation {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		verified, err := p.Restore(ctx, cache)
		return cache, verified, err
	}
	if bundle.AuthorityHasMore || bundle.RevocationOnly || cache.Authority == nil || cache.Authority.Generation != bundle.AuthorityHead.Generation || cache.Authority.AuthorityID != bundle.AuthorityHead.AuthorityID {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	if bundle.GlobalManifest == nil && bundle.MachineManifest == nil {
		if bundle.Bootstrap != nil {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		verified, err := p.restoreOrPending(ctx, cache)
		return cache, verified, err
	}
	if bundle.GlobalManifest == nil || bundle.MachineManifest == nil {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	authorities, err := p.parseAuthorities(cache.AuthorityDocuments)
	if err != nil || len(authorities) == 0 {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	head := authorities[len(authorities)-1]
	if head.Generation != cache.Authority.Generation || head.ID.String() != cache.Authority.AuthorityID || !p.hostAuthorized(head) {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	global, err := parseResponseManifest(bundle.GlobalManifest, head)
	if err != nil || global.Scope != environmente2ee.ScopeGlobal || global.State != environmente2ee.ScopeActive {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	machine, err := parseResponseManifest(bundle.MachineManifest, head)
	if err != nil || machine.Scope != environmente2ee.ScopeMachine || machine.MachineID != p.config.MachineID || machine.State != environmente2ee.ScopeActive {
		return Cache{}, Verified{}, ErrInvalidSnapshot
	}
	oldGlobal, oldGlobalAuthority, err := cachedManifest(cache.GlobalManifest, authorities)
	if err != nil {
		return Cache{}, Verified{}, err
	}
	oldMachine, oldMachineAuthority, err := cachedManifest(cache.MachineManifest, authorities)
	if err != nil {
		return Cache{}, Verified{}, err
	}
	var variables map[string]string
	if oldGlobal == nil && oldMachine == nil {
		variables, err = p.validateFirstDelivery(ctx, bundle.Bootstrap, authorities, head, global, machine)
		if err != nil {
			return Cache{}, Verified{}, err
		}
	} else {
		if bundle.Bootstrap != nil || oldGlobal == nil || oldMachine == nil {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		if oldGlobalAuthority == nil || oldMachineAuthority == nil || oldGlobalAuthority.ID != oldMachineAuthority.ID {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		material, recipient, recipientErr := p.recipient(ctx)
		if recipientErr != nil {
			return Cache{}, Verified{}, recipientErr
		}
		latest, latestErr := environmente2ee.ValidateLatestAfterHighWater(*oldGlobal, *oldMachine, global, machine, *oldGlobalAuthority, head, recipient)
		material.Destroy()
		if latestErr != nil {
			return Cache{}, Verified{}, ErrInvalidSnapshot
		}
		variables, err = stringValues(latest.Effective)
		clearFirstHostDelivery(latest)
		if err != nil {
			return Cache{}, Verified{}, err
		}
	}
	cache.GlobalManifest = cloneManifest(bundle.GlobalManifest)
	cache.MachineManifest = cloneManifest(bundle.MachineManifest)
	cache.Revoked = false
	cache.AuthorityDocuments = []string{base64.RawURLEncoding.EncodeToString(head.Raw)}
	return cache, Verified{
		Authority: cloneCursor(cache.Authority), Global: manifestCursor(global), Machine: manifestCursor(machine),
		Variables: variables, Ready: true,
	}, nil
}

func (p *CryptoProcessor) validateFirstDelivery(ctx context.Context, bootstrap *AuthorizationBootstrap, authorities []environmente2ee.Authority, head environmente2ee.Authority, latestGlobal, latestMachine environmente2ee.Manifest) (map[string]string, error) {
	if bootstrap == nil || !validAuthorityCursor(bootstrap.Authority) {
		return nil, ErrInvalidSnapshot
	}
	bootstrapAuthority, index, ok := authorityForCursor(authorities, bootstrap.Authority)
	if !ok {
		return nil, ErrInvalidSnapshot
	}
	var prior *environmente2ee.Authority
	if bootstrapAuthority.PreviousID != nil {
		if index == 0 || authorities[index-1].ID != *bootstrapAuthority.PreviousID || authorities[index-1].Generation+1 != bootstrapAuthority.Generation {
			return nil, ErrInvalidSnapshot
		}
		value := authorities[index-1]
		prior = &value
	}
	bootstrapGlobal, err := parseResponseManifest(&bootstrap.GlobalManifest, bootstrapAuthority)
	if err != nil {
		return nil, err
	}
	bootstrapMachine, err := parseResponseManifest(&bootstrap.MachineManifest, bootstrapAuthority)
	if err != nil {
		return nil, err
	}
	material, recipient, err := p.recipient(ctx)
	if err != nil {
		return nil, err
	}
	defer material.Destroy()
	anchor, err := environmente2ee.ValidateFirstHostDelivery(prior, bootstrapAuthority, bootstrapGlobal, bootstrapMachine, recipient)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	clearFirstHostDelivery(anchor)
	latest, err := environmente2ee.ValidateLatestAfterFirstDelivery(bootstrapGlobal, bootstrapMachine, latestGlobal, latestMachine, bootstrapAuthority, head, recipient)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	defer clearFirstHostDelivery(latest)
	return stringValues(latest.Effective)
}

func (p *CryptoProcessor) restoreOrPending(ctx context.Context, cache Cache) (Verified, error) {
	verified, err := p.Restore(ctx, cache)
	if err == nil {
		return verified, nil
	}
	if cache.GlobalManifest == nil && cache.MachineManifest == nil {
		return Verified{Authority: cloneCursor(cache.Authority)}, nil
	}
	return Verified{}, err
}

func (p *CryptoProcessor) decrypt(ctx context.Context, global, machine environmente2ee.Manifest) (map[string]string, error) {
	material, private, err := p.recipient(ctx)
	if err != nil {
		return nil, err
	}
	defer material.Destroy()
	globalPlain, err := environmente2ee.DecryptManifest(global, private)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	defer clearScope(globalPlain)
	machinePlain, err := environmente2ee.DecryptManifest(machine, private)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	defer clearScope(machinePlain)
	merged, err := environmente2ee.MergeScopes(globalPlain.Values, machinePlain.Values)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	defer clearValues(merged)
	values := make(map[string]string, len(merged))
	for name, value := range merged {
		values[name] = string(value)
	}
	if ValidateVariables(values) != nil {
		return nil, ErrInvalidSnapshot
	}
	return values, nil
}

func (p *CryptoProcessor) recipient(ctx context.Context) (*environmentkey.Material, environmente2ee.RecipientPrivate, error) {
	material, err := p.config.Keys.Load(ctx)
	if err != nil {
		return nil, environmente2ee.RecipientPrivate{}, err
	}
	if material.Generation != p.config.HostKeyGeneration {
		material.Destroy()
		return nil, environmente2ee.RecipientPrivate{}, ErrInvalidSnapshot
	}
	return &material, environmente2ee.RecipientPrivate{Kind: environmente2ee.RecipientHost, SubjectID: p.config.MachineID, KeyGeneration: p.config.HostKeyGeneration, KeyID: p.config.HostRecipientKeyID, PrivateKey: material.Private[:]}, nil
}

func (p *CryptoProcessor) parseAuthorities(encoded []string) ([]environmente2ee.Authority, error) {
	result := make([]environmente2ee.Authority, len(encoded))
	for index, item := range encoded {
		raw, err := decodeCanonicalBase64(item, environmente2ee.MaximumAuthorityBytes)
		if err != nil {
			return nil, err
		}
		authority, err := environmente2ee.ParseAuthority(raw, p.roots())
		clear(raw)
		if err != nil || authority.AccountID != p.config.AccountID {
			return nil, ErrInvalidSnapshot
		}
		if index > 0 {
			previous := result[index-1]
			if previous.Generation >= authority.Generation {
				return nil, ErrInvalidSnapshot
			}
			// Compact offline state may intentionally omit already validated
			// intermediate generations. Whenever retained documents are adjacent,
			// preserve and verify the exact root-signed link between them.
			if previous.Generation+1 == authority.Generation && environmente2ee.ValidateAuthorityTransition(&previous, authority) != nil {
				return nil, ErrInvalidSnapshot
			}
			// Keep the same pinned signer across retained documents, including
			// compacted pages whose generations are not adjacent locally.
			if previous.RootKeyID != authority.RootKeyID {
				return nil, ErrInvalidSnapshot
			}
		}
		result[index] = authority
	}
	return result, nil
}

func (p *CryptoProcessor) hostAuthorized(authority environmente2ee.Authority) bool {
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == environmente2ee.SubjectHost && binding.SubjectID == p.config.MachineID &&
			binding.SubjectGeneration == p.config.InstallationGeneration && binding.KeyGeneration == p.config.HostKeyGeneration &&
			binding.RecipientKeyID == p.config.HostRecipientKeyID {
			return true
		}
	}
	return false
}

func (p *CryptoProcessor) matches(cache Cache) bool {
	return cache.AccountID == p.config.AccountID && cache.MachineID == p.config.MachineID &&
		cache.InstallationGeneration == p.config.InstallationGeneration && cache.HostKeyGeneration == p.config.HostKeyGeneration &&
		cache.HostRecipientKeyID == p.config.HostRecipientKeyID
}

func (p *CryptoProcessor) roots() environmente2ee.RootKeys {
	roots := make(environmente2ee.RootKeys, len(p.config.TrustedKeys))
	for _, key := range p.config.TrustedKeys {
		roots[key.KeyID] = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	return roots
}

func normalizeTrustedKeys(rootKeyID string, rootPublic ed25519.PublicKey, trusted []endpointidentity.TrustedKey) ([]endpointidentity.TrustedKey, error) {
	if len(trusted) == 0 {
		return []endpointidentity.TrustedKey{{KeyID: rootKeyID, PublicKey: append(ed25519.PublicKey(nil), rootPublic...), Fingerprint: sha256.Sum256(rootPublic), Generation: 1}}, nil
	}
	validated, err := endpointidentity.ValidateTrustedKeySet(trusted)
	if err != nil {
		return nil, err
	}
	for _, key := range validated {
		fingerprint := sha256.Sum256(key.PublicKey)
		if key.KeyID != "aek_"+hex.EncodeToString(fingerprint[:]) {
			clearTrustedKeys(validated)
			return nil, endpointidentity.ErrTrustedKeySet
		}
	}
	selected, ok := endpointidentity.TrustedKeyFor(validated, rootKeyID)
	if !ok || !bytes.Equal(selected.PublicKey, rootPublic) {
		clearTrustedKeys(validated)
		return nil, endpointidentity.ErrTrustedKeySet
	}
	return validated, nil
}

func clearTrustedKeys(keys []endpointidentity.TrustedKey) {
	for index := range keys {
		clear(keys[index].PublicKey)
	}
}

func parseResponseManifest(document *ManifestEnvelope, authority environmente2ee.Authority) (environmente2ee.Manifest, error) {
	raw, err := decodeCanonicalBase64(document.Envelope, environmente2ee.MaximumManifestBytes)
	if err != nil {
		return environmente2ee.Manifest{}, err
	}
	defer clear(raw)
	manifest, err := environmente2ee.ParseManifest(raw, authority)
	if err != nil || manifest.Version != document.Version || manifest.KeyEpoch != document.KeyEpoch || manifest.ID.String() != document.ManifestID {
		return environmente2ee.Manifest{}, ErrInvalidSnapshot
	}
	return manifest, nil
}

func parseCachedManifest(document *ManifestEnvelope, authorities []environmente2ee.Authority) (environmente2ee.Manifest, environmente2ee.Authority, error) {
	var match *environmente2ee.Manifest
	var matchedAuthority environmente2ee.Authority
	for _, authority := range authorities {
		manifest, err := parseResponseManifest(document, authority)
		if err == nil {
			if match != nil {
				return environmente2ee.Manifest{}, environmente2ee.Authority{}, ErrInvalidSnapshot
			}
			value := manifest
			match, matchedAuthority = &value, authority
		}
	}
	if match == nil {
		return environmente2ee.Manifest{}, environmente2ee.Authority{}, ErrInvalidSnapshot
	}
	return *match, matchedAuthority, nil
}

func cachedManifest(oldDocument *ManifestEnvelope, authorities []environmente2ee.Authority) (*environmente2ee.Manifest, *environmente2ee.Authority, error) {
	if oldDocument == nil {
		return nil, nil, nil
	}
	old, authority, err := parseCachedManifest(oldDocument, authorities)
	if err != nil {
		return nil, nil, err
	}
	return &old, &authority, nil
}

func authorityForCursor(authorities []environmente2ee.Authority, cursor Cursor) (environmente2ee.Authority, int, bool) {
	for index, authority := range authorities {
		if authority.Generation == cursor.Generation && authority.ID.String() == cursor.AuthorityID {
			return authority, index, true
		}
	}
	return environmente2ee.Authority{}, -1, false
}

func (p *CryptoProcessor) compactAuthorityDocuments(cache Cache, current, page []environmente2ee.Authority, pageEncoded []string) ([]string, error) {
	combined := append(append([]environmente2ee.Authority(nil), current...), page...)
	encoded := append(append([]string(nil), cache.AuthorityDocuments...), pageEncoded...)
	wanted := make(map[string]struct{}, 3)
	for _, document := range []*ManifestEnvelope{cache.GlobalManifest, cache.MachineManifest} {
		if document == nil {
			continue
		}
		_, authority, err := parseCachedManifest(document, current)
		if err != nil {
			return nil, err
		}
		wanted[authority.ID.String()] = struct{}{}
	}
	if cache.GlobalManifest == nil && cache.MachineManifest == nil {
		for index, authority := range combined {
			if !p.hostAuthorized(authority) {
				continue
			}
			wanted[authority.ID.String()] = struct{}{}
			if index > 0 {
				wanted[combined[index-1].ID.String()] = struct{}{}
			}
			break
		}
	}
	latest := combined[len(combined)-1]
	wanted[latest.ID.String()] = struct{}{}
	result := make([]string, 0, len(wanted)+1)
	for index, authority := range combined {
		if _, ok := wanted[authority.ID.String()]; ok {
			result = append(result, encoded[index])
		}
	}
	if len(result) == 0 || len(result) > 3 || latest.Generation == 0 {
		return nil, ErrInvalidSnapshot
	}
	return result, nil
}

func manifestCursor(manifest environmente2ee.Manifest) *ManifestCursor {
	return &ManifestCursor{Version: manifest.Version, KeyEpoch: manifest.KeyEpoch, ManifestID: manifest.ID.String()}
}

func decodeCanonicalBase64(value string, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, ErrInvalidSnapshot
	}
	return decoded, nil
}

func validAuthorityCursor(value Cursor) bool {
	if value.Generation == 0 || value.Generation > environmente2ee.MaximumContractInteger {
		return false
	}
	_, err := environmente2ee.ParseDocumentID(value.AuthorityID)
	return err == nil
}

func clearScope(scope environmente2ee.DecryptedScope) {
	clear(scope.ScopeKey)
	for key, value := range scope.Values {
		clear(value)
		delete(scope.Values, key)
	}
}

func clearValues(values map[string][]byte) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

func clearFirstHostDelivery(delivery environmente2ee.FirstHostDelivery) {
	clearScope(delivery.Global)
	clearScope(delivery.Machine)
	clearValues(delivery.Effective)
}

func stringValues(values map[string][]byte) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = string(value)
	}
	if ValidateVariables(result) != nil {
		return nil, ErrInvalidSnapshot
	}
	return result, nil
}

var _ Processor = (*CryptoProcessor)(nil)
