package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// TakeLogoutCredentials atomically removes the active local profile and all
// revocation records for one issuer while returning every readable refresh
// token for best-effort server revocation. Concurrent login and switch
// mutations serialize on the same profile lock, so logout cannot delete a
// session that committed after its snapshot.
func (s ProfileStore) TakeLogoutCredentials(issuer string) (credentials []Credential, resultErr error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	profilePath := s.profilePath(issuer)
	if err := ensureProfileDirectory(filepath.Dir(profilePath)); err != nil {
		return nil, err
	}
	profileLock := newSharedLock(profilePath + ".lock")
	if err := profileLock.Lock(); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, profileLock.Unlock()) }()

	active, activeErr := s.loadNormalized(issuer)
	if activeErr == nil {
		if refresh, refreshErr := s.Secrets.Get(active.RefreshSecretRef); refreshErr == nil && strings.TrimSpace(refresh) != "" {
			accountID := active.Account.ID
			if accountID != "" && !validCredentialID(accountID) {
				accountID = ""
			}
			if err := s.queueRevocationLocked(issuer, active.CLIClientSessionID, refresh, accountID); err != nil {
				return nil, err
			}
		}
		var cleanupErrs []error
		cleanupErrs = append(cleanupErrs,
			s.Secrets.Delete(active.AccessSecretRef),
			s.Secrets.Delete(active.RefreshSecretRef),
			s.DeleteManagedSSHIdentity(active.Issuer, active.CLIClientSessionID),
			s.DeletePeerEndpointIdentity(active.Issuer, active.CLIClientSessionID),
			s.DeletePeerAccountRoot(active.Issuer, active.Account.ID),
		)
		for _, ref := range active.ObsoleteSecretRefs {
			cleanupErrs = append(cleanupErrs, s.Secrets.Delete(ref))
		}
		if removeErr := os.Remove(profilePath); removeErr != nil && !os.IsNotExist(removeErr) {
			cleanupErrs = append(cleanupErrs, removeErr)
		}
		if err := errors.Join(cleanupErrs...); err != nil {
			return nil, err
		}
	} else if !errors.Is(activeErr, ErrNoCredentials) {
		return nil, activeErr
	}

	records, recordsErr := s.pendingRevocationsLocked(issuer, "")
	if recordsErr == nil {
		for _, record := range records {
			credential, credentialErr := s.PendingRevocationCredential(record)
			if credentialErr == nil && strings.TrimSpace(credential.RefreshToken) != "" {
				credentials = append(credentials, credential)
			}
		}
	}
	// Local logout must not be trapped by corrupt historical metadata. The
	// profile lock prevents any concurrent auth mutation from adding a record
	// between the snapshot above and this cleanup.
	if err := s.DiscardPendingRevocations(issuer); err != nil {
		return nil, err
	}
	return credentials, nil
}
