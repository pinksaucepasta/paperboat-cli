package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

type ManagerConfig struct {
	ControlURL   string
	HostID       string
	Auth         MachineAuth
	Transport    http.RoundTripper
	Credentials  *FileCredentialStore
	Activator    Activator
	ControlToken string
}

type Manager struct {
	hostID       string
	server       *serverClient
	store        *FileCredentialStore
	activator    Activator
	controlToken string
	mu           sync.Mutex
	activating   map[string]struct{}
	// processClaims records the process generation claimed by this manager
	// lifetime for each durable connector. A failed activation can therefore
	// retry the exact same claim, while a newly-created manager advances it.
	processClaims map[processGenerationClaimKey]uint64
}

const maxExpiredEnrollmentRetries = 1

var errProcessGenerationExhausted = errors.New("tunnel connector process generation exhausted")

type processGenerationClaimKey struct {
	tunnelID             string
	hostID               string
	accountID            string
	connectorID          string
	operationID          string
	stableEndpointID     string
	credentialReference  string
	credentialGeneration uint64
}

func processGenerationClaimKeyFor(recordValue record) processGenerationClaimKey {
	return processGenerationClaimKey{
		tunnelID:             recordValue.TunnelID,
		hostID:               recordValue.HostID,
		accountID:            recordValue.AccountID,
		connectorID:          recordValue.ConnectorID,
		operationID:          recordValue.OperationID,
		stableEndpointID:     recordValue.StableEndpointID,
		credentialReference:  recordValue.Credential.Reference,
		credentialGeneration: recordValue.CredentialGeneration,
	}
}

func NewManager(config ManagerConfig) (*Manager, error) {
	if connectorprotocol.ValidateIdentifier(config.HostID) != nil || config.Credentials == nil || strings.TrimSpace(config.ControlToken) == "" {
		return nil, ErrInvalid
	}
	server, err := newServerClient(config.ControlURL, config.Auth, config.Transport)
	if err != nil {
		return nil, err
	}
	return &Manager{hostID: config.HostID, server: server, store: config.Credentials, activator: config.Activator, controlToken: strings.TrimSpace(config.ControlToken), activating: make(map[string]struct{}), processClaims: make(map[processGenerationClaimKey]uint64)}, nil
}

func (m *Manager) Enroll(ctx context.Context, tunnelID, localKey string) (Projection, error) {
	if m == nil || ctx == nil || connectorprotocol.ValidateIdentifier(tunnelID) != nil || !safeID(localKey) {
		return Projection{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, active := m.activating[tunnelID]; active {
		return Projection{}, ErrEnrollmentRetryable
	}
	state, err := m.store.loadJournal()
	if err != nil {
		return Projection{}, err
	}
	recordValue, ok := state.Records[tunnelID]
	if ok {
		if recordValue.HostID != m.hostID {
			return Projection{}, ErrConflict
		}
		if recordValue.Projection != nil && recordValue.Projection.valid() {
			if hoststate.ValidateStableEndpointID(recordValue.StableEndpointID) != nil {
				return Projection{}, ErrConflict
			}
			return *recordValue.Projection, nil
		}
		// A later CLI retry resumes the one authoritative host/tunnel record.
		// The first local key remains durable so concurrent callers cannot create
		// a second connector identity.
	} else {
		credentialID, err := randomID("credential")
		if err != nil {
			return Projection{}, err
		}
		credential, err := m.store.CreateKey(ctx, credentialID)
		if err != nil {
			return Projection{}, err
		}
		issueKey, err := randomID("connector-issue")
		if err != nil {
			return Projection{}, err
		}
		exchangeKey, err := randomID("connector-exchange")
		if err != nil {
			return Projection{}, err
		}
		recordValue = record{TunnelID: tunnelID, HostID: m.hostID, LocalKey: localKey, IssueKey: issueKey, ExchangeKey: exchangeKey, Credential: credential, Phase: "prepared"}
		state.Records[tunnelID] = recordValue
		if err = m.store.saveJournal(state); err != nil {
			return Projection{}, err
		}
	}
	expiredEnrollmentRetries := 0
	for {
		if err := ctx.Err(); err != nil {
			return Projection{}, err
		}
		if recordValue.Phase == "prepared" {
			if cleanupErr := m.finishPendingTokenCleanup(&state, tunnelID, &recordValue); cleanupErr != nil {
				return Projection{}, cleanupErr
			}
			enrollment, issueErr := m.server.issue(ctx, tunnelID, m.hostID, recordValue.IssueKey)
			if issueErr != nil {
				// A transport failure can mean the write committed but the one-time
				// token was lost. Persist a new issue key for the next explicit retry;
				// the unusable enrollment expires server-side.
				if errors.Is(issueErr, ErrUnavailable) || errors.Is(issueErr, ErrConflict) {
					newIssueKey, keyErr := randomID("connector-issue")
					if keyErr != nil {
						return Projection{}, errors.Join(issueErr, keyErr)
					}
					recordValue.IssueKey = newIssueKey
					state.Records[tunnelID] = recordValue
					if saveErr := m.store.saveJournal(state); saveErr != nil {
						return Projection{}, errors.Join(issueErr, saveErr)
					}
				}
				return Projection{}, issueErr
			}
			tokenReference, putErr := m.store.PutEnrollmentToken(ctx, enrollment.ID, enrollment.Token)
			if putErr != nil {
				return Projection{}, putErr
			}
			recordValue.EnrollmentID = enrollment.ID
			recordValue.TokenReference = tokenReference
			recordValue.Phase = "issued"
			state.Records[tunnelID] = recordValue
			if err := m.store.saveJournal(state); err != nil {
				return Projection{}, err
			}
		}
		if recordValue.Phase == "issued" {
			token, loadErr := m.store.EnrollmentToken(ctx, recordValue.TokenReference)
			if loadErr != nil {
				return Projection{}, loadErr
			}
			activation, exchangeErr := m.server.exchange(ctx, tunnelID, m.hostID, recordValue.ExchangeKey, token, recordValue.Credential, m.store)
			clearString(&token)
			if exchangeErr != nil {
				if errors.Is(exchangeErr, ErrEnrollmentExpired) {
					if resetErr := m.resetExpiredEnrollment(&state, tunnelID, &recordValue); resetErr != nil {
						return Projection{}, resetErr
					}
					if expiredEnrollmentRetries >= maxExpiredEnrollmentRetries {
						return Projection{}, errors.Join(ErrEnrollmentRetryable, ErrEnrollmentExpired)
					}
					expiredEnrollmentRetries++
					continue
				}
				return Projection{}, exchangeErr
			}
			recordValue.ConnectorID = activation.ConnectorID
			recordValue.AccountID = activation.AccountID
			recordValue.OperationID = activation.Operation.ID
			recordValue.CredentialGeneration = activation.CredentialGeneration
			recordValue.ProcessGeneration = activation.ProcessGeneration
			recordValue.StableEndpointID = activation.StableEndpointID
			if hoststate.ValidateStableEndpointID(recordValue.StableEndpointID) != nil {
				return Projection{}, ErrUnavailable
			}
			recordValue.Phase = "exchanged"
			state.Records[tunnelID] = recordValue
			if err := m.store.saveJournal(state); err != nil {
				return Projection{}, err
			}
			if err := m.store.DeleteEnrollmentToken(context.Background(), recordValue.TokenReference); err != nil {
				return Projection{}, errors.Join(ErrEnrollmentRetryable, err)
			}
		}
		if recordValue.Phase == "exchanged" {
			if m.activator == nil {
				return Projection{}, ErrActivation
			}
			projection, activateErr := m.activator.Activate(ctx, ActivationRequest{AccountID: recordValue.AccountID, TunnelID: tunnelID, HostID: m.hostID, ConnectorID: recordValue.ConnectorID, OperationID: recordValue.OperationID, StableEndpointID: recordValue.StableEndpointID, CredentialReference: recordValue.Credential.Reference, CredentialKeyID: recordValue.Credential.KeyID, CredentialThumbprint: recordValue.Credential.Thumbprint, CredentialPublicKey: append([]byte(nil), recordValue.Credential.PublicKey...), CredentialGeneration: recordValue.CredentialGeneration, ProcessGeneration: recordValue.ProcessGeneration})
			if activateErr != nil {
				return Projection{}, errors.Join(ErrActivation, activateErr)
			}
			if !projection.valid() || projection.TunnelID != tunnelID || projection.HostID != m.hostID || projection.ConnectorID != recordValue.ConnectorID || projection.OperationID != recordValue.OperationID || projection.CredentialReference != recordValue.Credential.Reference {
				return Projection{}, ErrActivation
			}
			recordValue.Phase = "active"
			recordValue.Projection = &projection
			state.Records[tunnelID] = recordValue
			if err := m.store.saveJournal(state); err != nil {
				return Projection{}, err
			}
			return projection, nil
		}
		return Projection{}, ErrConflict
	}
}

// resetExpiredEnrollment retires only the one-time enrollment material. The
// connector credential remains untouched, so an expired exchange can never
// create a second local identity. The prepared journal record is written
// before deleting the old token; a pending reference makes cleanup retryable
// if deletion or the process itself fails between those operations.
func (m *Manager) resetExpiredEnrollment(state *journal, tunnelID string, current *record) error {
	if m == nil || m.store == nil || state == nil || current == nil || current.Phase != "issued" || current.TunnelID != tunnelID || current.TokenReference == "" {
		return errors.Join(ErrEnrollmentRetryable, ErrConflict)
	}
	issueKey, err := randomID("connector-issue")
	if err != nil {
		return errors.Join(ErrEnrollmentRetryable, err)
	}
	exchangeKey, err := randomID("connector-exchange")
	if err != nil {
		return errors.Join(ErrEnrollmentRetryable, err)
	}
	next := *current
	next.IssueKey = issueKey
	next.ExchangeKey = exchangeKey
	next.EnrollmentID = ""
	next.TokenReference = ""
	next.PendingTokenCleanup = append(append([]string(nil), current.PendingTokenCleanup...), current.TokenReference)
	next.AccountID = ""
	next.ConnectorID = ""
	next.OperationID = ""
	next.StableEndpointID = ""
	next.CredentialGeneration = 0
	next.ProcessGeneration = 0
	next.Phase = "prepared"
	next.Projection = nil
	state.Records[tunnelID] = next
	if err := m.store.saveJournal(*state); err != nil {
		state.Records[tunnelID] = *current
		return errors.Join(ErrEnrollmentRetryable, err)
	}
	*current = next
	if err := m.finishPendingTokenCleanup(state, tunnelID, current); err != nil {
		return err
	}
	return nil
}

func (m *Manager) finishPendingTokenCleanup(state *journal, tunnelID string, current *record) error {
	if m == nil || m.store == nil || state == nil || current == nil || current.TunnelID != tunnelID || current.Phase != "prepared" {
		return errors.Join(ErrEnrollmentRetryable, ErrConflict)
	}
	if len(current.PendingTokenCleanup) == 0 {
		return nil
	}
	for _, reference := range current.PendingTokenCleanup {
		if err := m.store.DeleteEnrollmentToken(context.Background(), reference); err != nil {
			return errors.Join(ErrEnrollmentRetryable, err)
		}
	}
	next := *current
	next.PendingTokenCleanup = nil
	state.Records[tunnelID] = next
	if err := m.store.saveJournal(*state); err != nil {
		return errors.Join(ErrEnrollmentRetryable, err)
	}
	*current = next
	return nil
}

// Resume reattaches every durable connector after stable hostd restarts. The
// enrollment exchange is never replayed. Before any activation, each durable
// connector gets one process-generation claim for this manager lifetime. The
// claim is persisted first and cached so activation retries reuse the same
// generation; a new manager claims the next generation.
func (m *Manager) Resume(ctx context.Context) error {
	if m == nil || ctx == nil || m.store == nil || m.activator == nil {
		return ErrActivation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.activating == nil {
		m.activating = make(map[string]struct{})
	}
	if m.processClaims == nil {
		m.processClaims = make(map[processGenerationClaimKey]uint64)
	}
	state, err := m.store.loadJournal()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	tunnelIDs := make([]string, 0, len(state.Records))
	for tunnelID, recordValue := range state.Records {
		if recordValue.Phase != "active" && recordValue.Phase != "exchanged" {
			continue
		}
		if hoststate.ValidateStableEndpointID(recordValue.StableEndpointID) != nil {
			m.mu.Unlock()
			return ErrConflict
		}
		if _, active := m.activating[tunnelID]; active {
			m.mu.Unlock()
			return ErrEnrollmentRetryable
		}
		tunnelIDs = append(tunnelIDs, tunnelID)
	}
	sort.Strings(tunnelIDs)
	claims := make([]processGenerationClaim, 0, len(tunnelIDs))
	claimKeys := make([]processGenerationClaimKey, 0, len(tunnelIDs))
	for _, tunnelID := range tunnelIDs {
		recordValue := state.Records[tunnelID]
		key := processGenerationClaimKeyFor(recordValue)
		if claimed, ok := m.processClaims[key]; ok {
			if recordValue.ProcessGeneration != claimed {
				m.mu.Unlock()
				return ErrConflict
			}
			continue
		}
		if recordValue.ProcessGeneration == ^uint64(0) {
			m.mu.Unlock()
			return errors.Join(ErrConflict, errProcessGenerationExhausted)
		}
		claims = append(claims, processGenerationClaim{tunnelID: tunnelID, expected: recordValue.ProcessGeneration, next: recordValue.ProcessGeneration + 1})
		claimKeys = append(claimKeys, key)
	}
	if len(claims) > 0 {
		claimedState, claimErr := m.store.claimProcessGenerations(claims)
		if claimErr != nil {
			m.mu.Unlock()
			return claimErr
		}
		state = claimedState
		for index, claim := range claims {
			m.processClaims[claimKeys[index]] = claim.next
		}
	}
	for _, tunnelID := range tunnelIDs {
		m.activating[tunnelID] = struct{}{}
	}
	m.mu.Unlock()

	// Activation can wait for an independent control/carrier readiness event.
	// Run each claimed connector independently so one unavailable tunnel cannot
	// starve every other durable connector on this host. Journal commits remain
	// serialized by commitResumeActivation because load+modify+save must never
	// allow concurrent workers to overwrite one another's projection.
	activationErrors := make([]error, len(tunnelIDs))
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(tunnelIDs))
	for index, tunnelID := range tunnelIDs {
		go func(index int, tunnelID string) {
			defer waitGroup.Done()
			defer m.clearActivation(tunnelID)

			recordValue := state.Records[tunnelID]
			request := recordValue.activationRequest()
			projection, activateErr := m.activator.Activate(ctx, request)
			if activateErr != nil {
				activationErrors[index] = errors.Join(ErrActivation, activateErr)
				return
			}
			if !projection.valid() || projection.TunnelID != tunnelID || projection.HostID != recordValue.HostID || projection.ConnectorID != recordValue.ConnectorID || projection.OperationID != recordValue.OperationID || projection.CredentialReference != recordValue.Credential.Reference || projection.CredentialGeneration != recordValue.CredentialGeneration {
				activationErrors[index] = ErrActivation
				return
			}
			activationErrors[index] = m.commitResumeActivation(tunnelID, request, projection)
		}(index, tunnelID)
	}
	waitGroup.Wait()
	for _, activationErr := range activationErrors {
		err = errors.Join(err, activationErr)
	}
	return err
}

func (m *Manager) clearActivation(tunnelID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.activating, tunnelID)
	m.mu.Unlock()
}

func (m *Manager) commitResumeActivation(tunnelID string, request ActivationRequest, projection Projection) error {
	if m == nil || m.store == nil {
		return ErrActivation
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	currentState, loadErr := m.store.loadJournal()
	if loadErr != nil {
		return loadErr
	}
	current, exists := currentState.Records[tunnelID]
	if !exists || (current.Phase != "active" && current.Phase != "exchanged") || !sameActivationRequest(current.activationRequest(), request) {
		return ErrConflict
	}
	current.Phase = "active"
	current.Projection = &projection
	currentState.Records[tunnelID] = current
	return m.store.saveJournal(currentState)
}

func sameActivationRequest(left, right ActivationRequest) bool {
	return left.AccountID == right.AccountID && left.TunnelID == right.TunnelID && left.HostID == right.HostID && left.ConnectorID == right.ConnectorID && left.OperationID == right.OperationID && left.StableEndpointID == right.StableEndpointID && left.CredentialReference == right.CredentialReference && left.CredentialKeyID == right.CredentialKeyID && left.CredentialThumbprint == right.CredentialThumbprint && left.CredentialGeneration == right.CredentialGeneration && left.ProcessGeneration == right.ProcessGeneration && bytes.Equal(left.CredentialPublicKey, right.CredentialPublicKey)
}

func randomID(prefix string) (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}
func clearString(value *string) {
	if value != nil {
		*value = ""
	}
}

func (m *Manager) String() string {
	return fmt.Sprintf("tunnel enrollment manager for host %s", m.hostID)
}
