package tunnelenrollment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
}

func NewManager(config ManagerConfig) (*Manager, error) {
	if connectorprotocol.ValidateIdentifier(config.HostID) != nil || config.Credentials == nil || strings.TrimSpace(config.ControlToken) == "" {
		return nil, ErrInvalid
	}
	server, err := newServerClient(config.ControlURL, config.Auth, config.Transport)
	if err != nil {
		return nil, err
	}
	return &Manager{hostID: config.HostID, server: server, store: config.Credentials, activator: config.Activator, controlToken: strings.TrimSpace(config.ControlToken)}, nil
}

func (m *Manager) Enroll(ctx context.Context, tunnelID, localKey string) (Projection, error) {
	if m == nil || ctx == nil || connectorprotocol.ValidateIdentifier(tunnelID) != nil || !safeID(localKey) {
		return Projection{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if err := ctx.Err(); err != nil {
		return Projection{}, err
	}
	if recordValue.Phase == "prepared" {
		enrollment, issueErr := m.server.issue(ctx, tunnelID, m.hostID, recordValue.IssueKey)
		if issueErr != nil {
			// A transport failure can mean the write committed but the one-time
			// token was lost. Persist a new issue key for the next explicit retry;
			// the unusable enrollment expires server-side.
			if errors.Is(issueErr, ErrUnavailable) || errors.Is(issueErr, ErrConflict) {
				recordValue.IssueKey, _ = randomID("connector-issue")
				state.Records[tunnelID] = recordValue
				_ = m.store.saveJournal(state)
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
		if err = m.store.saveJournal(state); err != nil {
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
		if err = m.store.saveJournal(state); err != nil {
			return Projection{}, err
		}
		_ = m.store.DeleteEnrollmentToken(context.Background(), recordValue.TokenReference)
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
		if err = m.store.saveJournal(state); err != nil {
			return Projection{}, err
		}
		return projection, nil
	}
	return Projection{}, ErrConflict
}

// Resume reattaches every durable connector after stable hostd restarts. The
// enrollment exchange is never replayed; only the reference-backed activation
// is rerun with the exact persisted account, connector, credential, and
// process generations.
func (m *Manager) Resume(ctx context.Context) error {
	if m == nil || ctx == nil || m.activator == nil {
		return ErrActivation
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.store.loadJournal()
	if err != nil {
		return err
	}
	for tunnelID, recordValue := range state.Records {
		if recordValue.Phase != "active" && recordValue.Phase != "exchanged" {
			continue
		}
		if hoststate.ValidateStableEndpointID(recordValue.StableEndpointID) != nil {
			return ErrConflict
		}
		request := recordValue.activationRequest()
		projection, activateErr := m.activator.Activate(ctx, request)
		if activateErr != nil {
			return errors.Join(ErrActivation, activateErr)
		}
		if !projection.valid() || projection.TunnelID != tunnelID || projection.HostID != recordValue.HostID || projection.ConnectorID != recordValue.ConnectorID || projection.OperationID != recordValue.OperationID || projection.CredentialReference != recordValue.Credential.Reference || projection.CredentialGeneration != recordValue.CredentialGeneration {
			return ErrActivation
		}
		recordValue.Phase = "active"
		recordValue.Projection = &projection
		state.Records[tunnelID] = recordValue
		if err := m.store.saveJournal(state); err != nil {
			return err
		}
	}
	return nil
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
