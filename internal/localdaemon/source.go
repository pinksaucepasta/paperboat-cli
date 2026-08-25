package localdaemon

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

type AuthenticatedMachineSource struct {
	ServerURL       string
	Auth            config.AuthSource
	SSHLocalReady   bool
	SSHLocalCode    string
	HTTPClient      *http.Client
	SourceMachineID string
	// AutoApprovePeerEnrollments is invoked after the authenticated machine
	// list is loaded. Production wires this to the account-root signer so a
	// one-shot enrollment never requires a separate trust-approval command.
	AutoApprovePeerEnrollments func(context.Context, *api.Client, []api.UserMachine) error
	// ReportPeerApprovalSignerUnavailable observes the one non-fatal approval
	// condition without making ordinary machine inventory unavailable.
	ReportPeerApprovalSignerUnavailable func(PeerApprovalSignerUnavailableError)
}

func (s *AuthenticatedMachineSource) SetManagedSSHReadiness(ready bool, code string) {
	if s == nil {
		return
	}
	s.SSHLocalReady = ready
	s.SSHLocalCode = code
}

// IssuePeerStream obtains a fresh, operation-scoped authorization just before
// transport admission. It deliberately never caches the returned credential.
func (s AuthenticatedMachineSource) IssuePeerStream(ctx context.Context, request localapi.PeerStreamRequest) (localapi.PeerStreamRequest, error) {
	if strings.TrimSpace(s.ServerURL) == "" || s.Auth == nil || request.Credential != "" {
		return request, ErrInvalidInventoryConfig
	}
	var expires time.Time
	var token string
	var quicEndpoint, wssEndpoint string
	if request.Consumer != "exec" && request.Consumer != "ssh" {
		return request, errors.New("daemon descriptor issuance is not available for consumer " + request.Consumer)
	}
	var descriptor api.ExecDescriptor
	for attempt := 0; attempt < 2; attempt++ {
		credential, err := s.Auth.Credential()
		if err != nil {
			return request, err
		}
		client := api.New(s.ServerURL, credential, s.HTTPClient)
		client.SetSourceMachineID(s.SourceMachineID)
		if request.Consumer == "exec" {
			descriptor, err = client.MachineExecDescriptor(ctx, request.MachineID, request.OperationID)
		} else {
			descriptor, err = client.MachineSSHDescriptor(ctx, request.MachineID, request.OperationID)
		}
		if err == nil {
			break
		}
		if attempt == 0 && errors.Is(err, api.ErrUnauthenticated) {
			if refresher, ok := s.Auth.(interface {
				Refresh() (config.Credential, error)
			}); ok {
				if _, refreshErr := refresher.Refresh(); refreshErr == nil {
					continue
				}
			}
		}
		return request, err
	}
	if descriptor.Environment == nil || descriptor.Environment.ID != request.EnvironmentID {
		return request, errors.New("operation descriptor environment mismatch")
	}
	token, expires = descriptor.Auth.Token, descriptor.Auth.ExpiresAt
	quicEndpoint, wssEndpoint = descriptor.Endpoints.QUIC, descriptor.Endpoints.WSS
	if token == "" || expires.IsZero() || !expires.After(time.Now()) {
		return request, errors.New("operation descriptor expired")
	}
	request.Credential, request.Deadline = token, expires.UTC()
	request.QUICEndpoint, request.WSSEndpoint = quicEndpoint, wssEndpoint
	if err := request.Validate(time.Now().UTC()); err != nil {
		return request, err
	}
	return request, nil
}

func (s AuthenticatedMachineSource) ListCompletionItems(ctx context.Context, machines []api.UserMachine) ([]localapi.CompletionItem, error) {
	const maximumCompletionItems = 1024
	if strings.TrimSpace(s.ServerURL) == "" || s.Auth == nil {
		return nil, ErrInvalidInventoryConfig
	}
	credential, err := s.Auth.Credential()
	if err != nil {
		return nil, err
	}
	client := api.New(s.ServerURL, credential, nil)
	items := make([]localapi.CompletionItem, 0, len(machines)*3)
	for _, machine := range machines {
		description := completionDescription(machine.DisplayName, machine.State)
		if machine.Alias != "" {
			items = append(items, localapi.CompletionItem{Kind: "machine", Value: machine.Alias, Description: description, EnvironmentID: machine.EnvironmentID})
		}
		items = append(items, localapi.CompletionItem{Kind: "machine", Value: machine.ID, Description: description, EnvironmentID: machine.EnvironmentID})
		if machine.Capabilities.FileReceive.Configured && machine.State != "revoked" && machine.State != "deleted" {
			if machine.Alias != "" {
				items = append(items, localapi.CompletionItem{Kind: "transfer_target", Value: machine.Alias, Description: description, EnvironmentID: machine.EnvironmentID})
			}
			items = append(items, localapi.CompletionItem{Kind: "transfer_target", Value: machine.ID, Description: description, EnvironmentID: machine.EnvironmentID})
		}
	}
	previews, err := client.ListPreviews(ctx)
	if err != nil {
		return nil, err
	}
	for _, preview := range previews {
		items = append(items, localapi.CompletionItem{Kind: "preview", Value: preview.ID, Description: completionDescription(preview.LogicalName, preview.State), EnvironmentID: preview.EnvironmentID})
	}
	const maximumConcurrentSessionLists = 8
	var sessionMu sync.Mutex
	var sessionWG sync.WaitGroup
	sem := make(chan struct{}, maximumConcurrentSessionLists)
	for _, machine := range machines {
		machine := machine
		sessionWG.Add(1)
		go func() {
			defer sessionWG.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			sessions, listErr := client.ListUserMachineTerminalSessions(ctx, machine.ID)
			if listErr != nil {
				return
			}
			values := make([]localapi.CompletionItem, 0, len(sessions)*2)
			for _, session := range sessions {
				description := completionDescription(session.Name, session.State)
				values = append(values, localapi.CompletionItem{Kind: "session", Value: session.ID, Description: description, EnvironmentID: machine.EnvironmentID})
				if session.Name != "" && session.Name != session.ID {
					values = append(values, localapi.CompletionItem{Kind: "session", Value: session.Name, Description: description, EnvironmentID: machine.EnvironmentID})
				}
			}
			sessionMu.Lock()
			items = append(items, values...)
			sessionMu.Unlock()
		}()
	}
	sessionWG.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].Kind != items[right].Kind {
			return items[left].Kind < items[right].Kind
		}
		if items[left].EnvironmentID != items[right].EnvironmentID {
			return items[left].EnvironmentID < items[right].EnvironmentID
		}
		return items[left].Value < items[right].Value
	})
	if len(items) > maximumCompletionItems {
		items = items[:maximumCompletionItems]
	}
	return items, nil
}

func completionDescription(values ...string) string {
	result := strings.ToValidUTF8(strings.TrimSpace(strings.Join(values, " - ")), "?")
	result = strings.Map(func(character rune) rune {
		if character == '\x00' || character == '\t' || character == '\r' || character == '\n' {
			return ' '
		}
		return character
	}, result)
	if len(result) > 512 {
		result = result[:512]
		for !utf8.ValidString(result) {
			result = result[:len(result)-1]
		}
	}
	if result == "" {
		return "Paperboat resource"
	}
	return result
}

func (s AuthenticatedMachineSource) ListUserMachines(ctx context.Context) ([]api.UserMachine, error) {
	if strings.TrimSpace(s.ServerURL) == "" || s.Auth == nil {
		return nil, ErrInvalidInventoryConfig
	}
	credential, err := s.Auth.Credential()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(credential.AccessToken) == "" {
		return nil, errors.New("Paperboat authentication is unavailable")
	}
	client := api.New(s.ServerURL, credential, nil)
	machines, err := client.ListUserMachines(ctx)
	if err != nil {
		return nil, err
	}
	if s.AutoApprovePeerEnrollments != nil {
		if err := s.AutoApprovePeerEnrollments(ctx, client, machines); err != nil {
			var unavailable *PeerApprovalSignerUnavailableError
			if !errors.As(err, &unavailable) {
				return nil, err
			}
			if s.ReportPeerApprovalSignerUnavailable != nil {
				s.ReportPeerApprovalSignerUnavailable(*unavailable)
			}
		}
	}
	for index := range machines {
		if _, err := managedssh.AliasHost(machines[index].Alias, managedssh.AliasSuffix); err != nil {
			return nil, errors.New("paperboat-server returned an invalid machine alias")
		}
		machines[index].SSHLocalReady = s.SSHLocalReady
		machines[index].SSHLocalCode = s.SSHLocalCode
	}
	return reconcileSSHAuthorities(ctx, client, machines)
}

// RateLimitedPeerApprovalReporter bounds repeated diagnostics from inventory
// refreshes. The returned closure is concurrency-safe and reports immediately,
// then at most once per interval.
func RateLimitedPeerApprovalReporter(clock func() time.Time, interval time.Duration, report func(PeerApprovalSignerUnavailableError)) func(PeerApprovalSignerUnavailableError) {
	if clock == nil {
		clock = time.Now
	}
	if interval <= 0 {
		interval = time.Minute
	}
	var mu sync.Mutex
	var last time.Time
	return func(issue PeerApprovalSignerUnavailableError) {
		if report == nil {
			return
		}
		now := clock()
		mu.Lock()
		if !last.IsZero() && now.Sub(last) < interval {
			mu.Unlock()
			return
		}
		last = now
		mu.Unlock()
		report(issue)
	}
}

func reconcileSSHAuthorities(ctx context.Context, client *api.Client, machines []api.UserMachine) ([]api.UserMachine, error) {
	const maximumConcurrentLookups = 8
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, maximumConcurrentLookups)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for index := range machines {
		machine := &machines[index]
		if !machine.Online || machine.InstallationGeneration <= 0 || machine.State == "revoked" || machine.State == "deleted" {
			continue
		}
		wg.Add(1)
		go func(machine *api.UserMachine) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-lookupCtx.Done():
				return
			}
			generation := uint64(machine.InstallationGeneration)
			target, targetErr := client.ManagedSSHTarget(lookupCtx, machine.ID, generation)
			if api.IsNotFound(targetErr) {
				return
			}
			if targetErr != nil {
				recordSSHLookupError(&errMu, &firstErr, cancel, targetErr)
				return
			}
			machine.SSHUser, machine.SSHPort = target.OSUser, target.Port
			keys, keysErr := client.ManagedSSHHostKeys(lookupCtx, machine.ID, generation)
			if api.IsNotFound(keysErr) {
				machine.SSHAuthority.TargetGeneration = target.MachineGeneration
				return
			}
			if keysErr != nil {
				recordSSHLookupError(&errMu, &firstErr, cancel, keysErr)
				return
			}
			machine.SSHAuthority = api.SSHAuthority{TargetGeneration: target.MachineGeneration, HostKeyGeneration: keys.MachineGeneration}
		}(machine)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return machines, nil
}

func recordSSHLookupError(mu *sync.Mutex, destination *error, cancel context.CancelFunc, err error) {
	mu.Lock()
	defer mu.Unlock()
	if *destination == nil {
		*destination = err
		cancel()
	}
}
