package directpath

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pion/ice/v4"
)

var (
	ErrNegotiationInvalid = errors.New("invalid direct path negotiation")
	ErrPeerClosed         = errors.New("peer closed direct path signaling")
	ErrReachability       = errors.New("direct path is unreachable")
)

// SignalingTransport is an authenticated, ordered, message-preserving peer
// signaling attachment. Both methods must honor context cancellation. Close
// must interrupt blocked Send and Receive calls and be idempotent.
type SignalingTransport interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

type NegotiationConfig struct {
	Assembly      *Assembly
	Transport     SignalingTransport
	LocalBinding  signaling.Binding
	RemoteBinding signaling.Binding
	LocalUfrag    string
	LocalPassword string
}

type remoteCredentials struct {
	ufrag    string
	password string
}

type remoteAttemptResult struct {
	credentials remoteCredentials
	err         error
}

// Negotiate trickles candidates while Pion runs its checklist. Signaling stays
// open until both peers report a selected pair.
func Negotiate(ctx context.Context, config NegotiationConfig) (*ice.Conn, error) {
	if ctx == nil || config.Assembly == nil || nilInterface(config.Transport) || !oppositeRoles(config.LocalBinding.Role, config.RemoteBinding.Role) || !sameAttempt(config.LocalBinding, config.RemoteBinding) || config.Assembly.Generation() != (Generation{Attempt: config.LocalBinding.AttemptGeneration, Network: config.LocalBinding.NetworkGeneration}) {
		return nil, errors.Join(ErrNegotiationInvalid, closeNegotiation(config))
	}
	remoteValidator, err := signaling.NewValidator(config.RemoteBinding)
	if err != nil {
		return nil, errors.Join(ErrNegotiationInvalid, closeNegotiation(config))
	}
	credential := signaling.Message{
		Schema: signaling.Schema, IntentID: config.LocalBinding.IntentID,
		AttemptGeneration: config.LocalBinding.AttemptGeneration, NetworkGeneration: config.LocalBinding.NetworkGeneration,
		Role: config.LocalBinding.Role, Sequence: 1, Kind: signaling.KindCredentials,
		Ufrag: config.LocalUfrag, Password: config.LocalPassword,
	}
	if _, err := signaling.Encode(credential, config.LocalBinding); err != nil {
		return nil, errors.Join(ErrNegotiationInvalid, closeNegotiation(config))
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var closeOnce sync.Once
	var transportCloseErr error
	closeTransport := func() error {
		closeOnce.Do(func() { transportCloseErr = config.Transport.Close() })
		return transportCloseErr
	}
	type localResult struct{ err error }
	sender := &attemptSender{config: config, sequence: credential.Sequence}
	localDone := make(chan localResult, 1)
	remoteDone := make(chan remoteAttemptResult, 1)
	credentialsReady := make(chan remoteCredentials, 1)
	go func() { localDone <- localResult{err: sendLocalAttempt(runCtx, config, sender, credential)} }()
	go func() {
		credentials, receiveErr := receiveRemoteAttempt(runCtx, config, remoteValidator, credentialsReady)
		remoteDone <- remoteAttemptResult{credentials: credentials, err: receiveErr}
	}()
	connectDone := make(chan struct {
		connection *ice.Conn
		err        error
	}, 1)
	connectStarted := false
	connectFinished := false
	var connectErr error
	var connection *ice.Conn
	var local localResult
	var remote remoteAttemptResult
	localFinished := false
	remoteFinished := false
	for received := 0; ; {
		select {
		case local = <-localDone:
			received++
			localFinished = true
			if local.err != nil {
				cancel()
				_ = closeTransport()
			}
		case remote = <-remoteDone:
			received++
			remoteFinished = true
			if remote.err != nil {
				cancel()
				_ = closeTransport()
			}
		case credentials := <-credentialsReady:
			if connectStarted {
				continue
			}
			connectStarted = true
			go func(credentials remoteCredentials) {
				connection, connectErr := config.Assembly.Connect(ctx, iceRole(config.LocalBinding.Role), credentials.ufrag, credentials.password)
				connectDone <- struct {
					connection *ice.Conn
					err        error
				}{connection: connection, err: connectErr}
			}(credentials)
		case result := <-connectDone:
			connectFinished = true
			connectErr = result.err
			if result.err == nil {
				connection = result.connection
				if !localFinished {
					select {
					case local = <-localDone:
						localFinished = true
					case <-ctx.Done():
						cancel()
						return nil, errors.Join(ctx.Err(), closeTransport(), result.connection.Close(), config.Assembly.Close())
					}
				}
				if local.err != nil {
					cancel()
					return nil, errors.Join(local.err, closeTransport(), result.connection.Close(), config.Assembly.Close())
				}
				if err := sender.send(runCtx, signaling.Message{Kind: signaling.KindReady}); err != nil {
					cancel()
					return nil, errors.Join(fmt.Errorf("send direct path readiness: %w", err), closeTransport(), result.connection.Close(), config.Assembly.Close())
				}
				if !remoteFinished {
					select {
					case remote = <-remoteDone:
						remoteFinished = true
					case <-ctx.Done():
						cancel()
						return nil, errors.Join(ctx.Err(), closeTransport(), result.connection.Close(), config.Assembly.Close())
					}
				}
				if remote.err != nil {
					cancel()
					return nil, errors.Join(remote.err, closeTransport(), result.connection.Close(), config.Assembly.Close())
				}
				cancel()
				if err := closeTransport(); err != nil {
					return nil, errors.Join(err, result.connection.Close(), config.Assembly.Close())
				}
				return connection, nil
			}
		}
		if local.err != nil || remote.err != nil {
			return nil, errors.Join(local.err, remote.err, connectErr, closeTransport(), config.Assembly.Close())
		}
		if received == 2 && (!connectStarted || connectFinished) {
			if !connectStarted {
				connectErr = errors.New("remote ICE credentials were not received")
			}
			return nil, errors.Join(ErrReachability, connectErr, closeTransport(), config.Assembly.Close())
		}
	}
}

type attemptSender struct {
	mu       sync.Mutex
	config   NegotiationConfig
	sequence uint64
}

func (s *attemptSender) send(ctx context.Context, message signaling.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if message.Kind != signaling.KindCredentials {
		s.sequence++
	}
	message.Schema = signaling.Schema
	message.IntentID = s.config.LocalBinding.IntentID
	message.AttemptGeneration = s.config.LocalBinding.AttemptGeneration
	message.NetworkGeneration = s.config.LocalBinding.NetworkGeneration
	message.Role = s.config.LocalBinding.Role
	message.Sequence = s.sequence
	encoded, err := signaling.Encode(message, s.config.LocalBinding)
	if err != nil {
		return err
	}
	return s.config.Transport.Send(ctx, encoded)
}

func sendLocalAttempt(ctx context.Context, config NegotiationConfig, sender *attemptSender, credential signaling.Message) error {
	if err := sender.send(ctx, credential); err != nil {
		return fmt.Errorf("send direct path credentials: %w", err)
	}
	if err := config.Assembly.Gather(ctx, func(candidate string) error {
		return sender.send(ctx, signaling.Message{Kind: signaling.KindCandidate, Candidate: candidate})
	}); err != nil {
		return fmt.Errorf("gather direct path candidates: %w", err)
	}
	if err := sender.send(ctx, signaling.Message{Kind: signaling.KindEnd}); err != nil {
		return fmt.Errorf("send direct path candidate completion: %w", err)
	}
	return nil
}

func receiveRemoteAttempt(ctx context.Context, config NegotiationConfig, validator *signaling.Validator, credentialsReady chan<- remoteCredentials) (remoteCredentials, error) {
	var credentials remoteCredentials
	candidates := 0
	for {
		raw, err := config.Transport.Receive(ctx)
		if err != nil {
			return remoteCredentials{}, fmt.Errorf("receive direct path signaling after credentials=%t candidates=%d: %w", credentials.ufrag != "", candidates, err)
		}
		message, applied, err := validator.Accept(raw)
		if err != nil {
			return remoteCredentials{}, err
		}
		if !applied {
			continue
		}
		switch message.Kind {
		case signaling.KindCredentials:
			credentials = remoteCredentials{ufrag: message.Ufrag, password: message.Password}
			select {
			case credentialsReady <- credentials:
			default:
			}
		case signaling.KindCandidate:
			if err := config.Assembly.AddRemoteCandidate(message.Candidate); err != nil {
				return remoteCredentials{}, err
			}
			candidates++
		case signaling.KindEnd:
			continue
		case signaling.KindReady:
			return credentials, nil
		case signaling.KindClose:
			return remoteCredentials{}, ErrPeerClosed
		}
	}
}

func sameAttempt(local, remote signaling.Binding) bool {
	return local.IntentID == remote.IntentID && local.AttemptGeneration == remote.AttemptGeneration && local.NetworkGeneration == remote.NetworkGeneration
}

func oppositeRoles(local, remote signaling.Role) bool {
	return local == signaling.RoleControlling && remote == signaling.RoleControlled || local == signaling.RoleControlled && remote == signaling.RoleControlling
}

func iceRole(role signaling.Role) iceagent.Role {
	if role == signaling.RoleControlling {
		return iceagent.RoleControlling
	}
	return iceagent.RoleControlled
}

func closeNegotiation(config NegotiationConfig) error {
	var transportErr, assemblyErr error
	if !nilInterface(config.Transport) {
		transportErr = config.Transport.Close()
	}
	if config.Assembly != nil {
		assemblyErr = config.Assembly.Close()
	}
	return errors.Join(transportErr, assemblyErr)
}
