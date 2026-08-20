package directpath

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
)

var (
	ErrFactoryInvalid         = errors.New("invalid signaling-backed direct path factory")
	ErrDescriptorInvalid      = errors.New("invalid direct path attempt descriptor")
	ErrDescriptorUnavailable  = errors.New("direct path attempt descriptor unavailable")
	ErrDescriptorUnauthorized = errors.New("direct path attempt descriptor authorization failed")
	ErrDescriptorRevoked      = errors.New("direct path attempt descriptor revoked")
)

type AttemptDescriptor struct {
	Document             api.PeerAttemptDescriptor
	IntentID             string
	AttemptGeneration    uint64
	NetworkGeneration    uint64
	Role                 signaling.Role
	InitiatorEndpointID  string
	ResponderEndpointID  string
	InitiatorCertificate []byte
	ResponderCertificate []byte
	RootPublicKey        ed25519.PublicKey
	SignalingURL         string
	SignalingCredential  string
	RelayRegion          string
	RelayQUICURL         string
	RelayWSSURL          string
	RelayCredential      string
	RelayPMTUCredential  string
	RelayPMTUURL         string
	RouteGeneration      uint64
	STUNURLs             []string
	LocalUfrag           string
	LocalPassword        string
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

type DescriptorSource interface {
	Acquire(context.Context, Generation) (AttemptDescriptor, error)
}

type DescriptorSourceFunc func(context.Context, Generation) (AttemptDescriptor, error)

func (f DescriptorSourceFunc) Acquire(ctx context.Context, generation Generation) (AttemptDescriptor, error) {
	return f(ctx, generation)
}

type SignalingDialer func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error)
type AssemblyOpener func(context.Context, Config) (*Assembly, error)
type Negotiator func(context.Context, NegotiationConfig) error

type MappingSource interface {
	AcquireMapping(context.Context, uint64, uint16) (portmapping.VerifiedMapping, netip.Addr, error)
}

type SignalingFactoryConfig struct {
	Descriptors DescriptorSource
	Assembly    Config
	// Lifetime owns an assembly after setup succeeds. Descriptor acquisition,
	// signaling, negotiation, and the caller-visible Create operation remain
	// bounded by the Create context.
	Lifetime      context.Context
	TLS           *tls.Config
	Now           func() time.Time
	Dial          SignalingDialer
	Open          AssemblyOpener
	Negotiate     Negotiator
	Mapping       MappingSource
	SocketMapping SocketMappingSource
}

type SignalingFactory struct{ config SignalingFactoryConfig }

func NewSignalingFactory(config SignalingFactoryConfig) (*SignalingFactory, error) {
	if nilInterface(config.Descriptors) || config.Mapping != nil && nilInterface(config.Mapping) || config.SocketMapping != nil && nilInterface(config.SocketMapping) || config.Mapping != nil && config.SocketMapping != nil || len(config.Assembly.PMTUKey) == 0 {
		return nil, ErrFactoryInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Dial == nil {
		config.Dial = func(ctx context.Context, value signaling.WebSocketConfig) (SignalingTransport, error) {
			return signaling.DialWebSocket(ctx, value)
		}
	}
	if config.Open == nil {
		config.Open = Open
	}
	if config.Negotiate == nil {
		config.Negotiate = func(ctx context.Context, value NegotiationConfig) error {
			_, err := Negotiate(ctx, value)
			return err
		}
	}
	return &SignalingFactory{config: config}, nil
}

func (f *SignalingFactory) Create(ctx context.Context, generation Generation) (*Assembly, error) {
	if f == nil || ctx == nil || !generation.valid() {
		return nil, ErrFactoryInvalid
	}
	started := time.Now()
	timing := map[string]int64{}
	mark := func(name string) { timing[name] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer direct factory timing", "attempt_generation", generation.Attempt, "network_generation", generation.Network, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	descriptor, err := f.config.Descriptors.Acquire(ctx, generation)
	if err != nil {
		if errors.Is(err, ErrDescriptorUnavailable) {
			return nil, RetryableFactoryError(err)
		}
		return nil, err
	}
	mark("descriptor_ready")
	if err := validateAttemptDescriptor(descriptor, generation, f.config.Now().UTC()); err != nil {
		return nil, err
	}
	webSocketConfig := signaling.WebSocketConfig{URL: descriptor.SignalingURL, Credential: descriptor.SignalingCredential, TLS: f.config.TLS}
	if err := signaling.ValidateWebSocketConfig(webSocketConfig); err != nil {
		return nil, errors.Join(ErrDescriptorInvalid, err)
	}
	assemblyConfig := f.config.Assembly
	assemblyConfig.ICE = iceagent.Config{STUNURLs: append([]string(nil), descriptor.STUNURLs...), LocalUfrag: descriptor.LocalUfrag, LocalPwd: descriptor.LocalPassword, ProbeOnly: descriptor.Document.Purpose == "direct_probe"}
	if assemblyConfig.Sockets.IPv6Viable == nil {
		assemblyConfig.Sockets.IPv6Viable = ipv6RouteViable(descriptor.STUNURLs)
	}
	assemblyConfig.AttemptGeneration, assemblyConfig.NetworkGeneration = generation.Attempt, generation.Network
	assemblyConfig.SocketMapping = f.config.SocketMapping
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type assemblyResult struct {
		value *Assembly
		err   error
	}
	type transportResult struct {
		value SignalingTransport
		err   error
	}
	assemblyDone := make(chan assemblyResult, 1)
	transportDone := make(chan transportResult, 1)
	assemblyCtx := runCtx
	if f.config.Lifetime != nil {
		assemblyCtx = f.config.Lifetime
	}
	go func() {
		value, openErr := f.config.Open(assemblyCtx, assemblyConfig)
		assemblyDone <- assemblyResult{value: value, err: openErr}
	}()
	go func() {
		value, dialErr := f.config.Dial(runCtx, webSocketConfig)
		transportDone <- transportResult{value: value, err: dialErr}
	}()
	assemblyResultValue := <-assemblyDone
	transportResultValue := <-transportDone
	if assemblyResultValue.err != nil {
		if !nilInterface(transportResultValue.value) {
			_ = transportResultValue.value.Close()
		}
		return nil, errors.Join(assemblyResultValue.err, transportResultValue.err)
	}
	assembly := assemblyResultValue.value
	mark("assembly_ready")
	if assembly == nil {
		if !nilInterface(transportResultValue.value) {
			_ = transportResultValue.value.Close()
		}
		return nil, ErrFactoryInvalid
	}
	if assembly.Generation() != generation {
		if !nilInterface(transportResultValue.value) {
			_ = transportResultValue.value.Close()
		}
		return nil, errors.Join(ErrFactoryInvalid, assembly.Close())
	}
	transport, err := transportResultValue.value, transportResultValue.err
	if err == nil {
		mark("signaling_ready")
	}
	if f.config.Mapping != nil {
		mapping, related, mappingErr := f.config.Mapping.AcquireMapping(ctx, generation.Network, assembly.Port())
		if mappingErr == nil {
			if configureErr := assembly.ConfigureVerifiedMapping(mapping, related); configureErr != nil {
				return nil, errors.Join(configureErr, err, closeTransport(transport), assembly.Close())
			}
		} else if !errors.Is(mappingErr, portmapping.ErrUntrusted) && !errors.Is(mappingErr, portmapping.ErrUnavailable) && !errors.Is(mappingErr, portmapping.ErrUnreachable) {
			return nil, errors.Join(mappingErr, err, closeTransport(transport), assembly.Close())
		}
	}
	if err != nil {
		closeErr := assembly.Close()
		if errors.Is(err, signaling.ErrTransportUnavailable) {
			return nil, RetryableFactoryError(errors.Join(err, closeErr))
		}
		return nil, errors.Join(err, closeErr)
	}
	if nilInterface(transport) {
		return nil, errors.Join(ErrFactoryInvalid, assembly.Close())
	}
	local := signaling.Binding{IntentID: descriptor.IntentID, AttemptGeneration: generation.Attempt, NetworkGeneration: generation.Network, Role: descriptor.Role}
	remote := local
	remote.Role = oppositeSignalingRole(local.Role)
	if err := f.config.Negotiate(ctx, NegotiationConfig{Assembly: assembly, Transport: transport, LocalBinding: local, RemoteBinding: remote, LocalUfrag: descriptor.LocalUfrag, LocalPassword: descriptor.LocalPassword}); err != nil {
		return nil, errors.Join(err, transport.Close(), assembly.Close())
	}
	mark("ice_nominated")
	if _, err := assembly.SelectedPMTUExchanger(); err != nil {
		return nil, errors.Join(ErrFactoryInvalid, err, transport.Close(), assembly.Close())
	}
	return assembly, nil
}

func closeTransport(transport SignalingTransport) error {
	if nilInterface(transport) {
		return nil
	}
	return transport.Close()
}

func ipv6RouteViable(stunURLs []string) func(context.Context) bool {
	return func(ctx context.Context) bool {
		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		return networkcheck.ProbeSTUNReachability(probeCtx, "ip6", stunURLs, net.DefaultResolver, 250*time.Millisecond)
	}
}

func validateAttemptDescriptor(value AttemptDescriptor, generation Generation, now time.Time) error {
	local := signaling.Binding{IntentID: value.IntentID, AttemptGeneration: value.AttemptGeneration, NetworkGeneration: value.NetworkGeneration, Role: value.Role}
	remote := local
	remote.Role = oppositeSignalingRole(local.Role)
	if value.AttemptGeneration != generation.Attempt {
		return fmt.Errorf("%w: attempt generation", ErrDescriptorInvalid)
	}
	if value.NetworkGeneration != generation.Network {
		return fmt.Errorf("%w: network generation", ErrDescriptorInvalid)
	}
	if value.SignalingURL == "" || value.SignalingCredential == "" {
		return fmt.Errorf("%w: signaling credentials", ErrDescriptorInvalid)
	}
	if value.LocalUfrag == "" || value.LocalPassword == "" {
		return fmt.Errorf("%w: ICE credentials", ErrDescriptorInvalid)
	}
	if value.IssuedAt.IsZero() || !value.ExpiresAt.After(now) || !value.ExpiresAt.After(value.IssuedAt) || value.IssuedAt.After(now.Add(30*time.Second)) || value.ExpiresAt.Sub(value.IssuedAt) > 5*time.Minute {
		return fmt.Errorf("%w: descriptor lifetime", ErrDescriptorInvalid)
	}
	if _, err := signaling.NewValidator(local); err != nil {
		return fmt.Errorf("%w: local signaling binding: %v", ErrDescriptorInvalid, err)
	}
	if _, err := signaling.NewValidator(remote); err != nil {
		return fmt.Errorf("%w: remote signaling binding: %v", ErrDescriptorInvalid, err)
	}
	if _, err := signaling.Encode(signaling.Message{Schema: signaling.Schema, IntentID: value.IntentID, AttemptGeneration: value.AttemptGeneration, NetworkGeneration: value.NetworkGeneration, Role: value.Role, Sequence: 1, Kind: signaling.KindCredentials, Ufrag: value.LocalUfrag, Password: value.LocalPassword}, local); err != nil {
		return fmt.Errorf("%w: signaling encoding: %v", ErrDescriptorInvalid, err)
	}
	if _, err := iceagent.ValidateSTUNURLs(value.STUNURLs); err != nil {
		return fmt.Errorf("%w: STUN URLs: %v", ErrDescriptorInvalid, err)
	}
	return nil
}

func oppositeSignalingRole(role signaling.Role) signaling.Role {
	if role == signaling.RoleControlling {
		return signaling.RoleControlled
	}
	if role == signaling.RoleControlled {
		return signaling.RoleControlling
	}
	return ""
}
