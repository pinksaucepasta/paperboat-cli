package directpath

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
)

type mappingSourceFunc func(context.Context, uint64, uint16) (portmapping.VerifiedMapping, netip.Addr, error)

func (f mappingSourceFunc) AcquireMapping(ctx context.Context, generation uint64, port uint16) (portmapping.VerifiedMapping, netip.Addr, error) {
	return f(ctx, generation, port)
}

func TestSignalingFactoriesAcquireFreshDescriptorsAndNominateRealICE(t *testing.T) {
	now := time.Now().UTC()
	generation := Generation{Attempt: 3, Network: 7}
	mappingAddress, mappingAvailable := privateTestIPv4()
	var mappingMu sync.Mutex
	var mappingManagers []*portmapping.Manager
	mappingCalls := 0
	leftTransport, rightTransport := newTransportPair()
	descriptor := func(role signaling.Role, ufrag, password string) AttemptDescriptor {
		return AttemptDescriptor{IntentID: "intent_factory", AttemptGeneration: generation.Attempt, NetworkGeneration: generation.Network, Role: role, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: ufrag, LocalPassword: password, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	}
	newFactory := func(value AttemptDescriptor, transport SignalingTransport) *SignalingFactory {
		config := SignalingFactoryConfig{
			Descriptors: DescriptorSourceFunc(func(_ context.Context, got Generation) (AttemptDescriptor, error) {
				if got != generation {
					t.Fatalf("generation = %+v", got)
				}
				return value, nil
			}),
			Assembly: assemblyConfig(value.LocalUfrag, value.LocalPassword, []byte("factory-pmtu-key-01234567890123456")),
			Now:      func() time.Time { return now },
			Dial: func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) {
				return transport, nil
			},
		}
		if mappingAvailable {
			config.Mapping = mappingSourceFunc(func(ctx context.Context, network uint64, port uint16) (portmapping.VerifiedMapping, netip.Addr, error) {
				backend := &mappedBackend{external: netip.AddrPortFrom(mappingAddress, port)}
				manager, err := portmapping.New(portmapping.Config{
					Backend: backend, Verifier: reachableMapping{}, Trust: privateLANTrust,
					ProbeTimeout: 100 * time.Millisecond, CreateTimeout: time.Second,
				})
				if err != nil {
					return portmapping.VerifiedMapping{}, netip.Addr{}, err
				}
				if _, err := manager.Acquire(ctx, network, port); err != nil {
					_ = manager.Close()
					return portmapping.VerifiedMapping{}, netip.Addr{}, err
				}
				verified, ok := manager.Verified(network)
				if !ok {
					_ = manager.Close()
					return portmapping.VerifiedMapping{}, netip.Addr{}, portmapping.ErrStale
				}
				mappingMu.Lock()
				mappingManagers = append(mappingManagers, manager)
				mappingCalls++
				mappingMu.Unlock()
				return verified, mappingAddress, nil
			})
		}
		factory, err := NewSignalingFactory(config)
		if err != nil {
			t.Fatal(err)
		}
		return factory
	}
	left := newFactory(descriptor(signaling.RoleControlling, "factoryLeft", "leftPassword12345678901234567890"), leftTransport)
	right := newFactory(descriptor(signaling.RoleControlled, "factoryRight", "rightPassword1234567890123456789"), rightTransport)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		assembly *Assembly
		err      error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for _, factory := range []*SignalingFactory{left, right} {
		wait.Add(1)
		go func(factory *SignalingFactory) {
			defer wait.Done()
			assembly, err := factory.Create(ctx, generation)
			results <- result{assembly: assembly, err: err}
		}(factory)
	}
	wait.Wait()
	close(results)
	for value := range results {
		if value.err != nil || value.assembly == nil || value.assembly.Generation() != generation {
			t.Fatalf("assembly=%v error=%v", value.assembly, value.err)
		}
		if _, err := value.assembly.SelectedPMTUExchanger(); err != nil {
			t.Fatalf("assembly was not nominated: %v", err)
		}
		if err := value.assembly.Close(); err != nil {
			t.Fatal(err)
		}
	}
	mappingMu.Lock()
	managers := append([]*portmapping.Manager(nil), mappingManagers...)
	calls := mappingCalls
	mappingMu.Unlock()
	for _, manager := range managers {
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if mappingAvailable && calls != 2 {
		t.Fatalf("mapping calls=%d", calls)
	}
}

func TestSignalingFactoryRejectsStaleDescriptorBeforeOpeningSockets(t *testing.T) {
	now := time.Now().UTC()
	base := AttemptDescriptor{IntentID: "intent", AttemptGeneration: 2, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	for name, descriptor := range map[string]AttemptDescriptor{
		"stale generation": func() AttemptDescriptor { value := base; value.AttemptGeneration = 1; return value }(),
		"expires before issue": func() AttemptDescriptor {
			value := base
			value.IssuedAt = now.Add(20 * time.Second)
			value.ExpiresAt = now.Add(10 * time.Second)
			return value
		}(),
		"unsafe WSS URL": func() AttemptDescriptor {
			value := base
			value.SignalingURL = "ws://signal.example.test/v1/peer-signaling"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			opened := false
			factory, err := NewSignalingFactory(SignalingFactoryConfig{
				Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, nil }),
				Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
				Now:         func() time.Time { return now },
				Open: func(context.Context, Config) (*Assembly, error) {
					opened = true
					return nil, errors.New("unexpected open")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := factory.Create(context.Background(), Generation{Attempt: 2, Network: 1}); !errors.Is(err, ErrDescriptorInvalid) {
				t.Fatalf("error=%v", err)
			}
			if opened {
				t.Fatal("invalid descriptor opened sockets")
			}
		})
	}
}

func TestSignalingFactoryPreservesDaemonIPv6Viability(t *testing.T) {
	now := time.Now().UTC()
	generation := Generation{Attempt: 1, Network: 1}
	called := false
	want := errors.New("stop after socket policy")
	sockets := assemblyConfig("localUfrag", "localPassword12345678901234567890", []byte("factory-pmtu-key-01234567890123456")).Sockets
	sockets.IPv6Viable = func(context.Context) bool { called = true; return false }
	factory, err := NewSignalingFactory(SignalingFactoryConfig{
		Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) {
			return AttemptDescriptor{IntentID: "intent_ipv6_cache", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", STUNURLs: []string{"stun:stun.example.test:3478"}, LocalUfrag: "localUfrag", LocalPassword: "localPassword12345678901234567890", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
		}),
		Assembly: Config{Sockets: sockets, PMTUKey: []byte("factory-pmtu-key-01234567890123456")},
		Now:      func() time.Time { return now },
		Open: func(_ context.Context, config Config) (*Assembly, error) {
			config.Sockets.IPv6Viable(context.Background())
			return nil, want
		},
		Dial: func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) { return nil, want },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Create(context.Background(), generation); !errors.Is(err, want) || !called {
		t.Fatalf("error=%v cached callback called=%v", err, called)
	}
}

func TestSignalingFactoryDisablesICEKeepaliveOnlyForDirectProbe(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		purpose string
		probe   bool
	}{{purpose: "interactive"}, {purpose: "direct_probe", probe: true}} {
		t.Run(test.purpose, func(t *testing.T) {
			descriptor := AttemptDescriptor{Document: api.PeerAttemptDescriptor{Purpose: test.purpose, Consumer: "terminal"}, IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
			wantOpen := errors.New("captured assembly config")
			factory, err := NewSignalingFactory(SignalingFactoryConfig{
				Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, nil }),
				Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
				Now:         func() time.Time { return now },
				Open: func(_ context.Context, config Config) (*Assembly, error) {
					if config.ICE.ProbeOnly != test.probe {
						t.Fatalf("ProbeOnly=%t", config.ICE.ProbeOnly)
					}
					return nil, wantOpen
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := factory.Create(context.Background(), Generation{Attempt: 1, Network: 1}); !errors.Is(err, wantOpen) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestSignalingFactoryRetriesOnlyAvailabilityFailures(t *testing.T) {
	now := time.Now().UTC()
	descriptor := AttemptDescriptor{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	for name, test := range map[string]struct {
		sourceErr error
		dialErr   error
		retry     bool
	}{
		"descriptor unavailable":   {sourceErr: ErrDescriptorUnavailable, retry: true},
		"descriptor unauthorized":  {sourceErr: ErrDescriptorUnauthorized},
		"descriptor revoked":       {sourceErr: ErrDescriptorRevoked},
		"signaling unavailable":    {dialErr: signaling.ErrTransportUnavailable, retry: true},
		"signaling authentication": {dialErr: signaling.ErrTransportAuthentication},
		"signaling certificate":    {dialErr: signaling.ErrTransportCertificate},
		"signaling protocol":       {dialErr: signaling.ErrTransportProtocol},
	} {
		t.Run(name, func(t *testing.T) {
			factory, err := NewSignalingFactory(SignalingFactoryConfig{
				Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, test.sourceErr }),
				Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
				Now:         func() time.Time { return now },
				Dial: func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) {
					return nil, test.dialErr
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = factory.Create(context.Background(), Generation{Attempt: 1, Network: 1})
			var retryable *retryableFactoryError
			if errors.As(err, &retryable) != test.retry {
				t.Fatalf("error=%v retryable=%t", err, errors.As(err, &retryable))
			}
		})
	}
}

func TestSignalingFactoryMappingFallbackAndTerminalOwnership(t *testing.T) {
	now := time.Now().UTC()
	descriptor := AttemptDescriptor{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 2, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	wantDial := errors.New("dial reached")
	for name, mappingErr := range map[string]error{
		"untrusted":   portmapping.ErrUntrusted,
		"unavailable": portmapping.ErrUnavailable,
		"unreachable": portmapping.ErrUnreachable,
		"stale":       portmapping.ErrStale,
	} {
		t.Run(name, func(t *testing.T) {
			dialed := false
			factory, err := NewSignalingFactory(SignalingFactoryConfig{
				Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, nil }),
				Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
				Now:         func() time.Time { return now },
				Mapping: mappingSourceFunc(func(_ context.Context, generation uint64, port uint16) (portmapping.VerifiedMapping, netip.Addr, error) {
					if generation != 2 || port == 0 {
						t.Fatalf("generation=%d port=%d", generation, port)
					}
					return portmapping.VerifiedMapping{}, netip.Addr{}, mappingErr
				}),
				Dial: func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) {
					dialed = true
					return nil, wantDial
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, createErr := factory.Create(context.Background(), Generation{Attempt: 1, Network: 2})
			fallback := !errors.Is(mappingErr, portmapping.ErrStale)
			if !dialed {
				t.Fatalf("signaling did not start concurrently: error=%v", createErr)
			}
			if fallback && !errors.Is(createErr, wantDial) || !fallback && !errors.Is(createErr, mappingErr) {
				t.Fatalf("error=%v", createErr)
			}
		})
	}
}

func TestNewSignalingFactoryRejectsTypedNilDescriptorSource(t *testing.T) {
	var source DescriptorSourceFunc
	if _, err := NewSignalingFactory(SignalingFactoryConfig{Descriptors: source, Assembly: Config{PMTUKey: []byte("key")}}); !errors.Is(err, ErrFactoryInvalid) {
		t.Fatalf("error=%v", err)
	}
}

func TestSignalingFactoryEstablishedAssemblyOutlivesCreateContext(t *testing.T) {
	createCtx, cancelCreate := context.WithCancel(context.Background())
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	opened := make(chan context.Context, 1)
	dialed := make(chan context.Context, 1)
	want := errors.New("stop after context capture")
	now := time.Now().UTC()
	factory, err := NewSignalingFactory(SignalingFactoryConfig{
		Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) {
			return AttemptDescriptor{IntentID: "intent_lifetime", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
		}),
		Assembly: Config{PMTUKey: []byte("key")},
		Lifetime: lifetime,
		Open: func(ctx context.Context, _ Config) (*Assembly, error) {
			opened <- ctx
			return nil, want
		},
		Dial: func(ctx context.Context, _ signaling.WebSocketConfig) (SignalingTransport, error) {
			dialed <- ctx
			return nil, want
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Create(createCtx, Generation{Attempt: 1, Network: 1}); !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
	assemblyContext := <-opened
	signalingContext := <-dialed
	cancelCreate()
	select {
	case <-assemblyContext.Done():
		t.Fatal("established assembly canceled with setup context")
	default:
	}
	select {
	case <-signalingContext.Done():
	case <-time.After(time.Second):
		t.Fatal("signaling did not follow setup context")
	}
	cancelLifetime()
	select {
	case <-assemblyContext.Done():
	case <-time.After(time.Second):
		t.Fatal("established assembly did not follow lifetime context")
	}
}

func TestSignalingFactoryRejectsNilOwnedResults(t *testing.T) {
	now := time.Now().UTC()
	descriptor := AttemptDescriptor{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	base := SignalingFactoryConfig{
		Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, nil }),
		Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
		Now:         func() time.Time { return now },
	}
	t.Run("assembly", func(t *testing.T) {
		config := base
		config.Open = func(context.Context, Config) (*Assembly, error) { return nil, nil }
		transport := &recordingTransport{}
		config.Dial = func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) {
			return transport, nil
		}
		factory, err := NewSignalingFactory(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := factory.Create(context.Background(), Generation{Attempt: 1, Network: 1}); !errors.Is(err, ErrFactoryInvalid) {
			t.Fatalf("nil assembly error=%v", err)
		}
		if !transport.closed {
			t.Fatal("concurrently opened transport remained open after nil assembly")
		}
	})
	t.Run("transport", func(t *testing.T) {
		config := base
		assembly := &Assembly{attempt: 1, network: 1, done: make(chan struct{})}
		config.Open = func(context.Context, Config) (*Assembly, error) { return assembly, nil }
		var transport *recordingTransport
		config.Dial = func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) { return transport, nil }
		factory, err := NewSignalingFactory(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := factory.Create(context.Background(), Generation{Attempt: 1, Network: 1}); !errors.Is(err, ErrFactoryInvalid) {
			t.Fatalf("typed-nil transport error=%v", err)
		}
		if !assemblyClosed(assembly) {
			t.Fatal("assembly remained open after typed-nil transport")
		}
	})
}

func TestSignalingFactoryRequiresExactGenerationAndNominationPostcondition(t *testing.T) {
	now := time.Now().UTC()
	descriptor := AttemptDescriptor{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling, SignalingURL: "wss://signal.example.test/v1/peer-signaling", SignalingCredential: "header.payload.signature", LocalUfrag: "factoryLocal", LocalPassword: "factoryPassword123456789012345", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	base := SignalingFactoryConfig{
		Descriptors: DescriptorSourceFunc(func(context.Context, Generation) (AttemptDescriptor, error) { return descriptor, nil }),
		Assembly:    assemblyConfig("unusedLocal", "unused-password-123456789012345", []byte("factory-pmtu-key-01234567890123456")),
		Now:         func() time.Time { return now },
	}
	t.Run("generation", func(t *testing.T) {
		config := base
		assembly := &Assembly{attempt: 2, network: 1, done: make(chan struct{})}
		transport := &recordingTransport{}
		config.Open = func(context.Context, Config) (*Assembly, error) { return assembly, nil }
		config.Dial = func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) {
			return transport, nil
		}
		factory, _ := NewSignalingFactory(config)
		if _, err := factory.Create(context.Background(), Generation{Attempt: 1, Network: 1}); !errors.Is(err, ErrFactoryInvalid) {
			t.Fatalf("generation postcondition error=%v", err)
		}
		if !assemblyClosed(assembly) {
			t.Fatal("wrong-generation assembly remained open")
		}
		if !transport.closed {
			t.Fatal("transport remained open after wrong-generation assembly")
		}
	})
	t.Run("nomination", func(t *testing.T) {
		config := base
		assembly := &Assembly{attempt: 1, network: 1, done: make(chan struct{})}
		transport := &recordingTransport{}
		config.Open = func(context.Context, Config) (*Assembly, error) { return assembly, nil }
		config.Dial = func(context.Context, signaling.WebSocketConfig) (SignalingTransport, error) { return transport, nil }
		config.Negotiate = func(context.Context, NegotiationConfig) error { return nil }
		factory, _ := NewSignalingFactory(config)
		if _, err := factory.Create(context.Background(), Generation{Attempt: 1, Network: 1}); !errors.Is(err, ErrFactoryInvalid) {
			t.Fatalf("nomination postcondition error=%v", err)
		}
		if !assemblyClosed(assembly) || !transport.closed {
			t.Fatalf("cleanup assembly=%v transport=%v", assemblyClosed(assembly), transport.closed)
		}
	})
}
