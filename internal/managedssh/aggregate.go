package managedssh

import (
	"bytes"
	"errors"
	"io"
	"reflect"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const MaxAgentIdentities = 64

var ErrAgentIdentityLimit = errors.New("SSH agent identity limit exceeded")

type Aggregate struct {
	managed  *Agent
	delegate agent.ExtendedAgent
}

func NewAggregate(managed *Agent, delegate agent.ExtendedAgent) (*Aggregate, error) {
	if managed == nil || managed.signer == nil {
		return nil, ErrAgentDenied
	}
	if delegate != nil {
		value := reflect.ValueOf(delegate)
		if value.Kind() == reflect.Pointer && value.IsNil() {
			delegate = nil
		}
	}
	return &Aggregate{managed: managed, delegate: delegate}, nil
}

func (a *Aggregate) List() ([]*agent.Key, error) {
	managed, err := a.managed.List()
	if err != nil || a.delegate == nil {
		return managed, err
	}
	delegated, err := a.delegate.List()
	if err != nil {
		return managed, nil
	}
	if len(delegated) > MaxAgentIdentities || len(managed)+len(delegated) > MaxAgentIdentities {
		return nil, ErrAgentIdentityLimit
	}
	result := make([]*agent.Key, 0, len(managed)+len(delegated))
	result = append(result, managed...)
	for _, key := range delegated {
		if key == nil || len(key.Blob) == 0 || len(key.Blob) > MaxAgentRequestBytes || containsAgentKey(result, key.Blob) {
			continue
		}
		clone := *key
		clone.Blob = append([]byte(nil), key.Blob...)
		result = append(result, &clone)
	}
	return result, nil
}

func (a *Aggregate) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Aggregate) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if key == nil || len(data) > MaxSigningPayloadBytes {
		if len(data) > MaxSigningPayloadBytes {
			return nil, ErrAgentRequestTooLarge
		}
		return nil, ErrAgentDenied
	}
	if bytes.Equal(key.Marshal(), a.managed.key.Blob) {
		return a.managed.SignWithFlags(key, data, flags)
	}
	if a.delegate == nil {
		return nil, ErrAgentDenied
	}
	keys, err := a.delegate.List()
	if err != nil {
		return nil, err
	}
	if len(keys) > MaxAgentIdentities {
		return nil, ErrAgentIdentityLimit
	}
	if !containsAgentKey(keys, key.Marshal()) {
		return nil, ErrAgentDenied
	}
	return a.delegate.SignWithFlags(key, data, flags)
}

func (a *Aggregate) Signers() ([]ssh.Signer, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	result := make([]ssh.Signer, 0, len(keys))
	for _, key := range keys {
		public, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			return nil, ErrAgentDenied
		}
		result = append(result, aggregateSigner{aggregate: a, public: public})
	}
	return result, nil
}

func (*Aggregate) Add(agent.AddedKey) error   { return ErrAgentDenied }
func (*Aggregate) Remove(ssh.PublicKey) error { return ErrAgentDenied }
func (*Aggregate) RemoveAll() error           { return ErrAgentDenied }
func (*Aggregate) Lock([]byte) error          { return ErrAgentDenied }
func (*Aggregate) Unlock([]byte) error        { return ErrAgentDenied }
func (*Aggregate) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

type aggregateSigner struct {
	aggregate *Aggregate
	public    ssh.PublicKey
}

func (s aggregateSigner) PublicKey() ssh.PublicKey { return s.public }
func (s aggregateSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.aggregate.Sign(s.public, data)
}
func (s aggregateSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	flags := agent.SignatureFlags(0)
	switch algorithm {
	case ssh.KeyAlgoRSA:
	case ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	default:
		if algorithm != s.public.Type() {
			return nil, ErrAgentDenied
		}
	}
	return s.aggregate.SignWithFlags(s.public, data, flags)
}

func containsAgentKey(keys []*agent.Key, blob []byte) bool {
	for _, key := range keys {
		if key != nil && bytes.Equal(key.Blob, blob) {
			return true
		}
	}
	return false
}
