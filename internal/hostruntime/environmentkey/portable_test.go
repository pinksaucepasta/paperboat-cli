//go:build darwin || linux

package environmentkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type portableWrappingKey [32]byte

func (key portableWrappingKey) EnvironmentWrappingKey() ([32]byte, error) {
	return [32]byte(key), nil
}

func TestPortableSourcePersistsDedicatedRecipientWithoutPlaintext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime-state")
	var wrapping [32]byte
	copy(wrapping[:], bytes.Repeat([]byte{0x47}, len(wrapping)))
	identity := portableWrappingKey(wrapping)

	source, err := NewPortableSource(PortableConfig{
		StateRoot: root, MachineID: "mch_portable", Generation: 11,
		Random: zeroReader{},
	}, identity)
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	firstPublic, err := first.Public()
	if err != nil {
		t.Fatal(err)
	}
	if firstPublic == ([32]byte{}) || bytes.Equal(first.Private[:], wrapping[:]) {
		t.Fatal("portable source did not create a separate recipient key")
	}

	path := filepath.Join(root, PortableCredentialPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, first.Private[:]) || bytes.Contains(body, []byte(base64.RawURLEncoding.EncodeToString(first.Private[:]))) {
		t.Fatal("portable envelope contains the raw recipient key")
	}
	var envelope portableEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Ciphertext == "" || envelope.Nonce == "" {
		t.Fatalf("invalid portable envelope: %v", err)
	}
	if info, err := os.Stat(path); err != nil || !securePortableFile(info) {
		t.Fatalf("portable envelope permissions=%v err=%v", info, err)
	}

	reopened, err := NewPortableSource(PortableConfig{
		StateRoot: root, MachineID: "mch_portable", Generation: 11,
	}, identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if second != first {
		t.Fatalf("portable recipient changed after restart: first=%x second=%x", first.Private, second.Private)
	}
	if state, err := reopened.GenesisState(); err != nil || state != GenesisFresh {
		t.Fatalf("genesis state=%q err=%v", state, err)
	}
	if err := reopened.PrepareGenesis(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.CommitGenesis(); err != nil {
		t.Fatal(err)
	}
	if state, err := reopened.GenesisState(); err != nil || state != GenesisEstablished {
		t.Fatalf("committed genesis state=%q err=%v", state, err)
	}
}

func TestPortableSourceConcurrentFirstLoadsKeepOneRecipient(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime-state")
	var wrapping [32]byte
	copy(wrapping[:], bytes.Repeat([]byte{0x48}, len(wrapping)))
	identity := portableWrappingKey(wrapping)
	const workers = 16
	materials := make(chan Material, workers)
	errorsCh := make(chan error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			source, err := NewPortableSource(PortableConfig{
				StateRoot: root, MachineID: "mch_portable", Generation: 12,
				Random: zeroReader{offset: byte(index)},
			}, identity)
			if err != nil {
				errorsCh <- err
				return
			}
			material, err := source.Load(context.Background())
			if err != nil {
				errorsCh <- err
				return
			}
			materials <- material
		}(index)
	}
	close(start)
	wait.Wait()
	close(materials)
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}
	loaded := make([]Material, 0, workers)
	for material := range materials {
		loaded = append(loaded, material)
	}
	defer func() {
		for _, material := range loaded {
			material.Destroy()
		}
	}()
	var first Material
	for _, material := range loaded {
		if first == (Material{}) {
			first = material
			continue
		}
		if material != first {
			t.Fatalf("concurrent portable loads returned different recipients: %x %x", first.Private, material.Private)
		}
	}
	if first == (Material{}) {
		t.Fatal("concurrent portable loads returned no recipient")
	}
}

func TestPortableSourceBindsCiphertextToWrappingIdentityAndFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime-state")
	var wrapping [32]byte
	copy(wrapping[:], bytes.Repeat([]byte{0x28}, len(wrapping)))
	identity := portableWrappingKey(wrapping)
	source, err := NewPortableSource(PortableConfig{
		StateRoot: root, MachineID: "mch_portable", Generation: 3,
		Random: zeroReader{},
	}, identity)
	if err != nil {
		t.Fatal(err)
	}
	material, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()

	var changed [32]byte
	copy(changed[:], bytes.Repeat([]byte{0x29}, len(changed)))
	changedIdentity := portableWrappingKey(changed)
	wrongIdentity, err := NewPortableSource(PortableConfig{
		StateRoot: root, MachineID: "mch_portable", Generation: 3,
	}, changedIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongIdentity.Load(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong identity error=%v, want ErrInvalid", err)
	}

	path := filepath.Join(root, PortableCredentialPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Load(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered envelope error=%v, want ErrInvalid", err)
	}
	if _, err := source.Load(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered envelope was replaced: %v", err)
	}
}

func TestPortableSourceNewWritableIdentityGetsNewRecipient(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime-state")
	var firstWrapping [32]byte
	copy(firstWrapping[:], bytes.Repeat([]byte{0x51}, len(firstWrapping)))
	firstIdentity := portableWrappingKey(firstWrapping)
	firstSource, err := NewPortableSource(PortableConfig{
		StateRoot: root, MachineID: "mch_portable", Generation: 1,
		Random: zeroReader{},
	}, firstIdentity)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstPrivate := first.Private
	first.Destroy()

	newRoot := filepath.Join(t.TempDir(), "runtime-state")
	var secondWrapping [32]byte
	copy(secondWrapping[:], bytes.Repeat([]byte{0x52}, len(secondWrapping)))
	secondIdentity := portableWrappingKey(secondWrapping)
	secondSource, err := NewPortableSource(PortableConfig{
		StateRoot: newRoot, MachineID: "mch_portable", Generation: 1,
		Random: zeroReader{offset: 1},
	}, secondIdentity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if firstPrivate == second.Private {
		t.Fatal("new writable identity reused the old recipient key")
	}
}

func TestPortableDerivedKeyIsDomainSeparated(t *testing.T) {
	var wrapping [32]byte
	copy(wrapping[:], bytes.Repeat([]byte{0x61}, len(wrapping)))
	first := portableDerivedKey(wrapping, "mch_portable", 1)
	second := portableDerivedKey(wrapping, "mch_portable", 2)
	if first == second {
		t.Fatal("portable wrapping key was not generation bound")
	}
	digest := sha256.Sum256([]byte("portable test"))
	if bytes.Equal(first[:], digest[:]) {
		t.Fatal("portable derivation is not domain separated")
	}
}
