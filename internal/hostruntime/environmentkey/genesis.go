package environmentkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	genesisMarkerSchema = "paperboat.environment-host-genesis/v1"
	genesisMACDomain    = "paperboat-environment-host-genesis-marker-v1\x00"
	genesisNonceSize    = 32
)

var (
	ErrGenesisMarkerMissing      = errors.New("environment host genesis marker is missing")
	ErrGenesisMarkerInvalid      = errors.New("environment host genesis marker is invalid")
	ErrGenesisAlreadyEstablished = errors.New("environment host genesis is already established")
	ErrGenesisNotPrepared        = errors.New("environment host genesis is not prepared")
	ErrHostKeyMissing            = errors.New("environment host key is missing")
)

type GenesisState string

const (
	GenesisFresh       GenesisState = "fresh"
	GenesisPending     GenesisState = "pending"
	GenesisEstablished GenesisState = "established"
)

// GenesisMarker is the installation-level capability that permits creation of
// the first local high-water record. Implementations must keep it in the same
// approved secure custody boundary as the host key, not in ENV cache files.
type GenesisMarker interface {
	GenesisState() (GenesisState, error)
	PrepareGenesis() error
	CommitGenesis() error
}

type genesisMarkerRecord struct {
	Schema                 string       `json:"schema"`
	MachineID              string       `json:"machine_id"`
	InstallationGeneration uint64       `json:"installation_generation"`
	HostKeyGeneration      uint64       `json:"host_key_generation"`
	HostPublicKey          string       `json:"host_public_key"`
	State                  GenesisState `json:"state"`
	Nonce                  string       `json:"nonce"`
}

type authenticatedGenesisMarker struct {
	Record genesisMarkerRecord `json:"record"`
	MAC    string              `json:"mac"`
}

// genesisMarkerMu serializes marker transitions made by multiple host
// goroutines in one process. The secure-store Set operation is the durable,
// atomic replacement boundary; read-back verifies that replacement completed.
var genesisMarkerMu sync.Mutex

func (s KeyringSource) genesisReference() string {
	return fmt.Sprintf("environment-host-genesis/%s/%d", s.MachineID, s.Generation)
}

func (s KeyringSource) GenesisState() (state GenesisState, resultErr error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	unlock, err := s.lockEnvironmentHostKey()
	if err != nil {
		return "", err
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			state = ""
			resultErr = errors.Join(resultErr, ErrUnavailable, unlockErr)
		}
	}()
	material, err := s.loadExistingMaterial()
	if err != nil {
		return "", err
	}
	defer material.Destroy()
	genesisMarkerMu.Lock()
	defer genesisMarkerMu.Unlock()
	record, err := s.readGenesisMarker(material)
	if err != nil {
		return "", err
	}
	return record.State, nil
}

func (s KeyringSource) PrepareGenesis() (resultErr error) {
	if err := s.validate(); err != nil {
		return err
	}
	unlock, err := s.lockEnvironmentHostKey()
	if err != nil {
		return err
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			resultErr = errors.Join(resultErr, ErrUnavailable, unlockErr)
		}
	}()
	material, err := s.loadExistingMaterial()
	if err != nil {
		return err
	}
	defer material.Destroy()
	genesisMarkerMu.Lock()
	defer genesisMarkerMu.Unlock()
	record, err := s.readGenesisMarker(material)
	if err != nil {
		return err
	}
	switch record.State {
	case GenesisFresh:
		record.State = GenesisPending
		return s.writeGenesisMarker(material, record)
	case GenesisPending:
		return nil
	case GenesisEstablished:
		return ErrGenesisAlreadyEstablished
	default:
		return ErrGenesisMarkerInvalid
	}
}

func (s KeyringSource) CommitGenesis() (resultErr error) {
	if err := s.validate(); err != nil {
		return err
	}
	unlock, err := s.lockEnvironmentHostKey()
	if err != nil {
		return err
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			resultErr = errors.Join(resultErr, ErrUnavailable, unlockErr)
		}
	}()
	material, err := s.loadExistingMaterial()
	if err != nil {
		return err
	}
	defer material.Destroy()
	genesisMarkerMu.Lock()
	defer genesisMarkerMu.Unlock()
	record, err := s.readGenesisMarker(material)
	if err != nil {
		return err
	}
	switch record.State {
	case GenesisPending:
		record.State = GenesisEstablished
		return s.writeGenesisMarker(material, record)
	case GenesisEstablished:
		return nil
	case GenesisFresh:
		return ErrGenesisNotPrepared
	default:
		return ErrGenesisMarkerInvalid
	}
}

func (s KeyringSource) createGenesisMarker(material Material) error {
	nonce, err := s.randomNonce()
	if err != nil {
		return err
	}
	public, err := material.Public()
	if err != nil {
		return err
	}
	record := genesisMarkerRecord{
		Schema: genesisMarkerSchema, MachineID: s.MachineID,
		InstallationGeneration: s.Generation, HostKeyGeneration: material.Generation,
		HostPublicKey: base64.RawURLEncoding.EncodeToString(public[:]), State: GenesisFresh,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}
	clear(nonce)
	return s.writeGenesisMarker(material, record)
}

func (s KeyringSource) randomNonce() ([]byte, error) {
	random := s.Random
	if random == nil {
		random = rand.Reader
	}
	nonce := make([]byte, genesisNonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		clear(nonce)
		return nil, errors.Join(ErrUnavailable, err)
	}
	return nonce, nil
}

func (s KeyringSource) readGenesisMarker(material Material) (genesisMarkerRecord, error) {
	encoded, err := s.Store.Get(s.genesisReference())
	if err != nil {
		if s.NotFound(err) {
			return genesisMarkerRecord{}, ErrGenesisMarkerMissing
		}
		return genesisMarkerRecord{}, errors.Join(ErrUnavailable, err)
	}
	return decodeGenesisMarker(encoded, material, s.MachineID, s.Generation)
}

func (s KeyringSource) writeGenesisMarker(material Material, record genesisMarkerRecord) error {
	encoded, err := encodeGenesisMarker(record, material)
	if err != nil {
		return err
	}
	if err := s.Store.Set(s.genesisReference(), encoded); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	readback, err := s.Store.Get(s.genesisReference())
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if readback != encoded {
		return ErrGenesisMarkerInvalid
	}
	if _, err := decodeGenesisMarker(readback, material, s.MachineID, s.Generation); err != nil {
		return err
	}
	return nil
}

func encodeGenesisMarker(record genesisMarkerRecord, material Material) (string, error) {
	if err := validateGenesisRecord(record, material, "", 0); err != nil {
		return "", err
	}
	mac := genesisMAC(material, record)
	authenticated := authenticatedGenesisMarker{Record: record, MAC: base64.RawURLEncoding.EncodeToString(mac[:])}
	clear(mac[:])
	encoded, err := json.Marshal(authenticated)
	if err != nil {
		return "", errors.Join(ErrGenesisMarkerInvalid, err)
	}
	return string(encoded), nil
}

func decodeGenesisMarker(encoded string, material Material, machineID string, generation uint64) (genesisMarkerRecord, error) {
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var authenticated authenticatedGenesisMarker
	if err := decoder.Decode(&authenticated); err != nil {
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	canonical, err := json.Marshal(authenticated)
	if err != nil || string(canonical) != encoded {
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	if err := validateGenesisRecord(authenticated.Record, material, machineID, generation); err != nil {
		return genesisMarkerRecord{}, err
	}
	provided, err := base64.RawURLEncoding.Strict().DecodeString(authenticated.MAC)
	if err != nil || len(provided) != sha256.Size || authenticated.MAC != base64.RawURLEncoding.EncodeToString(provided) {
		clear(provided)
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	expected := genesisMAC(material, authenticated.Record)
	valid := hmac.Equal(provided, expected[:])
	clear(provided)
	clear(expected[:])
	if !valid {
		return genesisMarkerRecord{}, ErrGenesisMarkerInvalid
	}
	return authenticated.Record, nil
}

func validateGenesisRecord(record genesisMarkerRecord, material Material, machineID string, generation uint64) error {
	if record.Schema != genesisMarkerSchema || !validIdentity(record.MachineID) || record.InstallationGeneration == 0 || record.HostKeyGeneration == 0 || record.State == "" || record.Nonce == "" {
		return ErrGenesisMarkerInvalid
	}
	if machineID != "" && (record.MachineID != machineID || record.InstallationGeneration != generation || record.HostKeyGeneration != material.Generation) {
		return ErrGenesisMarkerInvalid
	}
	if record.InstallationGeneration != material.Generation || record.HostKeyGeneration != material.Generation {
		return ErrGenesisMarkerInvalid
	}
	public, err := material.Public()
	if err != nil || record.HostPublicKey != base64.RawURLEncoding.EncodeToString(public[:]) {
		return ErrGenesisMarkerInvalid
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(record.Nonce)
	if err != nil || len(nonce) != genesisNonceSize || record.Nonce != base64.RawURLEncoding.EncodeToString(nonce) {
		clear(nonce)
		return ErrGenesisMarkerInvalid
	}
	clear(nonce)
	switch record.State {
	case GenesisFresh, GenesisPending, GenesisEstablished:
		return nil
	default:
		return ErrGenesisMarkerInvalid
	}
}

func genesisMAC(material Material, record genesisMarkerRecord) [sha256.Size]byte {
	canonical, _ := json.Marshal(record)
	mac := hmac.New(sha256.New, material.Private[:])
	_, _ = mac.Write([]byte(genesisMACDomain))
	_, _ = mac.Write(canonical)
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}
