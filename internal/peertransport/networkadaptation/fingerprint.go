package networkadaptation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

var ErrInvalid = errors.New("invalid network adaptation input")

type InterfaceKind uint8

const (
	InterfacePhysical InterfaceKind = iota + 1
	InterfaceVPN
	InterfaceCellular
)

type Interface struct {
	Name     string
	Kind     InterfaceKind
	Prefixes []netip.Prefix
}

type NetworkObservation struct {
	Interfaces       []Interface
	DefaultInterface string
	NetworkIdentity  string
	IPv4             bool
	IPv6             bool
	VPN              bool
}

type Fingerprint [sha256.Size]byte

// DeriveFingerprint returns an opaque installation-scoped network identity.
// Callers must discard the raw observation after derivation.
func DeriveFingerprint(secret []byte, observation NetworkObservation) (Fingerprint, error) {
	if len(secret) < sha256.Size || len(observation.Interfaces) == 0 || len(observation.Interfaces) > 128 || len(observation.DefaultInterface) == 0 || len(observation.DefaultInterface) > 256 || len(observation.NetworkIdentity) > 1024 || !observation.IPv4 && !observation.IPv6 {
		return Fingerprint{}, ErrInvalid
	}
	interfaces := make([]Interface, len(observation.Interfaces))
	copy(interfaces, observation.Interfaces)
	for index := range interfaces {
		item := &interfaces[index]
		if item.Name == "" || len(item.Name) > 256 || item.Kind < InterfacePhysical || item.Kind > InterfaceCellular || len(item.Prefixes) > 128 {
			return Fingerprint{}, ErrInvalid
		}
		item.Prefixes = slices.Clone(item.Prefixes)
		for prefixIndex, prefix := range item.Prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() {
				return Fingerprint{}, ErrInvalid
			}
			item.Prefixes[prefixIndex] = prefix
		}
		slices.SortFunc(item.Prefixes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr())*129 + a.Bits() - b.Bits() })
	}
	slices.SortFunc(interfaces, func(a, b Interface) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return int(a.Kind) - int(b.Kind)
	})
	defaultPresent := false
	for index, item := range interfaces {
		if index > 0 && interfaces[index-1].Name == item.Name {
			return Fingerprint{}, ErrInvalid
		}
		defaultPresent = defaultPresent || item.Name == observation.DefaultInterface
	}
	if !defaultPresent {
		return Fingerprint{}, ErrInvalid
	}

	mac := hmac.New(sha256.New, secret)
	writeString(mac, "paperboat-network-fingerprint-v1")
	writeString(mac, observation.DefaultInterface)
	writeString(mac, observation.NetworkIdentity)
	flags := byte(0)
	if observation.IPv4 {
		flags |= 1
	}
	if observation.IPv6 {
		flags |= 2
	}
	if observation.VPN {
		flags |= 4
	}
	_, _ = mac.Write([]byte{flags})
	writeUint32(mac, uint32(len(interfaces)))
	for _, item := range interfaces {
		writeString(mac, item.Name)
		_, _ = mac.Write([]byte{byte(item.Kind)})
		writeUint32(mac, uint32(len(item.Prefixes)))
		for _, prefix := range item.Prefixes {
			address := prefix.Addr().As16()
			_, _ = mac.Write(address[:])
			_, _ = mac.Write([]byte{byte(prefix.Bits())})
		}
	}
	var result Fingerprint
	copy(result[:], mac.Sum(nil))
	return result, nil
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeString(writer hashWriter, value string) {
	writeUint32(writer, uint32(len(value)))
	_, _ = writer.Write([]byte(value))
}

func writeUint32(writer hashWriter, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func (f Fingerprint) valid() bool { return f != Fingerprint{} }

// Valid reports whether the fingerprint contains a derived opaque identity.
func (f Fingerprint) Valid() bool { return f.valid() }
