package managedssh

import (
	"crypto/sha256"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestFormatKnownHostsUsesStrictAliasAndPortAuthority(t *testing.T) {
	line := authorizedPublicLine(t)
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	key := HostPublicKey{Fingerprint: sha256.Sum256(public.Marshal()), Algorithm: public.Type(), PublicKey: line}
	defaultPort, err := FormatKnownHosts("Machine.PPRBT.dev", 22, []HostPublicKey{key})
	if err != nil || !strings.HasPrefix(string(defaultPort), "machine.pprbt.dev ssh-ed25519 ") {
		t.Fatalf("default known hosts=%q error=%v", defaultPort, err)
	}
	nonDefault, err := FormatKnownHosts("machine.pprbt.dev", 2222, []HostPublicKey{key})
	if err != nil || !strings.HasPrefix(string(nonDefault), "[machine.pprbt.dev]:2222 ssh-ed25519 ") {
		t.Fatalf("non-default known hosts=%q error=%v", nonDefault, err)
	}
	key.Fingerprint[0] ^= 0xff
	if _, err := FormatKnownHosts("machine.pprbt.dev", 22, []HostPublicKey{key}); err == nil {
		t.Fatal("mismatched host fingerprint was accepted")
	}
}

func TestFormatKnownHostsRejectsUnsafeHostAndDuplicateKeys(t *testing.T) {
	line := authorizedPublicLine(t)
	public, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
	key := HostPublicKey{Fingerprint: sha256.Sum256(public.Marshal()), Algorithm: public.Type(), PublicKey: line}
	for _, host := range []string{"127.0.0.1", "bad\nhost", "*.pprbt.dev", "-bad.pprbt.dev"} {
		if _, err := FormatKnownHosts(host, 22, []HostPublicKey{key}); err == nil {
			t.Fatalf("unsafe host %q was accepted", host)
		}
	}
	if _, err := FormatKnownHosts("machine.pprbt.dev", 22, []HostPublicKey{key, key}); err == nil {
		t.Fatal("duplicate host key was accepted")
	}
}
