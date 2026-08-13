package peercontext

import (
	"bytes"
	"testing"
)

func TestContextEncodingIsDeterministicAndBindsEveryField(t *testing.T) {
	base := validContext()
	want, err := base.Hash()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Context){
		func(c *Context) { c.AccountID = "account_02" },
		func(c *Context) { c.UserID = "user_02" },
		func(c *Context) { c.DeviceID = "cli_02" },
		func(c *Context) { c.MachineID = "machine_02" },
		func(c *Context) { c.InitiatorCertificateHash[0]++ },
		func(c *Context) { c.ResponderCertificateHash[0]++ },
		func(c *Context) { c.HostGeneration++ },
		func(c *Context) { c.AuthorizationGeneration++ },
		func(c *Context) { c.IntentID = "intent_02" },
		func(c *Context) { c.OperationID = "operation_02" },
		func(c *Context) { c.Consumer = "exec" },
		func(c *Context) { c.InitiatorRole = "device" },
		func(c *Context) { c.ResponderRole = "host" },
		func(c *Context) { c.AttemptGeneration++ },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		got, err := changed.Hash()
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if got == want {
			t.Fatalf("mutation %d did not change context hash", index)
		}
	}
}

func TestContextRejectsMissingAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*Context){
		"identifier":  func(c *Context) { c.IntentID = "" },
		"generation":  func(c *Context) { c.HostGeneration = 0 },
		"certificate": func(c *Context) { c.ResponderCertificateHash = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			context := validContext()
			mutate(&context)
			if _, err := context.MarshalBinary(); err == nil {
				t.Fatal("invalid context accepted")
			}
		})
	}
}

func TestContextAcceptsProductionAccountIdentifier(t *testing.T) {
	context := validContext()
	context.AccountID = "usr_a7fdebc68b751a996daebd5e8d0705dc"
	context.UserID = context.AccountID
	if _, err := context.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
}

func TestParseBinaryRoundTripsCanonicalContextAndRejectsMalformedInput(t *testing.T) {
	want := validContext()
	encoded, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBinary(encoded)
	if err != nil || got != want {
		t.Fatalf("context=%+v err=%v", got, err)
	}
	for name, value := range map[string][]byte{
		"truncated": encoded[:len(encoded)-1],
		"trailing":  append(append([]byte(nil), encoded...), 0),
		"version":   append([]byte(nil), encoded...),
	} {
		if name == "version" {
			value[4]++
		}
		if _, err := ParseBinary(value); err == nil {
			t.Fatalf("%s encoding accepted", name)
		}
	}
}

func validContext() Context {
	context := Context{AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 2, AuthorizationGeneration: 4, IntentID: "intent_01", OperationID: "operation_01", Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 3}
	copy(context.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(context.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return context
}
