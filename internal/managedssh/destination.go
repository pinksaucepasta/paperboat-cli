package managedssh

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrSSHAliasInvalid     = errors.New("managed SSH alias is invalid")
	ErrSSHUsernameInvalid  = errors.New("managed SSH username is invalid")
	ErrSSHUsernameConflict = errors.New("OpenSSH username conflicts with the requested user")
	ErrSSHPortConflict     = errors.New("OpenSSH destination port differs from the registered SSH target")
	ErrSSHUsernameMissing  = errors.New("managed SSH username is unavailable")
)

type Destination struct {
	Alias string
	Host  string
	Port  uint16
	User  string
}

type DestinationInput struct {
	Alias             string
	AliasSuffix       string
	RegisteredPort    uint16
	RequestedPort     uint16
	RequestedUser     string
	OpenSSHUser       string
	RegisteredUser    string
	LocalUser         string
	HasRegisteredUser bool
}

// ResolveDestination applies the account alias, registered target, and username
// policy before OpenSSH or a proxy process is started.
func ResolveDestination(input DestinationInput) (Destination, error) {
	host, err := AliasHost(input.Alias, input.AliasSuffix)
	if err != nil {
		return Destination{}, err
	}
	if input.RegisteredPort == 0 {
		return Destination{}, ErrSSHTargetInvalid
	}
	if input.RequestedPort != 0 && input.RequestedPort != input.RegisteredPort {
		return Destination{}, ErrSSHPortConflict
	}
	user, err := ResolveUsername(input.RequestedUser, input.OpenSSHUser, input.RegisteredUser, input.LocalUser, input.HasRegisteredUser)
	if err != nil {
		return Destination{}, err
	}
	return Destination{Alias: strings.ToLower(input.Alias), Host: host, Port: input.RegisteredPort, User: user}, nil
}

func AliasHost(alias, suffix string) (string, error) {
	alias = strings.ToLower(strings.TrimSpace(alias))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if !validAliasLabel(alias) || !validAliasSuffix(suffix) {
		return "", ErrSSHAliasInvalid
	}
	return alias + "." + suffix, nil
}

// ParseAliasHost accepts exactly one alias label beneath the configured suffix.
func ParseAliasHost(host, suffix string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if !validAliasSuffix(suffix) || !strings.HasSuffix(host, "."+suffix) {
		return "", ErrSSHAliasInvalid
	}
	alias := strings.TrimSuffix(host, "."+suffix)
	if !validAliasLabel(alias) {
		return "", ErrSSHAliasInvalid
	}
	return alias, nil
}

func ResolveUsername(requested, openSSH, registered, local string, hasRegistered bool) (string, error) {
	requested = strings.TrimSpace(requested)
	openSSH = strings.TrimSpace(openSSH)
	registered = strings.TrimSpace(registered)
	local = strings.TrimSpace(local)
	if requested != "" && openSSH != "" && requested != openSSH {
		return "", ErrSSHUsernameConflict
	}
	selected := requested
	if selected == "" {
		selected = openSSH
	}
	if selected == "" && hasRegistered {
		selected = registered
	}
	if selected == "" && !hasRegistered {
		selected = local
	}
	if selected == "" {
		return "", ErrSSHUsernameMissing
	}
	if !validSSHUsername(selected) {
		return "", ErrSSHUsernameInvalid
	}
	return selected, nil
}

func ValidateDestinationPort(value string, registered uint16) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 || registered == 0 {
		return 0, ErrSSHTargetInvalid
	}
	if uint16(port) != registered {
		return 0, ErrSSHPortConflict
	}
	return uint16(port), nil
}

func validAliasLabel(value string) bool {
	if value == "" || len(value) > 63 || value != strings.ToLower(value) || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validSSHUsername(value string) bool {
	if value == "" || len(value) > 255 || value[0] == '-' || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n@") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
