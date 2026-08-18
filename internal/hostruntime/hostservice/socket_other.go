//go:build !windows

package hostservice

func DefaultSocketPath() string { return "/var/run/paperboat/host-service.sock" }
