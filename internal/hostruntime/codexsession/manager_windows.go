//go:build windows

package codexsession

// Manager is kept as a distinct hostd ownership slot on Windows. The
// Windows Codex transport is registered by the host gateway once its
// ConPTY/user-session broker is running; hostd must still compile and retain
// the ownership boundary even when Codex is not installed on a machine.
type Manager struct{}
