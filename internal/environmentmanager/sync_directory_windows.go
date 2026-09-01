//go:build windows

package environmentmanager

// A deleted retry record reappearing after a Windows crash is safe: the exact
// signed ciphertext mutation is idempotently reconciled again. Atomic file
// replacement is still durable before any HTTP mutation is attempted.
func syncMutationDirectory(string) error { return nil }
