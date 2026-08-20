//go:build windows

package hosted

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// ConfigSyncHooks uses the same restore/save contract as Unix. It runs inside
// the enrolled owner workload, never inside the LocalSystem SCM process.
func ConfigSyncHooks(config Config, environ func(string) string) Hooks {
	command := filepath.Join(valueOr(os.Getenv("ProgramFiles"), `C:\Program Files`), "Paperboat", "paperboat-config-sync.exe")
	tokenName := ""
	token := ""
	if environ != nil {
		command = valueOr(environ("PAPERBOAT_CONFIG_SYNC_COMMAND"), command)
		tokenName = strings.TrimSpace(environ("PAPERBOAT_GITHUB_TOKEN_ENV"))
		if tokenName == "" {
			tokenName = "PAPERBOAT_GITHUB_CONFIG_TOKEN"
		}
		if safeEnvironmentName(tokenName) {
			token = environ(tokenName)
		} else {
			tokenName = ""
		}
	}
	runner := ExecRunner{OwnerSID: config.OwnerSID}
	run := func(ctx context.Context, action string) error {
		env := os.Environ()
		if tokenName != "" && token != "" {
			env = append(env, tokenName+"="+token)
		}
		_, err := runner.Run(ctx, Command{Path: command, Args: []string{action}, Dir: config.CheckoutRoot, Env: env, OutputLimit: config.MaxOutputBytes})
		return err
	}
	return Hooks{
		Restore: func(ctx context.Context, _ string) error { return run(ctx, "restore") },
		Flush:   func(ctx context.Context, _ string) error { return run(ctx, "save") },
	}
}
