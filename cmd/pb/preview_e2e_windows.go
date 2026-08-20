//go:build windows && paperboat_native_e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func runWindowsPreviewNativeE2E(ctx context.Context, stateRoot, name string) (bool, error) {
	body, err := os.ReadFile(`C:\ProgramData\Paperboat\native-preview-e2e.json`)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	var plan struct{ Schema, StateRoot, ReportPath, RunID string }
	if err != nil || json.Unmarshal(body, &plan) != nil || plan.Schema != "paperboat.native-preview-e2e/v1" || plan.StateRoot != stateRoot || !filepath.IsAbs(plan.ReportPath) || !strings.HasPrefix(name, plan.RunID+"-") {
		return true, errors.New("invalid native preview E2E workload")
	}
	user, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sid := ""
	if user != nil && user.User.Sid != nil {
		sid = user.User.Sid.String()
	}
	f, err := os.OpenFile(plan.ReportPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return true, err
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(map[string]any{"stage": "preview_owner", "name": name, "sid": sid, "elevated": windows.GetCurrentProcessToken().IsElevated()})
	if err != nil {
		return true, err
	}
	<-ctx.Done()
	return true, nil
}
