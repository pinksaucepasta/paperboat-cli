//go:build windows && paperboat_native_e2e

package hostruntimecmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntimeentry"
	"golang.org/x/sys/windows"
)

const nativePreviewE2EPlanPath = `C:\ProgramData\Paperboat\native-preview-e2e.json`

type nativePreviewE2EPlan struct {
	Schema, StateRoot, ReportPath, RunID string
	Port                                 uint16
	HoldAfterComplete                    bool
}
type nativePreviewE2EEvent struct {
	Stage    string `json:"stage"`
	Name     string `json:"name,omitempty"`
	SID      string `json:"sid,omitempty"`
	Elevated bool   `json:"elevated"`
	Session  uint32 `json:"session_id"`
	Error    string `json:"error,omitempty"`
}

func runWindowsHostdNativeE2E(ctx context.Context, install hostinstall.WindowsRuntimeConfig) (bool, error) {
	body, err := os.ReadFile(nativePreviewE2EPlanPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	var plan nativePreviewE2EPlan
	if err != nil || json.Unmarshal(body, &plan) != nil || plan.Schema != "paperboat.native-preview-e2e/v1" || plan.StateRoot != install.StateRoot || !filepath.IsAbs(plan.ReportPath) || !strings.HasPrefix(plan.RunID, "e2e-") || plan.Port == 0 {
		return true, errors.New("invalid native preview E2E plan")
	}
	user, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sid := ""
	if user != nil && user.User.Sid != nil {
		sid = user.User.Sid.String()
	}
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &sessionID); err != nil {
		return true, errors.New("native E2E owner session unavailable")
	}
	appendNativePreviewE2E(plan.ReportPath, nativePreviewE2EEvent{Stage: "hostd_owner", SID: sid, Elevated: windows.GetCurrentProcessToken().IsElevated(), Session: sessionID})
	if sid != install.OwnerSID || windows.GetCurrentProcessToken().IsElevated() || sessionID != 0 {
		return true, errors.New("native E2E owner token mismatch")
	}
	prefix := plan.RunID + "-"
	expires := time.Now().UTC().Add(2 * time.Minute)
	if err = hostruntimeentry.InstallPreviewService(ctx, "", plan.StateRoot, prefix+"single", plan.Port, &expires, false); err != nil {
		appendNativePreviewE2E(plan.ReportPath, nativePreviewE2EEvent{Stage: "failed", Error: err.Error()})
		return true, err
	}
	if err = waitNativePreviewE2E(plan.ReportPath, prefix+"single", 30*time.Second); err != nil {
		return true, err
	}
	if err = hostruntimeentry.RemovePreviewService(ctx, plan.StateRoot, prefix+"single"); err != nil {
		return true, err
	}
	for _, name := range []string{prefix + "bulk-a", prefix + "bulk-b"} {
		if err = hostruntimeentry.InstallPreviewService(ctx, "", plan.StateRoot, name, plan.Port, &expires, false); err != nil {
			return true, err
		}
	}
	if err = hostruntimeentry.RemoveAllPreviewServices(ctx, plan.StateRoot); err != nil {
		appendNativePreviewE2E(plan.ReportPath, nativePreviewE2EEvent{Stage: "failed", Error: err.Error()})
		return true, err
	}
	late := time.Now().UTC().Add(time.Minute)
	if err = hostruntimeentry.InstallPreviewService(ctx, "", plan.StateRoot, prefix+"expired", plan.Port, &late, false); err != nil {
		return true, err
	}
	if err = hostruntimeentry.ReconcileExpiredPreviewServices(ctx, plan.StateRoot, late.Add(time.Second)); err != nil {
		appendNativePreviewE2E(plan.ReportPath, nativePreviewE2EEvent{Stage: "failed", Error: err.Error()})
		return true, err
	}
	appendNativePreviewE2E(plan.ReportPath, nativePreviewE2EEvent{Stage: "complete", SID: sid})
	if plan.HoldAfterComplete {
		<-ctx.Done()
	}
	return true, nil
}

func appendNativePreviewE2E(path string, event nativePreviewE2EEvent) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(event)
}
func waitNativePreviewE2E(path, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		body, _ := os.ReadFile(path)
		if strings.Contains(string(body), `"stage":"preview_owner"`) && strings.Contains(string(body), `"name":"`+name+`"`) {
			return nil
		}
		//paperboat:allow-source-policy sleep owner=windows-native-qualification reason=bounded-preview-owner-report-poll
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("native preview owner did not report")
}
