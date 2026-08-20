//go:build windows

package elevation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func assertRenameBlocked(t *testing.T, from, to string) {
	t.Helper()
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		t.Fatal(err)
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_WRITE_THROUGH)
	if err == nil {
		t.Fatalf("rename %q to %q succeeded while a bridge handle was open", from, to)
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("rename %q to %q error = %v, want sharing violation or access denied", from, to, err)
	}
}

func createDirectoryReparseSwap(t *testing.T, original, target string) {
	t.Helper()
	linkPtr, err := windows.UTF16PtrFromString(original)
	if err != nil {
		t.Fatal(err)
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.CreateSymbolicLink(linkPtr, targetPtr, windows.SYMBOLIC_LINK_FLAG_DIRECTORY)
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skipf("reparse-point creation is unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(original) })
}

func TestBridgeParametersContainOnlyProtectedFilePaths(t *testing.T) {
	paths := bridgePaths{
		request: "C:\\Users\\Test User\\AppData\\Local\\Paperboat\\elevation\\request-abc\\request.json",
		result:  "C:\\Users\\Test User\\AppData\\Local\\Paperboat\\elevation\\request-abc\\result.json",
		cancel:  "C:\\Users\\Test User\\AppData\\Local\\Paperboat\\elevation\\request-abc\\cancel",
	}
	parameters := bridgeParameters(paths)
	for _, expected := range []string{"__runtime-service", "--request-file", "request.json", "--result-file", "result.json", "--cancel-file", "cancel"} {
		if !strings.Contains(parameters, expected) {
			t.Fatalf("parameters %q do not contain %q", parameters, expected)
		}
	}
	if strings.Contains(parameters, "enrollment-token") || strings.Contains(parameters, "private-key") || strings.Contains(parameters, "secret-value") {
		t.Fatalf("elevation parameters contain secret material: %q", parameters)
	}
}

func TestProtectedBridgeFilesUseCurrentUserACL(t *testing.T) {
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		if os.Getenv("LOCALAPPDATA") == "" {
			t.Skip("LOCALAPPDATA is unavailable")
		}
		t.Fatal(err)
	}
	defer cleanup()
	if err := verifyProtectedDirectory(paths.directory, ownerSID); err != nil {
		t.Fatalf("request directory ACL: %v", err)
	}
	request := Request{Schema: SchemaV1, RequestID: "request-test", OwnerSID: ownerSID, Operation: OperationOpenSSH, Action: ActionOpenSSHSetup, CancelPath: paths.cancel, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	if err := verifyProtectedFile(paths.request, ownerSID, true); err != nil {
		t.Fatalf("request file ACL: %v", err)
	}
	decoded, err := readProtectedRequest(paths.request)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID != request.RequestID || decoded.OwnerSID != ownerSID {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestOpenBridgeFileRejectsHardLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "request.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	linkPtr, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateHardLink(linkPtr, targetPtr, 0); err != nil {
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("hard links are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := openBridgeFile(link, windows.FILE_GENERIC_READ); err == nil {
		t.Fatal("openBridgeFile accepted a hard-linked bridge file")
	} else if !strings.Contains(strings.ToLower(err.Error()), "hard link") {
		t.Fatalf("openBridgeFile error = %v, want hard-link rejection", err)
	}
}

func TestOpenBridgeFilePreventsRenameSwap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "request.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := openBridgeFile(path, windows.FILE_GENERIC_READ)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)

	assertRenameBlocked(t, path, filepath.Join(root, "request.swap"))
	if _, err := bridgeHandleSize(handle); err != nil {
		t.Fatalf("validated handle became unusable after blocked swap: %v", err)
	}
}

func TestOpenBridgeHandlesPreventDirectoryRenameSwap(t *testing.T) {
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	request := Request{
		Schema:     SchemaV1,
		RequestID:  filepath.Base(paths.directory),
		OwnerSID:   ownerSID,
		Operation:  OperationOpenSSH,
		Action:     ActionOpenSSHSetup,
		CancelPath: paths.cancel,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
	}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	handles, err := openBridgeHandles(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer handles.close()

	assertRenameBlocked(t, paths.directory, paths.directory+".swap")
}

func TestOpenBridgeDirectoryChainRejectsReparseSwap(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "bridge")
	backup := filepath.Join(root, "bridge.original")
	target := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Join(original, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, backup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(original)
		_ = os.Rename(backup, original)
	})
	createDirectoryReparseSwap(t, original, target)

	if _, _, err := openBridgeDirectoryChain(filepath.Join(original, "child"), windows.FILE_GENERIC_READ); err == nil {
		t.Fatal("openBridgeDirectoryChain followed a reparse-point directory")
	} else if !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("openBridgeDirectoryChain error = %v, want reparse rejection", err)
	}
}

func TestRunOpenSSHMapsUACCancellationToTypedError(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridgeTestMutex.Lock()
	defer bridgeTestMutex.Unlock()
	previous := shellExecuteExForRun
	previousElevated := isCurrentProcessElevatedForRun
	shellExecuteExForRun = func(string, string, string) (windows.Handle, error) {
		return 0, windows.ERROR_CANCELLED
	}
	isCurrentProcessElevatedForRun = func() bool { return false }
	defer func() {
		shellExecuteExForRun = previous
		isCurrentProcessElevatedForRun = previousElevated
	}()
	err = RunOpenSSH(context.Background(), executable, ActionOpenSSHSetup)
	if !errors.Is(err, ErrElevationDenied) {
		t.Fatalf("error = %v, want ErrElevationDenied", err)
	}
}

func TestPinnedExecutableRejectsReplacementAndHardLinks(t *testing.T) {
	source := filepath.Join(t.TempDir(), "paperboat.exe")
	if err := os.WriteFile(source, []byte("MZ test"), 0o600); err != nil {
		t.Fatal(err)
	}
	validated, handle, err := pinExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	if validated != source {
		t.Fatalf("validated executable = %q, want %q", validated, source)
	}
	replacement := filepath.Join(filepath.Dir(source), "replacement.exe")
	if err := os.Rename(source, replacement); err == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("pinned executable was renamed while its validation handle was held")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, replacement); err != nil {
		t.Fatalf("executable remained pinned after close: %v", err)
	}
	link := filepath.Join(filepath.Dir(source), "paperboat-link.exe")
	if err := os.Link(replacement, link); err != nil {
		t.Skipf("hard links are unavailable on this test volume: %v", err)
	}
	if _, handle, err := pinExecutable(replacement); err == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("multiply-linked elevation executable was accepted")
	}
}

func TestBridgeRejectsHardLinkedResultPlaceholder(t *testing.T) {
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	request := Request{Schema: SchemaV1, RequestID: filepath.Base(paths.directory), OwnerSID: ownerSID, Operation: OperationOpenSSH, Action: ActionOpenSSHSetup, CancelPath: paths.cancel, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(paths.directory, "result-link.json")
	if err := os.Link(paths.result, link); err != nil {
		t.Skipf("hard links are unavailable on this test volume: %v", err)
	}
	if handles, err := openBridgeHandles(paths); err == nil {
		_ = handles.close()
		t.Fatal("hard-linked elevation result placeholder was accepted")
	}
}

func TestBridgeRejectsHardLinkedResultSwap(t *testing.T) {
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	request := Request{Schema: SchemaV1, RequestID: filepath.Base(paths.directory), OwnerSID: ownerSID, Operation: OperationOpenSSH, Action: ActionOpenSSHSetup, CancelPath: paths.cancel, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(paths.directory, "sentinel")
	if err := os.WriteFile(sentinel, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.result); err != nil {
		t.Fatal(err)
	}
	sentinelPtr, err := windows.UTF16PtrFromString(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	resultPtr, err := windows.UTF16PtrFromString(paths.result)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateHardLink(resultPtr, sentinelPtr, 0); err != nil {
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("hard links are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if handles, err := openBridgeHandles(paths); err == nil {
		_ = handles.close()
		t.Fatal("hard-linked result swap was accepted")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "sentinel\n" {
		t.Fatalf("sentinel changed during rejected result swap: %q", contents)
	}
}

func TestExecuteHonorsProtectedCancellationMarker(t *testing.T) {
	if !IsCurrentProcessElevated() {
		t.Skip("native elevated child test requires an administrator token")
	}
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	request := Request{Schema: SchemaV1, RequestID: "request-cancel", OwnerSID: ownerSID, Operation: OperationOpenSSH, Action: ActionOpenSSHSetup, CancelPath: paths.cancel, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		time.Sleep(200 * time.Millisecond)
		_ = writeCancellation(paths, ownerSID)
	}()
	err = Execute(context.Background(), paths.request, paths.result, paths.cancel, func(ctx context.Context, _ Request) error {
		<-ctx.Done()
		return ctx.Err()
	})
	<-cancelDone
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute error = %v, want context cancellation", err)
	}
	result, err := readProtectedResult(paths, ownerSID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != statusCanceled || result.ErrorCode != "canceled" {
		t.Fatalf("result = %#v, want canceled result", result)
	}
}

func TestExecuteDoesNotMisclassifyOperationFailureAsCancellation(t *testing.T) {
	if !IsCurrentProcessElevated() {
		t.Skip("native elevated child test requires an administrator token")
	}
	ownerSID, err := currentOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	paths, cleanup, err := newBridgeFiles(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	request := Request{Schema: SchemaV1, RequestID: "request-failure", OwnerSID: ownerSID, Operation: OperationOpenSSH, Action: ActionOpenSSHSetup, CancelPath: paths.cancel, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := writeProtectedJSON(paths.request, request, ownerSID); err != nil {
		t.Fatal(err)
	}
	want := errors.New("deliberate operation failure")
	err = Execute(context.Background(), paths.request, paths.result, paths.cancel, func(context.Context, Request) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("Execute error = %v, want operation failure", err)
	}
	result, err := readProtectedResult(paths, ownerSID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != statusError || result.ErrorCode != operationFailed || result.ErrorMessage != want.Error() {
		t.Fatalf("result = %#v, want operation failure", result)
	}
}
