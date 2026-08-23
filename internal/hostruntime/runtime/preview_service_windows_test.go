//go:build windows

package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func TestRemovePreviewServiceRemovesOwnedOrphanWithoutDescriptor(t *testing.T) {
	root := t.TempDir()
	const name = "docs"
	serviceName, err := WindowsPreviewServiceName(name)
	if err != nil {
		t.Fatal(err)
	}
	previous := removeWindowsPreviewService
	t.Cleanup(func() { removeWindowsPreviewService = previous })
	var gotName, gotRoot string
	removeWindowsPreviewService = func(_ context.Context, gotServiceName, gotStateRoot string) error {
		gotName, gotRoot = gotServiceName, gotStateRoot
		return nil
	}
	if err := RemovePreviewService(context.Background(), root, name); err != nil {
		t.Fatalf("RemovePreviewService error = %v", err)
	}
	if gotName != serviceName || gotRoot != root {
		t.Fatalf("orphan removal = (%q, %q), want (%q, %q)", gotName, gotRoot, serviceName, root)
	}
}

func TestRetirePreviewServiceWithRootUsesStateRootForInvalidSource(t *testing.T) {
	root := t.TempDir()
	const name = "invalid-source"
	definition, serviceName, err := previewServiceDefinition("", name, "windows")
	if err != nil {
		t.Fatal(err)
	}
	previous := removeWindowsPreviewService
	t.Cleanup(func() { removeWindowsPreviewService = previous })
	var gotName, gotRoot string
	removeWindowsPreviewService = func(_ context.Context, gotServiceName, gotStateRoot string) error {
		gotName, gotRoot = gotServiceName, gotStateRoot
		return nil
	}
	if err := retirePreviewServiceWithRoot(context.Background(), root, name, definition, nil); err != nil {
		t.Fatalf("retirePreviewServiceWithRoot error = %v", err)
	}
	if gotName != serviceName || gotRoot != root {
		t.Fatalf("invalid-source retirement = (%q, %q), want (%q, %q)", gotName, gotRoot, serviceName, root)
	}
}

func TestRemovePreviewServiceDoesNotHideServiceOnlyOrphan(t *testing.T) {
	root := t.TempDir()
	previous := removeWindowsPreviewService
	t.Cleanup(func() { removeWindowsPreviewService = previous })
	want := errors.New("service declaration is missing")
	removeWindowsPreviewService = func(context.Context, string, string) error { return want }
	if err := RemovePreviewService(context.Background(), root, "docs"); !errors.Is(err, want) {
		t.Fatalf("RemovePreviewService error = %v, want %v", err, want)
	}
}

func TestRemoveAllPreviewServicesRemovesOwnedOrphansAndRejectsAmbiguousService(t *testing.T) {
	root := t.TempDir()
	otherRoot := filepath.Join(t.TempDir(), "other")
	ownedName, err := WindowsPreviewServiceName("owned")
	if err != nil {
		t.Fatal(err)
	}
	declarationOnlyName, err := WindowsPreviewServiceName("declaration-only")
	if err != nil {
		t.Fatal(err)
	}
	foreignName, err := WindowsPreviewServiceName("foreign")
	if err != nil {
		t.Fatal(err)
	}
	serviceOnlyName, err := WindowsPreviewServiceName("service-only")
	if err != nil {
		t.Fatal(err)
	}
	previousList := listWindowsPreviewServiceArtifacts
	previousRemove := removeWindowsPreviewService
	previousValidate := validateWindowsPreviewServiceOwnership
	t.Cleanup(func() {
		listWindowsPreviewServiceArtifacts = previousList
		removeWindowsPreviewService = previousRemove
		validateWindowsPreviewServiceOwnership = previousValidate
	})
	listWindowsPreviewServiceArtifacts = func() ([]hostservice.WindowsPreviewServiceArtifact, error) {
		return []hostservice.WindowsPreviewServiceArtifact{
			{Name: ownedName, HasService: true, HasDeclaration: true, DeclarationRoot: root},
			{Name: declarationOnlyName, HasDeclaration: true, DeclarationRoot: root},
			{Name: foreignName, HasService: true, HasDeclaration: true, DeclarationRoot: otherRoot},
			{Name: serviceOnlyName, HasService: true},
		}, nil
	}
	removed := make(map[string]string)
	removeWindowsPreviewService = func(_ context.Context, name, stateRoot string) error {
		removed[name] = stateRoot
		return nil
	}
	validateWindowsPreviewServiceOwnership = func(context.Context, string, string) error { return nil }
	err = RemoveAllPreviewServices(context.Background(), root)
	if !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("RemoveAllPreviewServices error = %v, want production-invalid", err)
	}
	if len(removed) != 0 {
		t.Fatalf("partial removals occurred before ownership preflight completed: %+v", removed)
	}
	if _, ok := removed[foreignName]; ok {
		t.Fatalf("foreign orphan was removed: %+v", removed)
	}
	if _, ok := removed[serviceOnlyName]; ok {
		t.Fatalf("service-only orphan was removed: %+v", removed)
	}
}
