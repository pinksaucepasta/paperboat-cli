//go:build windows

package runtime

import (
	"context"
	_ "embed"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostd"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
)

// Keep the source contract available when a Windows test binary is built on
// another host and copied to the target machine for execution.
//
//go:embed production_unix.go
var productionHostSource []byte

// TestWindowsProductionTunnelEnrollmentHasOneStableOwner verifies the
// Windows production contract at both sides of the composition boundary. The
// handler, lifecycle component, and stable-hostd tunnel workload must all be
// the same ProductionTunnelEnrollment object. Starting a second enrollment
// service would split durable state and can produce duplicate connector
// sessions after a service restart.
func TestWindowsProductionTunnelEnrollmentHasOneStableOwner(t *testing.T) {
	service, err := NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		ControlURL:   "https://api.example.test",
		StateRoot:    t.TempDir(),
		HostID:       "host_windows_composition",
		ControlToken: "local-control-token",
		Auth:         windowsCompositionMachineAuth{},
		Activator:    windowsCompositionActivator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })

	var handler http.Handler = service
	var lifecycle Service = platformTunnelEnrollmentLifecycle(service)
	var workloads hostd.TunnelWorkloads = service
	if got, ok := handler.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("enrollment handler = %T/%p, want the production enrollment %p", handler, got, service)
	}
	if got, ok := lifecycle.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("enrollment lifecycle = %T/%p, want the production enrollment %p", lifecycle, got, service)
	}
	if got, ok := workloads.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("tunnel workload = %T/%p, want the production enrollment %p", workloads, got, service)
	}

	dependencies := HostDependencies{
		TunnelEnrollment:          handler,
		TunnelEnrollmentLifecycle: lifecycle,
		TunnelManager:             workloads,
	}
	if got, ok := dependencies.TunnelEnrollment.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("mounted enrollment = %T/%p, want %p", dependencies.TunnelEnrollment, got, service)
	}
	if got, ok := dependencies.TunnelEnrollmentLifecycle.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("mounted lifecycle = %T/%p, want %p", dependencies.TunnelEnrollmentLifecycle, got, service)
	}
	if got, ok := dependencies.TunnelManager.(*ProductionTunnelEnrollment); !ok || got != service {
		t.Fatalf("mounted workload = %T/%p, want %p", dependencies.TunnelManager, got, service)
	}
}

// TestWindowsProductionHostSourceKeepsAllEnrollmentAssignments protects the
// two production branches in production_unix.go. Constructing a full
// production Host requires a real enrolled machine and server, so this source
// contract test makes omission of the lifecycle assignment fail deterministically
// at review time rather than relying on an external enrollment environment.
func TestWindowsProductionHostSourceKeepsAllEnrollmentAssignments(t *testing.T) {
	const sourcePath = "production_unix.go"
	file, err := parser.ParseFile(token.NewFileSet(), sourcePath, productionHostSource, 0)
	if err != nil {
		t.Fatalf("parse production host source: %v", err)
	}

	want := map[string]int{
		"TunnelEnrollment":          2,
		"TunnelEnrollmentLifecycle": 2,
		"TunnelManager":             2,
	}
	got := map[string]int{}
	ast.Inspect(file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		field, ok := dependencyField(assignment.Lhs[0])
		if !ok {
			return true
		}
		if !validEnrollmentAssignment(field, assignment.Rhs[0]) {
			return true
		}
		got[field]++
		return true
	})
	for field, expected := range want {
		if got[field] != expected {
			t.Fatalf("production host %s assignments = %d, want %d (got %#v)", field, got[field], expected, got)
		}
	}
}

func dependencyField(expression ast.Expr) (string, bool) {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	owner, ok := selector.X.(*ast.Ident)
	if !ok || owner.Name != "dependencies" {
		return "", false
	}
	return selector.Sel.Name, true
}

func validEnrollmentAssignment(field string, expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	if identifier != nil {
		return ok && identifier.Name == "tunnelEnrollment" && field != "TunnelEnrollmentLifecycle"
	}
	call, ok := expression.(*ast.CallExpr)
	if !ok || field != "TunnelEnrollmentLifecycle" || len(call.Args) != 1 {
		return false
	}
	function, ok := call.Fun.(*ast.Ident)
	argument, argumentOK := call.Args[0].(*ast.Ident)
	return ok && argumentOK && function.Name == "platformTunnelEnrollmentLifecycle" && argument.Name == "tunnelEnrollment"
}

type windowsCompositionMachineAuth struct{}

func (windowsCompositionMachineAuth) Token(context.Context) (string, error) {
	return "windows-composition-token", nil
}

func (windowsCompositionMachineAuth) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("windows-composition-proof"), nil
}

type windowsCompositionActivator struct{}

func (windowsCompositionActivator) Activate(context.Context, tunnelenrollment.ActivationRequest) (tunnelenrollment.Projection, error) {
	return tunnelenrollment.Projection{}, errors.New("activation is not part of composition identity test")
}
