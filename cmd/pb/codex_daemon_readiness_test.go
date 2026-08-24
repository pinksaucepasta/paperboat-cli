package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
)

func TestRequireCodexLocalDaemonForPlatformUsesWindowsOnly(t *testing.T) {
	cfg := &config.Config{}
	sentinel := errors.New("readiness sentinel")
	calls := 0
	require := func(gotCtx context.Context, gotCfg *config.Config) error {
		calls++
		if gotCtx != context.Background() || gotCfg != cfg {
			t.Fatalf("readiness arguments ctx=%v cfg=%p, want background/%p", gotCtx, gotCfg, cfg)
		}
		return sentinel
	}

	if err := requireCodexLocalDaemonForPlatform(context.Background(), cfg, "windows", require); !errors.Is(err, sentinel) {
		t.Fatalf("Windows readiness error=%v", err)
	}
	if calls != 1 {
		t.Fatalf("Windows readiness calls=%d, want 1", calls)
	}
	for _, platform := range []string{"darwin", "linux"} {
		if err := requireCodexLocalDaemonForPlatform(context.Background(), cfg, platform, func(context.Context, *config.Config) error {
			t.Fatalf("%s Codex unexpectedly required the Windows local daemon", platform)
			return nil
		}); err != nil {
			t.Fatalf("%s readiness error=%v", platform, err)
		}
	}
	if err := requireCodexLocalDaemonForPlatform(context.Background(), cfg, "windows", nil); !errors.Is(err, localdaemon.ErrInvalidInventoryConfig) {
		t.Fatalf("nil Windows readiness error=%v", err)
	}
}

func TestActionCodexWiresWindowsReadinessBeforeBackendSession(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var action *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "actionCodex" {
			action = function
			break
		}
	}
	if action == nil {
		t.Fatal("actionCodex declaration is missing")
	}

	var readinessCall, backendCall, sessionCall *ast.CallExpr
	readinessCalls := 0
	ast.Inspect(action.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch calledFunction(call) {
		case "requireCodexLocalDaemonForPlatform":
			readinessCalls++
			readinessCall = call
		case "api.New":
			backendCall = call
		case "codexsession.Run":
			sessionCall = call
		}
		return true
	})
	if readinessCalls != 1 || readinessCall == nil || backendCall == nil || sessionCall == nil {
		t.Fatalf("actionCodex calls readiness/backend/session=%d/%t/%t, want 1/true/true", readinessCalls, backendCall != nil, sessionCall != nil)
	}
	if readinessCall.Pos() >= backendCall.Pos() || readinessCall.Pos() >= sessionCall.Pos() {
		t.Fatalf("Codex readiness at %d must precede backend/session at %d/%d", readinessCall.Pos(), backendCall.Pos(), sessionCall.Pos())
	}
	if len(readinessCall.Args) != 4 || calledFunctionExpr(readinessCall.Args[2]) != "runtime.GOOS" || calledFunctionExpr(readinessCall.Args[3]) != "requireLocalDaemonService" {
		t.Fatalf("actionCodex readiness arguments do not bind runtime.GOOS to requireLocalDaemonService")
	}

	errorGated := false
	for _, statement := range action.Body.List {
		ifStatement, ok := statement.(*ast.IfStmt)
		if !ok || ifStatement.Init == nil {
			continue
		}
		containsReadiness := false
		ast.Inspect(ifStatement.Init, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && call == readinessCall {
				containsReadiness = true
			}
			return true
		})
		if containsReadiness && len(ifStatement.Body.List) == 1 {
			_, errorGated = ifStatement.Body.List[0].(*ast.ReturnStmt)
		}
	}
	if !errorGated {
		t.Fatal("actionCodex readiness failure does not return before backend session creation")
	}
}

func calledFunction(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	return calledFunctionExpr(call.Fun)
}

func calledFunctionExpr(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := calledFunctionExpr(value.X)
		if prefix == "" {
			return value.Sel.Name
		}
		return prefix + "." + value.Sel.Name
	default:
		return ""
	}
}
