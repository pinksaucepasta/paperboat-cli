package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalDaemonCommandWiresAutomaticPeerEnrollmentApproval(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	mainPath := filepath.Join(filepath.Dir(testFile), "main.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), mainPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var commandBody *ast.BlockStmt
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "localDaemonCommand" {
			commandBody = function.Body
			break
		}
	}
	if commandBody == nil {
		t.Fatal("localDaemonCommand production entry point was not found")
	}

	wiringAssignments := 0
	validApprovalCall := false
	diagnosticAssignments := 0
	validDiagnosticReporter := false
	ast.Inspect(commandBody, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		left, ok := assignment.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		source, ok := left.X.(*ast.Ident)
		if !ok || source.Name != "source" {
			return true
		}
		if left.Sel.Name == "ReportPeerApprovalSignerUnavailable" {
			diagnosticAssignments++
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 3 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "RateLimitedPeerApprovalReporter" {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if !ok || qualifier.Name != "localdaemon" {
				return true
			}
			callback, ok := call.Args[2].(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(callback.Body, func(node ast.Node) bool {
				report, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				function, ok := report.Fun.(*ast.SelectorExpr)
				if !ok || function.Sel.Name != "TryInfo" {
					return true
				}
				pkg, ok := function.X.(*ast.Ident)
				validDiagnosticReporter = ok && pkg.Name == "diagnosticlog"
				return !validDiagnosticReporter
			})
			return true
		}
		if left.Sel.Name != "AutoApprovePeerEnrollments" {
			return true
		}
		wiringAssignments++
		callback, ok := assignment.Rhs[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(callback.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 5 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ApproveOwnedPeerEnrollments" {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if !ok || qualifier.Name != "localdaemon" {
				return true
			}
			want := []string{"ctx", "store", "profile", "client", "machines"}
			for index, argument := range call.Args {
				identifier, ok := argument.(*ast.Ident)
				if !ok || identifier.Name != want[index] {
					return true
				}
			}
			validApprovalCall = true
			return false
		})
		return true
	})

	if wiringAssignments != 1 || !validApprovalCall || diagnosticAssignments != 1 || !validDiagnosticReporter {
		t.Fatalf("production daemon approval wiring assignments=%d valid_call=%t diagnostic_assignments=%d valid_diagnostic=%t", wiringAssignments, validApprovalCall, diagnosticAssignments, validDiagnosticReporter)
	}
}
