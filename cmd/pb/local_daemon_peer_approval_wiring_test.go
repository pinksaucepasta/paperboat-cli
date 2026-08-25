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
	ast.Inspect(commandBody, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		left, ok := assignment.Lhs[0].(*ast.SelectorExpr)
		if !ok || left.Sel.Name != "AutoApprovePeerEnrollments" {
			return true
		}
		source, ok := left.X.(*ast.Ident)
		if !ok || source.Name != "source" {
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

	if wiringAssignments != 1 || !validApprovalCall {
		t.Fatalf("production daemon approval wiring assignments=%d valid_call=%t", wiringAssignments, validApprovalCall)
	}
}
