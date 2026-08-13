package contracttest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	noiseImport      = "github.com/flynn/noise"
	relayNoiseImport = "github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

func TestNoiseOwnershipBoundary(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal", "peertransport"))
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		packageDirectory := filepath.ToSlash(filepath.Dir(relative))
		noiseAlias := ""
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			switch importPath {
			case noiseImport:
				if packageDirectory != "relaynoise" && packageDirectory != "relaycarrier" {
					t.Errorf("%s imports Noise outside relay ownership", relative)
				}
				if imported.Name != nil {
					if imported.Name.Name == "." || imported.Name.Name == "_" {
						t.Errorf("%s uses forbidden Noise import form %q", relative, imported.Name.Name)
					} else {
						noiseAlias = imported.Name.Name
					}
				} else {
					noiseAlias = "noise"
				}
			case relayNoiseImport:
				if packageDirectory != "relaycarrier" {
					t.Errorf("%s imports relay Noise outside relay carrier ownership", relative)
				}
			}
		}

		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "UnsafeKey", "SetNonce":
				t.Errorf("%s uses forbidden Noise cipher-state API %s", relative, selector.Sel.Name)
			}
			identifier, qualified := selector.X.(*ast.Ident)
			if !qualified || noiseAlias == "" || identifier.Name != noiseAlias {
				return true
			}
			switch selector.Sel.Name {
			case "UnsafeNewCipherState":
				t.Errorf("%s uses forbidden Noise cipher-state constructor", relative)
			case "NewCipherSuite", "NewHandshakeState":
				if packageDirectory != "relaynoise" {
					t.Errorf("%s constructs Noise state outside relaynoise", relative)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
