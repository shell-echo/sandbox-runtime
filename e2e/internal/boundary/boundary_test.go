package boundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBlackBoxCallerDoesNotImportProviderImplementation(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"internal/caller", "cmd/caller"} {
		path := filepath.Join(root, relative)
		matches, err := filepath.Glob(filepath.Join(path, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			parsed, err := parser.ParseFile(token.NewFileSet(), match, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imported := range parsed.Imports {
				value, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if value == "github.com/shell-echo/sandbox-runtime" || strings.HasPrefix(value, "github.com/shell-echo/sandbox-runtime/") {
					t.Errorf("%s imports Provider implementation package %q", match, value)
				}
			}
			ast.Inspect(parsed, func(ast.Node) bool { return true })
		}
	}
}
