package boundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
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
	for _, relative := range []string{"internal/caller", "cmd/caller", "cmd/browser-caller", "cmd/shared-capacity-caller", "internal/platform", "cmd/platform-caller"} {
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

func TestSharedCapacityCallerHasNoProviderDependency(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/shared-capacity-caller")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list shared-capacity caller dependencies: %v: %s", err, strings.TrimSpace(string(output)))
	}
	for _, dependency := range strings.Fields(string(output)) {
		if dependency == "github.com/shell-echo/sandbox-runtime" || strings.HasPrefix(dependency, "github.com/shell-echo/sandbox-runtime/") {
			t.Errorf("shared-capacity caller transitively imports Provider implementation package %q", dependency)
		}
	}
}
