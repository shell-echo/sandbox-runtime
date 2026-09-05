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
	for _, relative := range []string{
		"internal/caller", "cmd/caller", "cmd/browser-caller", "cmd/shared-capacity-caller",
		"internal/durablerevocation/caller", "cmd/durable-revocation-caller",
		"internal/platform", "cmd/platform-caller",
	} {
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
	assertNoProviderDependency(t, "./cmd/shared-capacity-caller")
}

func TestDurableRevocationCallerHasNoProviderDependency(t *testing.T) {
	assertNoProviderDependency(t, "./cmd/durable-revocation-caller")
}

func TestDurableRevocationRevokerUsesOnlyExportedRevocationPorts(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/durable-revocation-revoker")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list durable-revocation revoker dependencies: %v: %s", err, strings.TrimSpace(string(output)))
	}
	allowed := map[string]bool{
		"github.com/shell-echo/sandbox-runtime/gateway":                  true,
		"github.com/shell-echo/sandbox-runtime/gateway/revocation/redis": true,
	}
	for _, dependency := range strings.Fields(string(output)) {
		if providerPackage(dependency) && !allowed[dependency] {
			t.Errorf("durable-revocation revoker transitively imports Provider package %q outside its exported allowlist", dependency)
		}
	}
}

func TestDownstreamFencingGatewayUsesOnlyNarrowProviderTypes(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/downstream-fencing-gateway")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list downstream-fencing Gateway dependencies: %v: %s", err, strings.TrimSpace(string(output)))
	}
	allowedProviderTypes := map[string]bool{
		"github.com/shell-echo/sandbox-runtime/provider/browser":           true,
		"github.com/shell-echo/sandbox-runtime/provider/browser/reference": true,
		// The shared composition package also declares the terminal narrow
		// Endpoint/Stream adapters; none provides repository or driver access.
		"github.com/shell-echo/sandbox-runtime/provider/session":           true,
		"github.com/shell-echo/sandbox-runtime/provider/session/reference": true,
		"github.com/shell-echo/sandbox-runtime/provider/terminal":          true,
	}
	for _, dependency := range strings.Fields(string(output)) {
		if strings.HasPrefix(dependency, "github.com/shell-echo/sandbox-runtime/provider/") && !allowedProviderTypes[dependency] {
			t.Errorf("downstream-fencing Gateway imports Provider implementation package %q outside its narrow type allowlist", dependency)
		}
		if strings.HasPrefix(dependency, "github.com/moby/") || strings.HasPrefix(dependency, "github.com/containerd/") {
			t.Errorf("downstream-fencing Gateway imports container runtime package %q", dependency)
		}
	}
}

func assertNoProviderDependency(t *testing.T, packagePath string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", packagePath)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %s dependencies: %v: %s", packagePath, err, strings.TrimSpace(string(output)))
	}
	for _, dependency := range strings.Fields(string(output)) {
		if providerPackage(dependency) {
			t.Errorf("%s transitively imports Provider implementation package %q", packagePath, dependency)
		}
	}
}

func providerPackage(importPath string) bool {
	return importPath == "github.com/shell-echo/sandbox-runtime" ||
		strings.HasPrefix(importPath, "github.com/shell-echo/sandbox-runtime/")
}
