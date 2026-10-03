//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is the E-only producer/consumer gate for the frozen runtime source.
// It derives the stage set from R9's actual Go declaration and verifies the
// formatter's switch before checking the independent bounded observer.
func TestSlice6FrozenMigrationStagesMatchBoundedObserver(t *testing.T) {
	root := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	revision := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")
	if root == "" && revision == "" {
		t.Skip("set the exact clean runtime source and revision for producer-consumer validation")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if root == "" || revision == "" || verifyCleanSlice6Source(ctx, root, revision) != nil {
		t.Fatal("frozen runtime producer source is unavailable")
	}
	path := filepath.Join(root, "cmd", "product_postgres_v3.go")
	source, err := os.ReadFile(path)
	if err != nil || len(source) == 0 || len(source) > 64<<10 {
		t.Fatal("bounded frozen migration producer is unavailable")
	}
	stages, err := slice6FrozenMigrationStageSet(source)
	if err != nil || len(stages) != 13 {
		t.Fatalf("frozen migration stage set is not closed: %v", err)
	}
	classSource, err := os.ReadFile(filepath.Join(root, "internal", "phase6tls", "peercrl_failure.go"))
	if err != nil || len(classSource) == 0 || len(classSource) > 16<<10 {
		t.Fatal("bounded frozen peer failure producer is unavailable")
	}
	classes, err := slice6FrozenPeerFailureClassSet(classSource)
	if err != nil || len(classes) != 11 ||
		strings.Count(string(source), "closedMigrationPeerClass(startup.peerClass)") != 1 {
		t.Fatalf("frozen peer failure projection is not closed: %v", err)
	}
	for _, class := range classes {
		line := "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=" + class
		if got := slice6MigrationFailureCategory([]byte(line + "\n")); got != "migration-connect-peer-bootstrap-"+class {
			t.Fatalf("frozen peer class %q is not observable: %q", class, got)
		}
	}
	for _, stage := range stages {
		line := "migration v2 PostgreSQL connection is unavailable: stage=" + stage
		want := "migration-connect-" + stage
		if stage == "peer-bootstrap" {
			line += ": class=unknown"
			want += "-unknown"
		}
		if got := slice6MigrationFailureCategory([]byte(line + "\n")); got != want {
			t.Fatalf("frozen producer stage %q is not observable: %q", stage, got)
		}
		for _, bad := range []string{
			"prefix " + line, line + " suffix", line + "\n" + line,
			line + "\r\n", line + "\x00", line + "\npassword=private\n",
		} {
			if got := slice6MigrationFailureCategory([]byte(bad)); got != "unknown" {
				t.Fatalf("noncanonical stage output admitted: %q", got)
			}
		}
	}
	for _, bad := range []string{
		"migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap",
		"migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=controller-denied",
		"migration v2 PostgreSQL connection is unavailable: stage=unknown",
		"migration v2 PostgreSQL connection is unavailable: stage=tls-client",
		"migration v2 PostgreSQL connection is unavailable: stage=dsn-binding",
		"migration v2 PostgreSQL connection is unavailable: stage=authority authority",
		strings.Repeat("x", 513),
		"postgres://role:password@hidden.example/db",
	} {
		if got := slice6MigrationFailureCategory([]byte(bad)); got != "unknown" {
			t.Fatalf("unreviewed migration output admitted: %q", got)
		}
	}
	if got := slice6MigrationFailureCategory([]byte("migration v2 PostgreSQL connection is unavailable\n")); got != "migration-connect" {
		t.Fatal("legacy generic migration category regressed")
	}
}

func slice6FrozenPeerFailureClassSet(source []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "peercrl_failure.go", source, 0)
	if err != nil {
		return nil, err
	}
	var classes []string
	seen := make(map[string]bool)
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, specification := range group.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || !strings.HasPrefix(value.Names[0].Name, "PeerCRL") ||
				!strings.HasSuffix(value.Names[0].Name, "Failure") {
				continue
			}
			if len(value.Values) != 1 {
				return nil, errors.New("peer failure class has no exact literal")
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return nil, errors.New("peer failure class is not a literal")
			}
			class, decodeErr := strconv.Unquote(literal.Value)
			if decodeErr != nil || class == "" || len(class) > 32 || seen[class] {
				return nil, errors.New("peer failure class is invalid")
			}
			seen[class] = true
			classes = append(classes, class)
		}
	}
	return classes, nil
}

func slice6FrozenMigrationStageSet(source []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "product_postgres_v3.go", source, 0)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, specification := range group.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || !strings.HasPrefix(value.Names[0].Name, "postgresStage") {
				continue
			}
			if len(value.Values) != 1 {
				return nil, errors.New("migration stage has no exact literal")
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return nil, errors.New("migration stage is not a string literal")
			}
			decoded, decodeErr := strconv.Unquote(literal.Value)
			if decodeErr != nil || decoded == "" || len(decoded) > 48 || values[value.Names[0].Name] != "" {
				return nil, errors.New("migration stage literal is invalid")
			}
			values[value.Names[0].Name] = decoded
		}
	}
	if len(values) != 13 {
		return nil, errors.New("migration stage constant count drift")
	}
	var switchNames []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "migrationPostgresConnectError" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, ok := node.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			tag, ok := statement.Tag.(*ast.SelectorExpr)
			if !ok || tag.Sel.Name != "stage" {
				return true
			}
			for _, item := range statement.Body.List {
				clause := item.(*ast.CaseClause)
				for _, expression := range clause.List {
					name, ok := expression.(*ast.Ident)
					if !ok {
						switchNames = append(switchNames, "invalid")
						continue
					}
					switchNames = append(switchNames, name.Name)
				}
			}
			return false
		})
	}
	if len(switchNames) != len(values) ||
		strings.Count(string(source), `generic + ": stage=" + string(startup.stage)`) != 1 ||
		strings.Count(string(source), `generic = "migration v2 PostgreSQL connection is unavailable"`) != 1 {
		return nil, errors.New("migration stage formatter is not the reviewed closed projection")
	}
	seen := make(map[string]bool, len(values))
	seenValues := make(map[string]bool, len(values))
	stages := make([]string, 0, len(values))
	for _, name := range switchNames {
		stage := values[name]
		if stage == "" || seen[name] || seenValues[stage] {
			return nil, errors.New("migration stage formatter drift")
		}
		seen[name] = true
		seenValues[stage] = true
		stages = append(stages, stage)
	}
	return stages, nil
}

func TestSlice6MigrationStageUsesActualBoundedCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	candidates := []struct {
		stdout, stderr, category string
	}{
		{"", "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=unknown\n", "migration-connect-peer-bootstrap-unknown"},
		{"extra stdout\n", "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=unknown\n", "unknown"},
		{"", "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=unknown\nsecond line\n", "unknown"},
		{"", "password=private\n", "unknown"},
	}
	for _, class := range []string{"local-guard", "parent-canceled", "parent-deadline",
		"internal-deadline", "agent-request-build", "agent-socket-peer", "agent-transport",
		"agent-response", "guard-binding", "crl-semantic"} {
		candidates = append(candidates, struct{ stdout, stderr, category string }{
			stderr:   "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class=" + class + "\n",
			category: "migration-connect-peer-bootstrap-" + class,
		})
	}
	for _, candidate := range candidates {
		command := exec.CommandContext(ctx, "sh", "-c", "printf '%s' \"$1\"; printf '%s' \"$2\" >&2; exit 1",
			"stage-capture", candidate.stdout, candidate.stderr)
		captured, err, overflow := slice6CaptureBounded(command, 16<<10, nil)
		if err == nil || overflow || slice6MigrationFailureCategory(captured) != candidate.category {
			clear(captured)
			t.Fatal("actual bounded stdout/stderr collector lost its closed stage category")
		}
		clear(captured)
	}
	command := exec.CommandContext(ctx, "sh", "-c", "printf '%s' \"$1\" >&2; exit 1", "long-capture",
		"migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class="+strings.Repeat("x", 32768))
	captured, err, overflow := slice6CaptureBounded(command, 16<<10, nil)
	if err == nil || !overflow || slice6MigrationFailureCategory(captured) != "unknown" {
		clear(captured)
		t.Fatal("oversized diagnostic escaped strict bounded capture")
	}
	clear(captured)
}
