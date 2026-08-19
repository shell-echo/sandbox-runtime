package admission

import (
	"context"
	"crypto"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAlgorithmSupported(t *testing.T) {
	tests := map[Algorithm]bool{
		AlgorithmEdDSA: true,
		AlgorithmES256: true,
		"none":         false,
		"RS256":        false,
		"":             false,
	}
	for algorithm, want := range tests {
		if got := algorithm.Supported(); got != want {
			t.Fatalf("%q Supported() = %t, want %t", algorithm, got, want)
		}
	}
}

func TestMutationGuardRequestDoesNotExposeRawJTI(t *testing.T) {
	fields := mutationGuardRequestFields(t)
	for _, field := range fields {
		for _, name := range field.Names {
			if strings.EqualFold(name.Name, "jti") {
				t.Fatalf("MutationGuardRequest exposes raw JTI field %q", name.Name)
			}
		}
	}
}

func TestAdmissionPortsDoNotImportTransportOrRuntimePackages(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		for _, importSpec := range file.Imports {
			path := strings.Trim(importSpec.Path.Value, "\"")
			if strings.Contains(path, "/driver") || strings.Contains(path, "/instance") || strings.Contains(path, "/server") || strings.Contains(path, "/providerapi") {
				t.Fatalf("%s imports forbidden package %q", entry.Name(), path)
			}
		}
	}
}

func mutationGuardRequestFields(t *testing.T) []*ast.Field {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "port.go", nil, 0)
	if err != nil {
		t.Fatalf("parse port.go: %v", err)
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "MutationGuardRequest" {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatal("MutationGuardRequest is not a struct")
			}
			return structure.Fields.List
		}
	}
	t.Fatal("MutationGuardRequest declaration not found")
	return nil
}

type trustedKeySourceSpy struct{}

func (trustedKeySourceSpy) Lookup(context.Context, KeyID, Algorithm) (crypto.PublicKey, error) {
	return nil, nil
}

type clockSpy struct{}

func (clockSpy) Now() time.Time { return time.Unix(0, 0).UTC() }

type mutationGuardSpy struct{}

func (mutationGuardSpy) Reserve(context.Context, MutationGuardRequest) (MutationGuardDecision, error) {
	return MutationGuardAccepted, nil
}

var (
	_ TrustedKeySource = trustedKeySourceSpy{}
	_ Clock            = clockSpy{}
	_ MutationGuard    = mutationGuardSpy{}
)
