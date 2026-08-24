package session

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

type authoritySpy struct{}

func (authoritySpy) ReserveOpen(context.Context, OpenRequest, time.Time) (Reservation, error) {
	return Reservation{}, nil
}

func (authoritySpy) GetOpen(context.Context, string) (Record, error) { return Record{}, nil }

func (authoritySpy) UpdateOpen(context.Context, Record, Status) error { return nil }

var _ Authority = authoritySpy{}

func TestSessionPackageDoesNotImportTransportPersistenceOrRuntimePackages(t *testing.T) {
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
			if strings.Contains(path, "github.com/shell-echo/sandbox-runtime/") {
				t.Fatalf("%s imports repository package %q", entry.Name(), path)
			}
		}
	}
}
