package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
)

func TestCompositionFileRejectsUnknownDuplicateAndNoncanonicalInput(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath, outputPath := filepath.Join(directory, "input.json"), filepath.Join(directory, "profile.json")
	for _, document := range [][]byte{
		[]byte(`{"schema_version":"` + inputSchema + `","unexpected":true}`),
		[]byte(`{"schema_version":"` + inputSchema + `","schema_version":"` + inputSchema + `"}`),
		[]byte(`{ "schema_version": "` + inputSchema + `" }`),
	} {
		if err := os.WriteFile(inputPath, document, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(context.Background(), inputPath, outputPath, time.Now().UTC()); !errors.Is(err, errInvalidInput) {
			t.Fatalf("invalid composition admitted: %v", err)
		}
		if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid input wrote an output")
		}
	}
	canonical, err := json.Marshal(compositionFile{SchemaVersion: inputSchema})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), inputPath, outputPath, time.Now().UTC()); !errors.Is(err, errInvalidInput) && !errors.Is(err, phase6profilebuilder.ErrInvalidComposition) {
		t.Fatalf("incomplete canonical source admitted: %v", err)
	}
}

func TestCompositionOutputDoesNotOverwriteOrLeaveInvalidFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "profile.json")
	if err := writeExclusive(outputPath, []byte(`{}`)); !errors.Is(err, errInvalidInput) {
		t.Fatal("invalid profile document accepted")
	}
	if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid output file remained")
	}
	if err := os.WriteFile(outputPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(outputPath, []byte(`{}`)); !errors.Is(err, errInvalidInput) {
		t.Fatal("existing output was overwritten")
	}
	if data, err := os.ReadFile(outputPath); err != nil || string(data) != "existing" {
		t.Fatal("existing output changed")
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if privateParent(outputPath) {
		t.Fatal("public parent admitted")
	}
}
