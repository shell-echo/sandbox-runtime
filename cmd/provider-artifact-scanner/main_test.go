package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestScannerConfigStrictFraming(t *testing.T) {
	c := configDocument{Protocol: scannerConfigProtocol, OperationTimeoutSeconds: 5, RuleManifest: []byte("{}")}
	document, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeConfig(document); err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{nil, append(bytes.Clone(document), '\n'), append(bytes.Clone(document), document...), append([]byte(`{"unknown":1,`), document[1:]...), bytes.Repeat([]byte(" "), (256<<10)+1)}
	duplicate := append([]byte(`{"protocol":"`+scannerConfigProtocol+`",`), document[1:]...)
	cases = append(cases, duplicate)
	for _, data := range cases {
		if _, err := decodeConfig(data); err == nil {
			t.Fatal("noncanonical configuration accepted")
		}
	}
}

func TestScannerCommandRetainsV2HoldBeforeSideEffects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	profile, err := json.Marshal(phase6security.ProfileV2{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, profile, 0600); err != nil {
		t.Fatal(err)
	}
	c := configDocument{Protocol: scannerConfigProtocol, SecurityProfilePath: path, OperationTimeoutSeconds: 5, RuleManifest: []byte("{}"), AgentSocket: filepath.Join(dir, "absent-agent.sock")}
	document, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), bytes.NewReader(document)); err == nil {
		t.Fatal("held profile admitted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed preflight created runtime artifacts", err)
	}
	if err := run(nil, bytes.NewReader(document)); err == nil {
		t.Fatal("nil lifetime admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, bytes.NewReader(document)); err == nil {
		t.Fatal("cancelled lifetime admitted")
	}
}
