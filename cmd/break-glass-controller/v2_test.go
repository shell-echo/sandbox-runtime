package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
)

func TestV2ControllerPreflightRefusesUnboundSourcesBeforeLedger(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(root, "ledger.json")
	config := configDocumentV2{Protocol: configProtocolV2, SecurityProfilePath: filepath.Join(root, "missing-profile.json"),
		LedgerPath: ledger, AuditPath: filepath.Join(root, "audit.ndjson"), MaxTTLSeconds: 300}
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{document, append(bytes.Clone(document), '\n'),
		bytes.Replace(document, []byte(`"max_ttl_seconds":300`), []byte(`"max_ttl_seconds":300,"max_ttl_seconds":300`), 1),
		bytes.Replace(document, []byte(`"actors":null`), []byte(`"actors":null,"extra":true`), 1)} {
		if _, err := prepareV2(input); err == nil {
			t.Fatal("invalid or unbound v2 controller admitted")
		}
		if _, err := os.Lstat(ledger); !os.IsNotExist(err) {
			t.Fatal("failed preflight created ledger")
		}
	}
	if v2BusinessKind("target") != breakglass.ActorTarget || v2BusinessKind("approver") != breakglass.ActorApprover {
		t.Fatal("v2 Profile kind did not map to unchanged signed business actor kind")
	}
}
