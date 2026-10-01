package workloadcredentialv2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerRestartFailsClosedOnCrashResidue(t *testing.T) {
	directory := secureDirectory(t)
	path := filepath.Join(directory, "ledger-v2.json")
	ledger := Ledger{Schema: LedgerSchema, Revision: 1}
	if err := saveLedger(path, ledger); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(directory, ".workload-credential-v2-ledger-abandoned")
	if err := os.WriteFile(residue, []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLedger(path); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("crash residue was admitted on restart: %v", err)
	}
	if err := saveLedger(path, ledger); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("crash residue was admitted before next write: %v", err)
	}
	if _, err := os.Lstat(residue); err != nil {
		t.Fatal("controller silently removed crash evidence")
	}
}
