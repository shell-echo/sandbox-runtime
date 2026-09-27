package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareCanonicalAccounts(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "build-context")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "accounts.json")
	if err := os.WriteFile(source, []byte(`{"schema":"sandbox.runtime/desktop-phase6-workload-accounts/v1","accounts":[{"uid":20000,"gid":30000},{"uid":20001,"gid":30001}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(source, output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "workload.passwd")); err != nil {
		t.Fatal(err)
	}
}
