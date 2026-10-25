//go:build !darwin && !linux

package artifactscanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuleCustodyRefusesUnsupportedPlatform(t *testing.T) {
	directory := t.TempDir()
	var files []RuleFile
	for _, name := range []string{"bytecode.cvd", "daily.cvd", "main.cvd"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, RuleFile{Name: name, Version: 1, SizeBytes: 1, Digest: scanDigest([]byte("x"))})
	}
	if !errors.Is(verifyRuleDirectory(t.Context(), directory, files), ErrRulesUnavailable) {
		t.Fatal("unsupported native custody admitted valid rule files")
	}
}
