package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestDerivationRejectsMissingOrUnsafeAuthorityBeforeOutput(t *testing.T) {
	directory := t.TempDir()
	for name, arguments := range map[string][]string{
		"missing": nil,
		"relative output": {"-profile", filepath.Join(directory, "profile.json"),
			"-profile-digest", "sha256:invalid", "-sources", filepath.Join(directory, "sources.json"),
			"-sources-digest", "sha256:invalid", "-principal-digest", "sha256:invalid", "-output", "role.json"},
		"newline output": {"-profile", filepath.Join(directory, "profile.json"),
			"-profile-digest", "sha256:invalid", "-sources", filepath.Join(directory, "sources.json"),
			"-sources-digest", "sha256:invalid", "-principal-digest", "sha256:invalid",
			"-output", filepath.Join(directory, "role\n.json")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe role derivation accepted")
			}
		})
	}
}
