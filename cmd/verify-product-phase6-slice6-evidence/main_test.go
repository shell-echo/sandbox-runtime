package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSlice6BundleVerifierRejectsMissingAndUnsupportedArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"-manifest", "/tmp/manifest.json"},
		{"-bundle-root", "/tmp/bundle"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle", "extra"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle", "-source-root", "/tmp/source"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle", "-source-root", "/tmp/source", "-role-candidate-dir", "/tmp/roles"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle", "-source-root", "/tmp/source", "-role-candidate-dir", "/tmp/roles", "-desktop-candidate", "/tmp/desktop.json"},
		{"-manifest", "/tmp/manifest.json", "-bundle-root", "/tmp/bundle", "-runtime-source-root", "/tmp/runtime", "-evidence-source-root", "/tmp/evidence", "-role-candidate-dir", "/tmp/roles", "-desktop-candidate", "/tmp/desktop.json"},
	} {
		var output bytes.Buffer
		if err := run(arguments, &output); err == nil || strings.Contains(output.String(), "verified") {
			t.Fatalf("unsupported or unavailable bundle accepted: %v", arguments)
		}
	}
}
