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
	} {
		var output bytes.Buffer
		if err := run(arguments, &output); err == nil || strings.Contains(output.String(), "verified") {
			t.Fatalf("unsupported or unavailable bundle accepted: %v", arguments)
		}
	}
}
