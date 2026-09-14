package evidencefiles

import (
	"strings"
	"testing"
)

func TestDigestEntriesValidatesAndDoesNotMutate(t *testing.T) {
	entries := []Entry{
		{Path: "z", Bytes: 1, SHA256: "sha256:" + strings.Repeat("b", 64)},
		{Path: "a", Bytes: 0, SHA256: "sha256:" + strings.Repeat("a", 64)},
	}
	if _, err := DigestEntries(entries); err != nil {
		t.Fatalf("DigestEntries() error = %v", err)
	}
	if entries[0].Path != "z" {
		t.Fatalf("DigestEntries mutated caller entries: %#v", entries)
	}
	invalid := []Entry{
		{Path: "a", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		{Path: "a", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
	}
	if _, err := DigestEntries(invalid); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("DigestEntries(duplicate) error = %v", err)
	}
	for _, entry := range []Entry{
		{Path: "../a", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		{Path: "nested/a", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		{Path: "a", Bytes: -1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		{Path: "a", Bytes: 1, SHA256: "sha256:" + strings.Repeat("A", 64)},
		{Path: strings.Repeat("a", MaxPathRunes+1), Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		{Path: "a\x7fb", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
	} {
		if _, err := DigestEntries([]Entry{entry}); err == nil {
			t.Errorf("DigestEntries(%#v) accepted invalid entry", entry)
		}
	}
}

func TestDigestEntriesUsesCanonicalArrayBytes(t *testing.T) {
	entries := []Entry{
		{Path: "z", Bytes: 1, SHA256: "sha256:" + strings.Repeat("b", 64)},
		{Path: "a", Bytes: 0, SHA256: "sha256:" + strings.Repeat("a", 64)},
	}
	got, err := DigestEntries(entries)
	if err != nil {
		t.Fatalf("DigestEntries() error = %v", err)
	}
	const want = "sha256:09014a1f1684575b65b2b4bbf6e09ee7770cd886ea9159976f4c14e2ec788edb"
	if got != want {
		t.Fatalf("DigestEntries() = %q, want %q", got, want)
	}
}
