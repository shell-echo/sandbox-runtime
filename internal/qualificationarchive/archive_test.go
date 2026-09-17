package qualificationarchive

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndExtractDeterministicClosedArchive(t *testing.T) {
	root := t.TempDir()
	for _, name := range EvidenceFiles() {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{\"file\":\""+name+"\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first := filepath.Join(t.TempDir(), "evidence.tar")
	second := filepath.Join(t.TempDir(), "evidence.tar")
	one, err := Create(context.Background(), root, first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Create(context.Background(), root, second)
	if err != nil {
		t.Fatal(err)
	}
	if one.Digest != two.Digest || one.Bytes != two.Bytes || one.Files != 7 {
		t.Fatalf("archive results differ: %+v %+v", one, two)
	}
	destination := filepath.Join(t.TempDir(), "extracted")
	extracted, err := Extract(context.Background(), first, destination)
	if err != nil {
		t.Fatal(err)
	}
	if extracted.Digest != one.Digest || extracted.Bytes != one.Bytes || extracted.Files != one.Files {
		t.Fatalf("extract result = %+v, want %+v", extracted, one)
	}
	for _, name := range EvidenceFiles() {
		contents, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || string(contents) != "{\"file\":\""+name+"\"}\n" {
			t.Fatalf("%s = %q, %v", name, contents, err)
		}
	}
}

func TestExtractRejectsChangedOrUnexpectedArchive(t *testing.T) {
	root := t.TempDir()
	for _, name := range EvidenceFiles() {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "evidence.tar")
	if _, err := Create(context.Background(), root, archive); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(archive, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("changed"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(context.Background(), archive, filepath.Join(t.TempDir(), "extracted")); err == nil {
		t.Fatal("changed archive was accepted")
	}
}
