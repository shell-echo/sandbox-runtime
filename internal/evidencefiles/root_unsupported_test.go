//go:build !darwin && !linux

package evidencefiles

import "testing"

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	wantError := unsupportedPlatformMessage
	assertError := func(name string, err error) {
		t.Helper()
		if err == nil || err.Error() != wantError {
			t.Fatalf("%s error = %v, want %q", name, err, wantError)
		}
	}

	rootPath := t.TempDir()
	opened, err := OpenRoot(rootPath)
	assertError("OpenRoot", err)
	if opened != nil {
		t.Fatalf("OpenRoot root = %#v, want nil", opened)
	}
	if _, err := Read(rootPath, nil, DefaultOptions()); err == nil || err.Error() != wantError {
		t.Fatalf("Read error = %v, want %q", err, wantError)
	}

	root := &Root{}
	if err := root.Close(); err != nil {
		t.Fatalf("Root.Close error = %v, want nil", err)
	}
	_, err = root.Read(nil, DefaultOptions())
	assertError("Root.Read", err)
	_, err = root.ReadFile("report.json", 1)
	assertError("Root.ReadFile", err)
	publication, err := root.Publish("receipt.json", nil, 1)
	assertError("Root.Publish", err)
	if publication != nil {
		t.Fatalf("Root.Publish publication = %#v, want nil", publication)
	}

	publication = &Publication{}
	if got := publication.Path(); got != "" {
		t.Fatalf("Publication.Path = %q, want empty", got)
	}
	if got := publication.Size(); got != 0 {
		t.Fatalf("Publication.Size = %d, want 0", got)
	}
	_, err = publication.Read(1)
	assertError("Publication.Read", err)
	assertError("Publication.Commit", publication.Commit("receipt.json"))
	assertError("Publication.Remove", publication.Remove())
}
