package productwebclient

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckedInClientMatchesLockedProductOpenAPI(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	openAPI, err := os.ReadFile(filepath.Join(root, "product-contract", "openapi", "sandbox-runtime-product-v1alpha1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := Generate(openAPI)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(root, "productweb", "assets", "client.generated.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("checked-in browser client is stale; run go generate ./productweb")
	}
}
