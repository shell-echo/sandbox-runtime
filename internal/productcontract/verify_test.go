package productcontract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyRepositoryProductContract(t *testing.T) {
	report, err := Verify(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Namespace != "urn:shell-echo:sandbox-runtime:product-v1alpha1" || report.Version != "0.1.0" ||
		report.ResourceCount != 9 || report.OperationCount != 27 || report.ConformanceCases != 3 {
		t.Fatalf("report = %#v", report)
	}
}

func TestVerifyRejectsResourceDrift(t *testing.T) {
	root := copyProductContract(t)
	filename := filepath.Join(root, ContractRoot, "specification", "product-contract-v1alpha1.md")
	if err := os.WriteFile(filename, []byte("drift\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestStrictJSONRejectsDuplicateMembers(t *testing.T) {
	var target map[string]any
	if err := decodeStrictJSON([]byte(`{"key":1,"key":2}`), &target); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
}

func copyProductContract(t *testing.T) string {
	t.Helper()
	source := filepath.Join(repositoryRoot(t), ContractRoot)
	targetRoot := t.TempDir()
	target := filepath.Join(targetRoot, ContractRoot)
	if err := filepath.WalkDir(source, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, filename)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	return targetRoot
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve verifier test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
