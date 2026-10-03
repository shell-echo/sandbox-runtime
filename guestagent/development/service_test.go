package development

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceMaterializesExactWorkspaceAndReportsHealth(t *testing.T) {
	workspace, state := testRoots(t)
	identity := filepath.Join(workspace, StorageIdentityFileName)
	if err := os.WriteFile(identity, []byte("operator-owned-volume"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateIdentity := filepath.Join(state, StorageIdentityFileName)
	if err := os.WriteFile(stateIdentity, []byte("operator-owned-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := testService(t, workspace, state)
	content := []byte("package main\n")
	request := PrepareRequest{
		StartupID: "dev-test", TemplateRevision: digestOf("template"), WorkspaceRevision: "rev-test", ManifestDigest: digestOf("manifest"),
		Entries: []Entry{{Path: "src", Type: "directory", Mode: 0o750}, {Path: "src/main.go", Type: "file", Mode: 0o640, SizeBytes: int64(len(content)), Digest: digestOf(string(content))}},
	}
	if err := service.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Write(context.Background(), WriteRequest{StartupID: request.StartupID, Path: "src/main.go", Offset: 0, Data: content[:4]}); err != nil {
		t.Fatal(err)
	}
	if err := service.Write(context.Background(), WriteRequest{StartupID: request.StartupID, Path: "src/main.go", Offset: 4, Data: content[4:]}); err != nil {
		t.Fatal(err)
	}
	health, err := service.Commit(context.Background(), request.StartupID)
	if err != nil || !health.Live || !health.Ready || health.TemplateRevision != request.TemplateRevision || health.WorkspaceRevision != request.WorkspaceRevision {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old workspace content remains: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "src", "main.go"))
	if err != nil || string(got) != string(content) {
		t.Fatalf("materialized content=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(identity); err != nil || string(got) != "operator-owned-volume" {
		t.Fatalf("operator volume identity was replaced by workspace commit: %v", err)
	}
	if got, err := os.ReadFile(stateIdentity); err != nil || string(got) != "operator-owned-state" {
		t.Fatalf("operator state identity was replaced by workspace commit: %v", err)
	}
	document := healthJSON(t, health)
	if strings.Contains(document, workspace) || strings.Contains(document, state) || strings.Contains(document, "credential") {
		t.Fatalf("health exposed private coordinates: %s", document)
	}

	reconstructed := testService(t, workspace, state)
	if err := VerifyClosedState(state); err != nil {
		t.Fatalf("restart lost closed persistent state: %v", err)
	}
	recovered, err := reconstructed.Health(context.Background())
	if err != nil || !recovered.Ready || recovered.WorkspaceRevision != request.WorkspaceRevision {
		t.Fatalf("reconstructed health=%+v err=%v", recovered, err)
	}
}

func TestServiceIntegrityFailureAndRollbackPreserveWorkspace(t *testing.T) {
	workspace, state := testRoots(t)
	if err := os.WriteFile(filepath.Join(workspace, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := testService(t, workspace, state)
	request := PrepareRequest{
		StartupID: "dev-fail", TemplateRevision: digestOf("template"), WorkspaceRevision: "rev-fail", ManifestDigest: digestOf("manifest"),
		Entries: []Entry{{Path: "broken.txt", Type: "file", Mode: 0o600, SizeBytes: 4, Digest: digestOf("good")}},
	}
	if err := service.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Write(context.Background(), WriteRequest{StartupID: request.StartupID, Path: "broken.txt", Data: []byte("evil")}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Commit(context.Background(), request.StartupID); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	if err := service.Rollback(context.Background(), request.StartupID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "keep.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("rollback content=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, stageName)); !os.IsNotExist(err) {
		t.Fatalf("stage remains after rollback: %v", err)
	}
	if err := service.Prepare(context.Background(), PrepareRequest{StartupID: "dev-unsafe", TemplateRevision: digestOf("template"), WorkspaceRevision: "rev-unsafe", ManifestDigest: digestOf("manifest"), Entries: []Entry{{Path: "../escape", Type: "file", Digest: digestOf(""), Mode: 0o600}}}); err == nil {
		t.Fatal("unsafe path was accepted")
	}
}

func TestServiceRollsBackCommittedWorkspaceBeforeFinalize(t *testing.T) {
	workspace, state := testRoots(t)
	stateIdentity := filepath.Join(state, StorageIdentityFileName)
	if err := os.WriteFile(stateIdentity, []byte("operator-owned-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := testService(t, workspace, state)
	content := []byte("replacement")
	request := PrepareRequest{
		StartupID: "dev-rollback", TemplateRevision: digestOf("template"), WorkspaceRevision: "rev-rollback", ManifestDigest: digestOf("manifest"),
		Entries: []Entry{{Path: "new.txt", Type: "file", Mode: 0o600, SizeBytes: int64(len(content)), Digest: digestOf(string(content))}},
	}
	if err := service.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Write(context.Background(), WriteRequest{StartupID: request.StartupID, Path: "new.txt", Data: content}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Commit(context.Background(), request.StartupID); err != nil {
		t.Fatal(err)
	}
	if err := service.Rollback(context.Background(), request.StartupID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "keep.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("restored content=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("committed replacement survived rollback: %v", err)
	}
	if got, err := os.ReadFile(stateIdentity); err != nil || string(got) != "operator-owned-state" {
		t.Fatalf("operator state identity was replaced by rollback: %v", err)
	}
	if err := VerifyClosedState(state); err != nil {
		t.Fatalf("rollback lost closed persistent state: %v", err)
	}
	health, err := service.Health(context.Background())
	if err != nil || health.Ready {
		t.Fatalf("health=%+v err=%v", health, err)
	}
}

func TestServiceRecoversInterruptedSwapFromBackup(t *testing.T) {
	workspace, state := testRoots(t)
	backup := filepath.Join(workspace, backupName)
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "original.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "partial.txt"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = testService(t, workspace, state)
	if _, err := os.Stat(filepath.Join(workspace, "partial.txt")); !os.IsNotExist(err) {
		t.Fatalf("partial content survived recovery: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "original.txt"))
	if err != nil || string(got) != "original" {
		t.Fatalf("recovered content=%q err=%v", got, err)
	}
}

func TestVerifyClosedPersistentStateRejectsCorruptionAndCrashResidue(t *testing.T) {
	newState := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, StorageIdentityFileName), []byte("receipt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeMarker(root, marker{StartupID: "dev-state", TemplateRevision: digestOf("template"),
			WorkspaceRevision: "rev-state", ManifestDigest: digestOf("manifest")}); err != nil {
			t.Fatal(err)
		}
		if err := writeTransaction(root, transaction{StartupID: "dev-state"}); err != nil {
			t.Fatal(err)
		}
		if err := VerifyClosedState(root); err != nil {
			t.Fatalf("valid closed state rejected: %v", err)
		}
		return root
	}
	for name, mutate := range map[string]func(*testing.T, string){
		"oversized": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, markerName), []byte(strings.Repeat("x", maxStateDocumentBytes+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"corrupt": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, markerName), []byte("not-json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, markerName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, transactionName), filepath.Join(root, markerName)); err != nil {
				t.Fatal(err)
			}
		},
		"unknown": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "unknown.json"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"crash temporary": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, ".materialization-crash.tmp"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing receipt": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, StorageIdentityFileName)); err != nil {
				t.Fatal(err)
			}
		},
		"writable mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, transactionName), 0o640); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := newState(t)
			mutate(t, root)
			if VerifyClosedState(root) == nil {
				t.Fatal("corrupt or unreviewed Guest persistent state accepted")
			}
		})
	}
}

func testRoots(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	state := filepath.Join(root, "state")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return workspace, state
}

func testService(t *testing.T, workspace, state string) *Service {
	t.Helper()
	service, err := New(Options{
		WorkspaceRoot: workspace, StateRoot: state,
		Mounts:     []Mount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}},
		Toolchains: []Toolchain{{ID: "posix-shell", Version: "test-1", Digest: digestOf("toolchain"), Executable: "/bin/sh"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func digestOf(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func healthJSON(t *testing.T, value HealthResponse) string {
	t.Helper()
	document, err := jsonMarshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

var jsonMarshal = json.Marshal
