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
	document := healthJSON(t, health)
	if strings.Contains(document, workspace) || strings.Contains(document, state) || strings.Contains(document, "credential") {
		t.Fatalf("health exposed private coordinates: %s", document)
	}

	reconstructed := testService(t, workspace, state)
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
