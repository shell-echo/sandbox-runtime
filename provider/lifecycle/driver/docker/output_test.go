package docker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

func TestOpenOutputConfinesRegularFileToOwnedGeneration(t *testing.T) {
	backend := newFakeEngine()
	driver, err := newDriver(backend, testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	sandbox := testSandbox(time.Now().UTC())
	if err := driver.Create(context.Background(), sandbox); err != nil {
		t.Fatal(err)
	}
	paths, _ := driver.mountPaths(sandbox.ID)
	if err := os.MkdirAll(filepath.Join(paths.outputs, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.outputs, "nested", "result.txt"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := driver.OpenOutput(context.Background(), sandbox.ID, 1, "/outputs/nested/result.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Content.Close()
	content, err := io.ReadAll(output.Content)
	if err != nil || string(content) != "bounded" || output.SizeBytes != 7 {
		t.Fatalf("OpenOutput() = %q, %d, %v", content, output.SizeBytes, err)
	}
	if _, err := driver.OpenOutput(context.Background(), sandbox.ID, 2, "/outputs/nested/result.txt"); !errors.Is(err, artifact.ErrGenerationConflict) {
		t.Fatalf("stale generation error = %v", err)
	}
	container := backend.containers[containerName(sandbox.ID)]
	delete(container.labels, generationLabel)
	backend.containers[containerName(sandbox.ID)] = container
	if _, err := driver.OpenOutput(context.Background(), sandbox.ID, 1, "/outputs/nested/result.txt"); !errors.Is(err, artifact.ErrGenerationConflict) {
		t.Fatalf("missing generation label error = %v", err)
	}
}

func TestOpenOutputRejectsLinksDirectoriesAndStoppedRuntime(t *testing.T) {
	backend := newFakeEngine()
	driver, err := newDriver(backend, testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	sandbox := testSandbox(time.Now().UTC())
	if err := driver.Create(context.Background(), sandbox); err != nil {
		t.Fatal(err)
	}
	paths, _ := driver.mountPaths(sandbox.ID)
	if err := os.WriteFile(filepath.Join(paths.outputs, "target.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(paths.outputs, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(paths.outputs, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"/outputs/link.txt", "/outputs/directory", "/outputs"} {
		if _, err := driver.OpenOutput(context.Background(), sandbox.ID, 1, source); !errors.Is(err, artifact.ErrSourceMissing) {
			t.Fatalf("OpenOutput(%q) error = %v", source, err)
		}
	}
	info := backend.containers[containerName(sandbox.ID)]
	info.running, info.status = false, "exited"
	backend.containers[containerName(sandbox.ID)] = info
	if _, err := driver.OpenOutput(context.Background(), sandbox.ID, 1, "/outputs/target.txt"); !errors.Is(err, artifact.ErrSourceMissing) {
		t.Fatalf("stopped runtime error = %v", err)
	}
}
