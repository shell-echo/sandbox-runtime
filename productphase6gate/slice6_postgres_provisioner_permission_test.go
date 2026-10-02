//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const slice6PostgresPermissionEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_POSTGRES_PERMISSION_PROBE"

// This bounded Docker probe uses six harmless fixed one-byte files, not a
// certificate, key or password. It proves the CHOWN-only order and that an
// independently bounded cleanup still removes exact resources after the main
// context is cancelled. It is not PostgreSQL or Vault evidence.
func TestSlice6PostgresProvisionerPermissionOrder(t *testing.T) {
	if os.Getenv(slice6PostgresPermissionEnv) != "1" {
		t.Skip("set " + slice6PostgresPermissionEnv + "=1 for the networkless permission probe")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact permission-probe fallback cleanup: %v", err)
		}
	})
	root, err := os.MkdirTemp(".", ".sr-pg-permission-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove exact no-secret permission-probe directory: %v", err)
		}
	})
	directory := filepath.Join(root, "postgres-server")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("create exact no-secret private material directory")
	}
	for _, name := range slice6PostgresPrivateFiles {
		if err := os.WriteFile(filepath.Join(directory, name), []byte{'x'}, 0o600); err != nil {
			t.Fatal("write one no-secret permission-probe file")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	config, data := slice6ProvisionPostgresVolumes(t, ctx, run, directory, 70, 70)
	cancel()
	if config == "" || data == "" || config == data {
		t.Fatal("permission probe did not create two exact private volumes")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	if err := run.cleanup(cleanup); err != nil {
		t.Fatal("cancelled main context prevented exact provisioner resource cleanup")
	}
	t.Log("networkless CHOWN-only fixed-file provisioner and cancelled-context exact cleanup passed with no secrets or PostgreSQL process")
}
