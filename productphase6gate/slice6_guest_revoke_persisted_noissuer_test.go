//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const slice6GuestRevokePersistedNoIssuerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_REVOKE_PERSISTED_NO_ISSUER"

// This disposable, networkless PostgreSQL check uses the pinned upstream
// PostgreSQL index and arm64 platform. It is not E6's exact selected OCI
// archive manifest. It executes the gate's exact SQL and psql flags through
// slice6VerifyGuestRevokePersisted. It neither starts Vault nor mutates an E6
// database, and is not live-revocation evidence.
func TestSlice6GuestRevokePersistedNoIssuerPostgres(t *testing.T) {
	if os.Getenv(slice6GuestRevokePersistedNoIssuerEnv) != "1" {
		t.Skip("set " + slice6GuestRevokePersistedNoIssuerEnv + " for isolated PostgreSQL readback")
	}
	if os.Getenv(slice6VaultTrustSwitchEnv) == "1" {
		t.Fatal("no-issuer persisted revoke check cannot enable Vault gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	t.Cleanup(func() {
		if cleaned {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("no-issuer PostgreSQL exact cleanup: %v", err)
		}
	})
	const image = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	created, err := run.docker(ctx, "run", "-d", "--pull=never", "--platform=linux/arm64/v8",
		"--name", "sr-p6-revoke-readback-"+run.id, "--label", run.label(),
		"--network=none", "--restart=no", "--user=70:70", "--read-only",
		"--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--memory=268435456", "--cpus=0.5", "--pids-limit=32",
		"--tmpfs=/tmp:rw,nosuid,nodev,size=134217728,mode=1777",
		"--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=134217728,uid=70,gid=70,mode=0700",
		"--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=8388608,uid=70,gid=70,mode=0775",
		"--entrypoint=/bin/sh", image, "-ec",
		"initdb -D /var/lib/postgresql/data/pgdata --no-sync -U postgres -A trust >/dev/null 2>&1; "+
			"exec postgres -D /var/lib/postgresql/data/pgdata -c listen_addresses=''")
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("isolated pinned PostgreSQL startup unavailable")
	}
	ready := false
	for attempt := 0; attempt < 80 && ctx.Err() == nil; attempt++ {
		if _, err := run.docker(ctx, "exec", "-u", "70:70", id,
			"pg_isready", "-q", "-U", "postgres", "-d", "postgres"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated pinned PostgreSQL did not reach local readiness")
	}
	createdDB, err, overflow := slice6DockerBounded(ctx, 256, nil, "exec", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres",
		"-c", "CREATE DATABASE product")
	clear(createdDB)
	if err != nil || overflow {
		t.Fatal("isolated PostgreSQL product database unavailable")
	}
	runSQL := func(script string) {
		t.Helper()
		out, err, overflow := slice6DockerBounded(ctx, 512, []byte(script), "exec", "-i", "-u", "70:70", id,
			"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", "product", "-f", "-")
		defer clear(out)
		if err != nil || overflow {
			t.Fatalf("isolated PostgreSQL test-row setup unavailable: command_error=%t overflow=%t output_bytes=%d", err != nil, overflow, len(out))
		}
	}
	row := "WHERE tenant_id='tenant-phase6-" + run.id + "' AND guest_id='gst-noissuer'"
	runSQL("CREATE SCHEMA sandbox_runtime_product;\n" +
		"CREATE TABLE sandbox_runtime_product.guest_bindings(tenant_id text,guest_id text,state text,connection_nonce text,expires_at timestamptz);\n" +
		"INSERT INTO sandbox_runtime_product.guest_bindings VALUES('tenant-phase6-" + run.id +
		"','gst-noissuer','revoked',NULL,clock_timestamp()+interval '10 minutes');\n")
	check := func(name string, want bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			err := slice6VerifyGuestRevokePersisted(ctx, id, run.id, "gst-noissuer")
			if (err == nil) != want {
				t.Fatalf("formal readback verdict unavailable: %v", err)
			}
		})
	}
	check("revoked empty nonce before DB expiry", true)
	runSQL("UPDATE sandbox_runtime_product.guest_bindings SET connection_nonce='nonce' " + row + ";\n")
	check("nonempty nonce", false)
	runSQL("UPDATE sandbox_runtime_product.guest_bindings SET state='connected',connection_nonce=NULL " + row + ";\n")
	check("unrevoked state", false)
	runSQL("UPDATE sandbox_runtime_product.guest_bindings SET state='revoked',expires_at=clock_timestamp()-interval '1 minute' " + row + ";\n")
	check("expired by DB clock", false)
	runSQL("UPDATE sandbox_runtime_product.guest_bindings SET expires_at=clock_timestamp()+interval '10 minutes' " + row + ";\n" +
		"INSERT INTO sandbox_runtime_product.guest_bindings SELECT * FROM sandbox_runtime_product.guest_bindings " + row + ";\n")
	check("duplicate matching rows", false)
	runSQL("DELETE FROM sandbox_runtime_product.guest_bindings " + row + ";\n")
	check("no matching row", false)
	runSQL("INSERT INTO sandbox_runtime_product.guest_bindings VALUES('tenant-phase6-" + run.id +
		"','gst-noissuer','revoked',repeat('x',200),clock_timestamp()+interval '10 minutes');\n")
	script := slice6GuestRevokePersistedScript(run.id)
	out, commandErr, overflow := slice6DockerBounded(ctx, 128, script, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
		"-v", "guest_id=gst-noissuer", "-U", "postgres", "-d", "product", "-f", "-")
	clear(script)
	clear(out)
	if !overflow || !errors.Is(commandErr, errSlice6OutputLimit) {
		t.Fatal("bounded persisted revoke observation did not reject oversized row")
	}
	check("oversized output", false)
	runSQL("DROP TABLE sandbox_runtime_product.guest_bindings;\n")
	check("SQL error", false)
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("no-issuer PostgreSQL exact cleanup: %v", err)
	}
	cleaned = true
	t.Log("formal read-only SQL/psql/parser positive and closed negatives passed on pinned arm64 PostgreSQL; exact run-label cleanup to zero, no issuer")
}
