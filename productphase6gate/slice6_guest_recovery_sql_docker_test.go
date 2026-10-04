//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// This disposable no-issuer drill exercises the fixed E/operator local peer,
// bounded SELECT, backend exit and failure path. It is not the source-bound
// nine-network/HBA Product/Guest PG or a recovery acceptance receipt.
func TestSlice6GuestOperatorReadbackNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_OPERATOR_READBACK_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_OPERATOR_READBACK_NO_ISSUER=1 for isolated PostgreSQL operator drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("operator PG no-issuer exact cleanup: %v", err)
		}
	})
	const image = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	const imageID = "sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	configVolume := "sr-p6-postgres-config-" + run.id
	dataVolume := "sr-p6-postgres-data-" + run.id
	for _, name := range []string{configVolume, dataVolume} {
		created, err := run.docker(ctx, "volume", "create", "--label", run.label(), name)
		if err != nil || strings.TrimSpace(string(created)) != name {
			t.Fatal("create exact no-issuer PostgreSQL volume")
		}
	}
	// The source-locked image runs as 70:70. A finite no-secret preparer with
	// only CHOWN makes the two fresh named volumes writable by that account.
	prepared, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-pg-readback-prep-"+run.id,
		"--label", run.label(), "--network=none", "--restart=no", "--read-only",
		"--user=0:0", "--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt=no-new-privileges:true",
		"--memory=67108864", "--pids-limit=16",
		"--mount", "type=volume,src="+configVolume+",dst=/pg",
		"--mount", "type=volume,src="+dataVolume+",dst=/data",
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec", "chown 70:70 /pg /data")
	if err != nil || len(prepared) != 0 {
		t.Fatal("finite no-secret PostgreSQL volume preparer unavailable")
	}
	created, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", "sr-p6-postgres-"+run.id,
		"--label", run.label(), "--network=none", "--restart=no", "--user=70:70",
		"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--memory=268435456", "--pids-limit=32",
		"--tmpfs=/tmp:rw,nosuid,nodev,size=16777216,uid=70,gid=70",
		"--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=8388608,uid=70,gid=70",
		"--mount", "type=volume,src="+configVolume+",dst=/pg,readonly",
		"--mount", "type=volume,src="+dataVolume+",dst=/var/lib/postgresql/data",
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "PGDATA=/var/lib/postgresql/data/pgdata", image)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("no-issuer PostgreSQL PID1 unavailable")
	}
	ready := false
	for attempt := 0; attempt < 80 && ctx.Err() == nil; attempt++ {
		comm, commErr := run.docker(ctx, "exec", "-u", "70:70", id, "cat", "/proc/1/comm")
		if commErr == nil && string(comm) == "postgres\n" {
			if _, err := run.docker(ctx, "exec", "-u", "70:70", id,
				"pg_isready", "-q", "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres"); err == nil {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("no-issuer PostgreSQL local socket unavailable")
	}
	createdDB, err := run.docker(ctx, "exec", "-u", "70:70", id, "psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1",
		"-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", "-c", "CREATE DATABASE product")
	clear(createdDB)
	if err != nil {
		t.Fatal("create disposable Product database")
	}
	target := slice6GuestOperatorTarget{Run: run, PostgresID: id, ImageID: imageID, ImageRef: image,
		UID: 70, GID: 70, TenantID: "tenant-phase6-" + run.id,
		WorkspaceID: "wrk_" + strings.Repeat("a", 32), SlotKey: "primary-code",
		SlotProfileID: "coding-shell-v1", SlotGeneration: 1,
		GuestID: "gst_" + strings.Repeat("b", 32), BindingGeneration: 1}
	if _, err := slice6VerifyGuestOperatorFinalPGSettings(ctx, target); err == nil {
		t.Fatal("no-issuer PostgreSQL incorrectly passed final TLS/HBA settings")
	}
	setup := []byte("CREATE SCHEMA sandbox_runtime_product;\n" +
		"CREATE TABLE sandbox_runtime_product.guest_bindings (tenant_id text,workspace_id text,slot_key text,slot_profile_id text,slot_generation bigint,guest_id text,binding_generation bigint,state text,connection_nonce text,expires_at timestamptz);\n" +
		"INSERT INTO sandbox_runtime_product.guest_bindings VALUES('" + target.TenantID + "','" + target.WorkspaceID + "','primary-code','coding-shell-v1',1,'" + target.GuestID + "',1,'connected','old-nonce',clock_timestamp()+interval '10 minutes');\n")
	out, commandErr, overflow := slice6DockerBounded(ctx, 128, setup, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
		"-U", "postgres", "-d", "product", "-f", "-")
	clear(setup)
	clear(out)
	if commandErr != nil || overflow {
		t.Fatal("fixed no-issuer Guest row setup unavailable")
	}
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	noIssuerSource := slice6ReceiptSHA256([]byte("no-issuer-sql-source|" + run.id))
	connected, err := slice6ReadGuestOperatorPGRecorded(ctx, target, "initial", noIssuerSource, recorder)
	defer clear(connected.RawRow)
	defer clear(connected.RawBackend)
	if err != nil || connected.State != "connected" || connected.NonceNull || !connected.DBTimeUnexpired ||
		connected.ExpiresUnixMicros < 1 || connected.BackendCount != 0 ||
		len(connected.OperationDigest) != 71 || len(connected.ReadExecID) != 64 ||
		len(connected.CheckExecID) != 64 || connected.ReadExecID == connected.CheckExecID ||
		!bytes.Equal(connected.RawBackend, []byte("0\n")) ||
		slice6ReceiptSHA256(connected.RawRow) != connected.OutputSHA256 {
		t.Fatalf("bounded connected-row observer unavailable: %v", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].Kind != "initial_sql_call" ||
		recorder.events[0].ReferenceDigest != slice6GuestRecoverySQLCallRef(slice6GuestOperatorRawBinding{
			Stage: "initial", RunID: run.id, SourceProofDigest: noIssuerSource,
			TargetDigest: connected.TargetDigest, PostgresID: id,
			OperationDigest: connected.OperationDigest}) {
		t.Fatal("real no-issuer SQL invocation journal reference drift")
	}
	update := []byte("UPDATE sandbox_runtime_product.guest_bindings SET state='disconnected',connection_nonce=NULL " +
		"WHERE tenant_id='" + target.TenantID + "' AND guest_id='" + target.GuestID + "';\n")
	out, commandErr, overflow = slice6DockerBounded(ctx, 128, update, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
		"-U", "postgres", "-d", "product", "-f", "-")
	clear(update)
	clear(out)
	if commandErr != nil || overflow {
		t.Fatal("disposable test-row update unavailable")
	}
	disconnected, err := slice6ReadGuestOperatorPG(ctx, target)
	defer clear(disconnected.RawRow)
	defer clear(disconnected.RawBackend)
	if err != nil || disconnected.State != "disconnected" || !disconnected.NonceNull ||
		disconnected.ExpiresUnixMicros != connected.ExpiresUnixMicros ||
		disconnected.PostgresFingerprint != connected.PostgresFingerprint ||
		disconnected.OperationDigest == connected.OperationDigest ||
		disconnected.ReadExecID == connected.ReadExecID ||
		disconnected.CheckExecID == connected.CheckExecID {
		t.Fatalf("bounded disconnected/null readback unavailable: %v", err)
	}
	target.GuestID = "gst_" + strings.Repeat("c", 32)
	if _, err := slice6ReadGuestOperatorPG(ctx, target); err == nil {
		t.Fatal("operator readback accepted a missing exact Guest row")
	}
	target.GuestID = "gst_" + strings.Repeat("b", 32)
	duplicate := []byte("INSERT INTO sandbox_runtime_product.guest_bindings SELECT * FROM sandbox_runtime_product.guest_bindings " +
		"WHERE tenant_id='" + target.TenantID + "' AND guest_id='" + target.GuestID + "';\n")
	out, commandErr, overflow = slice6DockerBounded(ctx, 128, duplicate, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
		"-U", "postgres", "-d", "product", "-f", "-")
	clear(duplicate)
	clear(out)
	if commandErr != nil || overflow {
		t.Fatal("disposable duplicate-row setup unavailable")
	}
	if _, err := slice6ReadGuestOperatorPG(ctx, target); err == nil {
		t.Fatal("operator readback accepted duplicate exact Guest rows")
	}
	expire := []byte("DELETE FROM sandbox_runtime_product.guest_bindings WHERE ctid IN " +
		"(SELECT ctid FROM sandbox_runtime_product.guest_bindings LIMIT 1);\n" +
		"UPDATE sandbox_runtime_product.guest_bindings SET expires_at=clock_timestamp()-interval '1 second';\n")
	out, commandErr, overflow = slice6DockerBounded(ctx, 128, expire, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
		"-U", "postgres", "-d", "product", "-f", "-")
	clear(expire)
	clear(out)
	if commandErr != nil || overflow {
		t.Fatal("disposable expired-row setup unavailable")
	}
	if _, err := slice6ReadGuestOperatorPG(ctx, target); err == nil {
		t.Fatal("operator readback accepted an expired exact Guest row")
	}
	missingTable := []byte("DROP TABLE sandbox_runtime_product.guest_bindings;\n")
	out, commandErr, overflow = slice6DockerBounded(ctx, 128, missingTable, "exec", "-i", "-u", "70:70", id,
		"psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
		"-U", "postgres", "-d", "product", "-f", "-")
	clear(missingTable)
	clear(out)
	if commandErr != nil || overflow {
		t.Fatal("disposable missing-table setup unavailable")
	}
	if _, err := slice6ReadGuestOperatorPG(ctx, target); err == nil ||
		!slice6GuestOperatorUncertain[run.id] ||
		len(slice6GuestOperatorUncertainExec[run.id]) != 64 {
		t.Fatal("operator readback did not stop on an uncertain SQL exit")
	}
	if _, err := slice6ReadGuestOperatorPG(ctx, target); err == nil {
		t.Fatal("operator readback retried after an uncertain SQL exit")
	}
}
