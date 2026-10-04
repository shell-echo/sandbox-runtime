//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6ProductMigrationOriginalIDExitedAndRemovedProof(t *testing.T) {
	runID := strings.Repeat("a", 32)
	id := strings.Repeat("b", 64)
	pgID := strings.Repeat("c", 64)
	image := "sha256:" + strings.Repeat("d", 64)
	principal := phase6security.Principal{Name: "product-migration-job", Kind: "migration_job",
		ImageDigest: image, ImageReference: image}
	started := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	finished := started.Add(time.Second)
	ledgerStart := finished.Add(time.Millisecond)
	ledgerFinish := ledgerStart.Add(time.Millisecond)
	lines := make([]string, len(slice6ProductMigrationFiles))
	for i := range lines {
		lines[i] = fmt.Sprintf("%d|sha256:%s", i+1, strings.Repeat("e", 64))
	}
	proof := slice6ProductMigrationExitProof{RunID: runID, ContainerID: id, PostgresID: pgID,
		ExitRaw: []byte(id + "|/sr-p6-product-migrate-live-" + runID + "|" + image + "|" + image + "|" +
			runID + "|false|0|false|0|0|" + started.Format(time.RFC3339Nano) + "|" + finished.Format(time.RFC3339Nano) + "\n"),
		LedgerRaw:  []byte(strings.Join(lines, "\n") + "\n"),
		RemovalRaw: []byte(id + "\n"), LedgerExecID: strings.Repeat("f", 64),
		LedgerStartedUTC:  ledgerStart.Format(time.RFC3339Nano),
		LedgerFinishedUTC: ledgerFinish.Format(time.RFC3339Nano),
		LedgerExecExitRaw: slice6GuestOperatorExecExitReceipt(strings.Repeat("f", 64), pgID,
			ledgerFinish.Format(time.RFC3339Nano))}
	if digest, err := slice6CheckProductMigrationExitProof(proof, principal, lines); err != nil ||
		!guestRevokeFixtureDigestGate(digest) {
		t.Fatalf("original exited/removed proof rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*slice6ProductMigrationExitProof)
	}{
		{"missing removal", func(p *slice6ProductMigrationExitProof) { p.RemovalRaw = nil }},
		{"wrong original ID", func(p *slice6ProductMigrationExitProof) { p.ContainerID = strings.Repeat("1", 64) }},
		{"wrong launch name", func(p *slice6ProductMigrationExitProof) {
			p.ExitRaw = bytes.Replace(p.ExitRaw, []byte("product-migrate-live"), []byte("product-migration-job"), 1)
		}},
		{"restarted migration", func(p *slice6ProductMigrationExitProof) {
			p.ExitRaw = bytes.Replace(p.ExitRaw, []byte("|false|0|false|0|0|"), []byte("|true|0|false|1|42|"), 1)
		}},
		{"ledger replay drift", func(p *slice6ProductMigrationExitProof) {
			p.LedgerRaw = bytes.Replace(p.LedgerRaw, []byte("1|sha256:"), []byte("2|sha256:"), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrong := proof
			test.edit(&wrong)
			if _, err := slice6CheckProductMigrationExitProof(wrong, principal, lines); err == nil {
				t.Fatal("migration lifecycle/ledger drift accepted")
			}
		})
	}
}

func TestSlice6ProductMigrationLedgerSharesGuestOperatorFailStopAdmission(t *testing.T) {
	runID := strings.Repeat("7", 32)
	postgresID := strings.Repeat("8", 64)
	defer func() {
		slice6GuestOperatorSQLMu.Lock()
		delete(slice6GuestOperatorUncertain, runID)
		delete(slice6GuestOperatorUncertainExec, runID)
		slice6GuestOperatorSQLMu.Unlock()
	}()
	calls := 0
	execID := strings.Repeat("9", 64)
	runner := func(_ context.Context, containerID, _ string, query []byte, command []string, limit int) (slice6GuestOperatorExec, error) {
		calls++
		if containerID != postgresID || string(query) != slice6ProductMigrationLedgerSQL ||
			len(command) < 2 || limit != 2048 {
			t.Fatal("ledger observer escaped fixed read-only input")
		}
		return slice6GuestOperatorExec{ID: execID, ContainerID: containerID}, errors.New("injected uncertain exit")
	}
	first, err := slice6ReadProductMigrationLedgerRawWithExec(t.Context(), runID, postgresID, runner)
	if err == nil || first.ID != execID || calls != 1 || !slice6GuestOperatorUncertain[runID] ||
		slice6GuestOperatorUncertainExec[runID] != execID {
		t.Fatal("ledger uncertain exec identity was not retained")
	}
	if _, err := slice6ReadProductMigrationLedgerRawWithExec(t.Context(), runID, postgresID, runner); err == nil || calls != 1 {
		t.Fatal("same-run ledger retry bypassed fail-stop admission")
	}
	slice6GuestOperatorSQLMu.Lock()
	_, busyErr := slice6ReadProductMigrationLedgerRawWithExec(t.Context(), strings.Repeat("a", 32), postgresID, runner)
	slice6GuestOperatorSQLMu.Unlock()
	if busyErr == nil || calls != 1 {
		t.Fatal("ledger observer bypassed single-worker admission")
	}
}
