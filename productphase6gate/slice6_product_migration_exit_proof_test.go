//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// Captured before the one-shot container is removed, then completed by the
// exact rm response and absence readback. These bounded raw bytes contain no
// credential or full Docker inspect and must be saved in the same private E
// run before a later source proof can claim them.
type slice6ProductMigrationExitProof struct {
	RunID, ContainerID, PostgresID      string
	ExitRaw, LedgerRaw, RemovalRaw      []byte
	LedgerExecExitRaw                   []byte
	LedgerExecID                        string
	LedgerStartedUTC, LedgerFinishedUTC string
}

type slice6ProductMigrationRemovedWitness struct {
	CurrentLedgerRaw, CurrentLedgerExitRaw []byte
	CurrentLedgerExecID                    string
	CurrentLedgerStartedUTC                string
	CurrentLedgerFinishedUTC               string
	ExpectedLedger                         []string
}

const slice6ProductMigrationExitFormat = "{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|" +
	"{{index .Config.Labels \"" + slice6RunLabel + "\"}}|{{.State.Running}}|" +
	"{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.State.Pid}}|" +
	"{{.State.StartedAt}}|{{.State.FinishedAt}}"

const slice6ProductMigrationLedgerSQL = "BEGIN READ ONLY;\n" +
	"SET LOCAL statement_timeout='3000ms';\nSET LOCAL lock_timeout='1000ms';\n" +
	"SELECT version::text||'|'||digest FROM sandbox_runtime_product.schema_migrations ORDER BY version;\nCOMMIT;\n"

func slice6ReadProductMigrationLedgerRaw(parent context.Context, runID, postgresID string) (slice6GuestOperatorExec, error) {
	return slice6ReadProductMigrationLedgerRawWithExec(parent, runID, postgresID, slice6RunGuestOperatorSQL)
}

type slice6GuestOperatorSQLRunner func(context.Context, string, string, []byte, []string, int) (slice6GuestOperatorExec, error)

func slice6ReadProductMigrationLedgerRawWithExec(parent context.Context, runID, postgresID string,
	runner slice6GuestOperatorSQLRunner) (slice6GuestOperatorExec, error) {
	if parent == nil || parent.Err() != nil || len(runID) != 32 || !lowerHexSlice6(runID) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) || runner == nil ||
		!slice6GuestOperatorSQLMu.TryLock() {
		return slice6GuestOperatorExec{}, errors.New("Product migration ledger source invalid")
	}
	defer slice6GuestOperatorSQLMu.Unlock()
	if slice6GuestOperatorUncertain[runID] {
		return slice6GuestOperatorExec{}, errors.New("Product migration ledger prior SQL exit uncertain")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return slice6GuestOperatorExec{}, errors.New("Product migration ledger operation unavailable")
	}
	appName := "sr-p6-mig-" + runID + "-" + hex.EncodeToString(nonce)
	clear(nonce)
	query := []byte(slice6ProductMigrationLedgerSQL)
	defer clear(query)
	observed, err := runner(ctx, postgresID, appName, query,
		[]string{"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
			"-h", "/var/run/postgresql", "-U", "postgres", "-d", "product", "-f", "-"}, 2048)
	if err != nil || slice6CheckGuestOperatorExecExitReceipt(observed) != nil {
		slice6GuestOperatorUncertain[runID] = true
		slice6GuestOperatorUncertainExec[runID] = observed.ID
		return observed, errors.New("Product migration ledger SQL process exit uncertain")
	}
	return observed, nil
}

func slice6CaptureProductMigrationExitProof(ctx context.Context, run slice6DockerRun,
	containerID, postgresID string) (slice6ProductMigrationExitProof, error) {
	if ctx == nil || ctx.Err() != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return slice6ProductMigrationExitProof{}, errors.New("Product migration exit capture target invalid")
	}
	exitRaw, err, overflow := slice6DockerBounded(ctx, 2048, nil, "inspect", "--format",
		slice6ProductMigrationExitFormat, containerID)
	if err != nil || overflow {
		clear(exitRaw)
		return slice6ProductMigrationExitProof{}, errors.New("Product migration exit raw inspect unavailable")
	}
	ledger, err := slice6ReadProductMigrationLedgerRaw(ctx, run.id, postgresID)
	if err != nil {
		clear(exitRaw)
		clear(ledger.Output)
		return slice6ProductMigrationExitProof{}, errors.New("Product migration ledger raw exec unavailable")
	}
	return slice6ProductMigrationExitProof{RunID: run.id, ContainerID: containerID, PostgresID: postgresID,
		ExitRaw: exitRaw, LedgerRaw: ledger.Output, LedgerExecID: ledger.ID,
		LedgerExecExitRaw: bytes.Clone(ledger.ExitReceipt),
		LedgerStartedUTC:  ledger.StartedUTC, LedgerFinishedUTC: ledger.FinishedUTC}, nil
}

func slice6CheckProductMigrationExitProof(proof slice6ProductMigrationExitProof,
	principal phase6security.Principal, expectedLedger []string) (string, error) {
	if principal.Name != "product-migration-job" || principal.Kind != "migration_job" ||
		len(proof.RunID) != 32 || !lowerHexSlice6(proof.RunID) ||
		len(proof.ContainerID) != 64 || !lowerHexSlice6(proof.ContainerID) ||
		len(proof.PostgresID) != 64 || !lowerHexSlice6(proof.PostgresID) ||
		len(proof.LedgerExecID) != 64 || !lowerHexSlice6(proof.LedgerExecID) ||
		len(expectedLedger) != len(slice6ProductMigrationFiles) ||
		len(proof.ExitRaw) < 12 || len(proof.ExitRaw) > 2048 ||
		len(proof.LedgerRaw) < 2 || len(proof.LedgerRaw) > 2048 ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: proof.LedgerExecID,
			ContainerID: proof.PostgresID, StartedUTC: proof.LedgerStartedUTC,
			FinishedUTC: proof.LedgerFinishedUTC, ExitReceipt: proof.LedgerExecExitRaw}) != nil ||
		!bytes.Equal(proof.RemovalRaw, []byte(proof.ContainerID+"\n")) {
		return "", errors.New("Product migration removed source incomplete")
	}
	parts := strings.Split(strings.TrimSuffix(string(proof.ExitRaw), "\n"), "|")
	if len(parts) != 12 || proof.ExitRaw[len(proof.ExitRaw)-1] != '\n' ||
		parts[0] != proof.ContainerID ||
		parts[1] != "/sr-p6-product-migrate-live-"+proof.RunID ||
		parts[2] != principal.ImageDigest || parts[3] != principal.ImageReference ||
		parts[4] != proof.RunID || parts[5] != "false" || parts[6] != "0" ||
		parts[7] != "false" || parts[8] != "0" || parts[9] != "0" {
		return "", errors.New("Product migration original PID1 exit/image drift")
	}
	started, startErr := time.Parse(time.RFC3339Nano, parts[10])
	finished, finishErr := time.Parse(time.RFC3339Nano, parts[11])
	ledgerStart, ledgerStartErr := time.Parse(time.RFC3339Nano, proof.LedgerStartedUTC)
	ledgerFinish, ledgerFinishErr := time.Parse(time.RFC3339Nano, proof.LedgerFinishedUTC)
	if startErr != nil || finishErr != nil || !finished.After(started) ||
		ledgerStartErr != nil || ledgerFinishErr != nil || !ledgerFinish.After(ledgerStart) ||
		ledgerStart.Before(finished) {
		return "", errors.New("Product migration original exit/ledger order drift")
	}
	if !bytes.Equal(proof.LedgerRaw, []byte(strings.Join(expectedLedger, "\n")+"\n")) {
		return "", errors.New("Product migration frozen ledger raw drift")
	}
	return slice6ReceiptSHA256([]byte("phase6-product-migration-exited-removed.v1|" +
		proof.RunID + "|" + proof.ContainerID + "|" + proof.PostgresID + "|" +
		principal.ImageReference + "|" + principal.ImageDigest + "|" +
		proof.LedgerExecID + "|" + proof.LedgerStartedUTC + "|" + proof.LedgerFinishedUTC + "|" +
		slice6ReceiptSHA256(proof.ExitRaw) + "|" + slice6ReceiptSHA256(proof.LedgerRaw) + "|" +
		slice6ReceiptSHA256(proof.RemovalRaw) + "|" +
		slice6ReceiptSHA256(proof.LedgerExecExitRaw))), nil
}

func slice6VerifyProductMigrationRemovedProof(ctx context.Context, target slice6GuestOperatorTarget,
	principal phase6security.Principal, member slice6GuestPGMember,
	inventory []byte) (string, slice6ProductMigrationRemovedWitness, error) {
	if ctx == nil || ctx.Err() != nil || member.Migration == nil ||
		member.ID != member.Migration.ContainerID || target.Run.id != member.Migration.RunID ||
		target.PostgresID != member.Migration.PostgresID {
		return "", slice6ProductMigrationRemovedWitness{}, errors.New("formal Product migration original ID unavailable")
	}
	expected, err := slice6FrozenProductMigrationLedger(ctx)
	if err != nil {
		return "", slice6ProductMigrationRemovedWitness{}, err
	}
	proofDigest, err := slice6CheckProductMigrationExitProof(*member.Migration, principal, expected)
	if err != nil {
		return "", slice6ProductMigrationRemovedWitness{}, err
	}
	// No Docker inspect of an already-removed container. Reuse the exact
	// all-container inventory captured once for every A-prime dialer.
	listed, err := slice6ParseGuestOperatorRunInventory(inventory)
	if err != nil || listed["sr-p6-product-migrate-live-"+target.Run.id] != "" {
		return "", slice6ProductMigrationRemovedWitness{}, errors.New("formal Product migration original name restarted or replaced")
	}
	for _, id := range listed {
		if id == member.ID {
			return "", slice6ProductMigrationRemovedWitness{}, errors.New("formal Product migration original ID remains")
		}
	}
	ledger, err := slice6ReadProductMigrationLedgerRaw(ctx, target.Run.id, target.PostgresID)
	if err != nil {
		clear(ledger.Output)
		return "", slice6ProductMigrationRemovedWitness{}, errors.New("formal Product migration current ledger unavailable")
	}
	defer clear(ledger.Output)
	if !bytes.Equal(ledger.Output, member.Migration.LedgerRaw) || ledger.ID == member.Migration.LedgerExecID ||
		len(ledger.ID) != 64 || !lowerHexSlice6(ledger.ID) ||
		slice6CheckGuestOperatorExecExitReceipt(ledger) != nil {
		return "", slice6ProductMigrationRemovedWitness{}, errors.New("formal Product migration current ledger drift")
	}
	witness := slice6ProductMigrationRemovedWitness{CurrentLedgerRaw: bytes.Clone(ledger.Output),
		CurrentLedgerExitRaw: bytes.Clone(ledger.ExitReceipt), CurrentLedgerExecID: ledger.ID,
		CurrentLedgerStartedUTC: ledger.StartedUTC, CurrentLedgerFinishedUTC: ledger.FinishedUTC,
		ExpectedLedger: slices.Clone(expected)}
	return slice6ReceiptSHA256([]byte(proofDigest + "|" + slice6ReceiptSHA256(inventory) + "|" +
		ledger.ID + "|" + slice6ReceiptSHA256(ledger.Output) + "|" +
		slice6ReceiptSHA256(ledger.ExitReceipt) + "|" + strconv.Itoa(len(expected)))), witness, nil
}

// Stable, bounded names for the later same-run private evidence writer.
func slice6ProductMigrationProofRawNames() []string {
	return slices.Clone([]string{"product-migration-exit.inspect", "product-migration-ledger.stdout",
		"product-migration-remove.stdout", "product-migration-ledger-exit.receipt",
		"product-migration-current-ledger.stdout", "product-migration-current-ledger-exit.receipt"})
}
