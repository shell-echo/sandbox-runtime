//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"errors"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

var slice6GuestRecoveryActionRawNames = [8]string{
	"guest-e-pg-down-before.raw", "guest-e-pg-down-after.raw",
	"guest-e-guest-off-before.raw", "guest-e-guest-off-after.raw",
	"guest-e-pg-up-before.raw", "guest-e-pg-up-after.raw",
	"guest-e-guest-on-before.raw", "guest-e-guest-on-after.raw",
}

func slice6GuestRecoveryActionProjections(ledger slice6GuestRecoveryActionLedger) [8]string {
	return [8]string{
		ledger.PGDown.BeforeProjection, ledger.PGDown.AfterProjection,
		ledger.GuestOff.BeforeProjection, ledger.GuestOff.AfterProjection,
		ledger.PGUp.BeforeProjection, ledger.PGUp.AfterProjection,
		ledger.GuestOn.BeforeProjection, ledger.GuestOn.AfterProjection,
	}
}

func slice6GuestRecoveryActionDockerSnapshots(ledger slice6GuestRecoveryActionLedger) [8]slice6GuestRecoveryDockerSnapshot {
	return [8]slice6GuestRecoveryDockerSnapshot{
		ledger.PGDown.BeforeDocker, ledger.PGDown.AfterDocker,
		ledger.GuestOff.BeforeDocker, ledger.GuestOff.AfterDocker,
		ledger.PGUp.BeforeDocker, ledger.PGUp.AfterDocker,
		ledger.GuestOn.BeforeDocker, ledger.GuestOn.AfterDocker,
	}
}

func slice6GuestRecoveryActionDockerRawNames(index int) [4]string {
	base := strings.TrimSuffix(slice6GuestRecoveryActionRawNames[index], ".raw")
	return [4]string{base + "-product.inspect", base + "-peer.inspect",
		base + "-network.inspect", base + "-retained.inspect"}
}

func slice6GuestRecoveryDockerSnapshotParts(snapshot slice6GuestRecoveryDockerSnapshot) [4][]byte {
	return [4][]byte{snapshot.Product, snapshot.Peer, snapshot.Network, snapshot.Retained}
}

func slice6GuestRecoveryActionRawDigest(projections [8]string,
	snapshots [8]slice6GuestRecoveryDockerSnapshot) string {
	lines := make([]string, 0, 40)
	for index, name := range slice6GuestRecoveryActionRawNames {
		lines = append(lines, name+"|"+slice6ReceiptSHA256([]byte(projections[index])))
		for partIndex, rawName := range slice6GuestRecoveryActionDockerRawNames(index) {
			lines = append(lines, rawName+"|"+slice6ReceiptSHA256(slice6GuestRecoveryDockerSnapshotParts(snapshots[index])[partIndex]))
		}
	}
	return slice6ReceiptSHA256([]byte(strings.Join(lines, "\n")))
}

// Persist the bounded canonical observation projections returned by the
// actual Docker action probes. These are not a substitute for independently
// saving/replaying the Docker inspect outputs that produced them.
func (run *slice6ReceiptEvidenceRun) writeGuestRecoveryActionRaw(
	ledger slice6GuestRecoveryActionLedger) (string, error) {
	if run == nil || run.check() != nil || ledger.PGDown.RunID != run.id ||
		ledger.GuestOff.RunID != run.id ||
		!slice6CheckPGActionProjection(ledger.PGDown, true) ||
		!slice6CheckPGActionProjection(ledger.PGUp, false) ||
		!slice6CheckGuestActionProjection(ledger.GuestOff, true) ||
		!slice6CheckGuestActionProjection(ledger.GuestOn, false) {
		return "", phase6guestreceipt.ErrUnavailable
	}
	projections := slice6GuestRecoveryActionProjections(ledger)
	snapshots := slice6GuestRecoveryActionDockerSnapshots(ledger)
	for index, name := range slice6GuestRecoveryActionRawNames {
		if err := run.writeV2BoundedPrivateFile(name, []byte(projections[index]), 1024, false); err != nil {
			return "", err
		}
		parts := slice6GuestRecoveryDockerSnapshotParts(snapshots[index])
		for partIndex, rawName := range slice6GuestRecoveryActionDockerRawNames(index) {
			if len(parts[partIndex]) < 1 || len(parts[partIndex]) > 16<<10 ||
				run.writeV2BoundedPrivateFile(rawName, parts[partIndex], 16<<10, false) != nil {
				return "", errors.New("Guest E original Docker observation raw unavailable")
			}
		}
	}
	return slice6GuestRecoveryActionRawDigest(projections, snapshots), nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryActionRaw(ledger slice6GuestRecoveryActionLedger) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(ledger.RawProofDigest) ||
		ledger.PGDown.RunID != run.id || ledger.GuestOff.RunID != run.id {
		return phase6guestreceipt.ErrUnavailable
	}
	projections := slice6GuestRecoveryActionProjections(ledger)
	snapshots := slice6GuestRecoveryActionDockerSnapshots(ledger)
	if ledger.RawProofDigest != slice6GuestRecoveryActionRawDigest(projections, snapshots) {
		return errors.New("Guest recovery action projection inventory drift")
	}
	for index, name := range slice6GuestRecoveryActionRawNames {
		raw, err := run.readFile(name, 1024)
		if err != nil || !bytes.Equal(raw, []byte(projections[index])) {
			clear(raw)
			return errors.New("Guest recovery action raw projection tampered")
		}
		clear(raw)
		parts := slice6GuestRecoveryDockerSnapshotParts(snapshots[index])
		for partIndex, rawName := range slice6GuestRecoveryActionDockerRawNames(index) {
			observed, readErr := run.readFile(rawName, 16<<10)
			if readErr != nil || !bytes.Equal(observed, parts[partIndex]) {
				clear(observed)
				return errors.New("Guest recovery original Docker observation raw tampered")
			}
			clear(observed)
		}
	}
	return nil
}
