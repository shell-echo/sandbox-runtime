//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"errors"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func slice6GuestOperatorSourceRawLimit(name string) int {
	switch name {
	case "guest-source-hba.raw":
		return 64 << 10
	case "guest-source-settings.stdout":
		return 32
	case "guest-source-settings-exit.receipt":
		return 256
	case "guest-source-container-inventory.stdout":
		return 64 << 10
	case "guest-source-product-runtime.inspect":
		return 1024
	case "guest-source-product-networks.inspect":
		return 4096
	case "guest-source-postgres.inspect":
		return 16 << 10
	case "guest-source-metadata.json":
		return 32 << 10
	case "product-migration-exit.inspect":
		return 2048
	case "product-migration-ledger.stdout":
		return 2048
	case "product-migration-remove.stdout":
		return 128
	case "product-migration-ledger-exit.receipt":
		return 256
	case "product-migration-current-ledger.stdout":
		return 2048
	case "product-migration-current-ledger-exit.receipt":
		return 256
	}
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service == "postgres" && name == "guest-source-network-"+path.Network+".json" {
			return 64 << 10
		}
	}
	return 0
}

func slice6GuestOperatorSourceRawNames() []string {
	names := []string{"guest-source-hba.raw", "guest-source-settings.stdout",
		"guest-source-settings-exit.receipt", "guest-source-container-inventory.stdout",
		"guest-source-product-runtime.inspect", "guest-source-product-networks.inspect",
		"guest-source-postgres.inspect",
		"guest-source-metadata.json"}
	names = append(names, slice6ProductMigrationProofRawNames()...)
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service == "postgres" {
			names = append(names, "guest-source-network-"+path.Network+".json")
		}
	}
	slices.Sort(names)
	return names
}

func (run *slice6ReceiptEvidenceRun) writeV2GuestSourceRaw(name string, raw []byte) (string, error) {
	limit := slice6GuestOperatorSourceRawLimit(name)
	if run == nil || run.check() != nil || limit == 0 || len(raw) < 1 || len(raw) > limit {
		return "", phase6guestreceipt.ErrUnavailable
	}
	run.mu.Lock()
	if run.check() != nil || run.closed {
		run.mu.Unlock()
		return "", phase6guestreceipt.ErrUnavailable
	}
	file, err := run.createPrivateFileLocked(name)
	run.mu.Unlock()
	if err != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	written, writeErr := file.Write(raw)
	syncErr := run.syncFile(file)
	closeErr := file.Close()
	if written != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil ||
		run.syncDir(run.fd) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	observed, err := run.readFile(name, limit)
	defer clear(observed)
	if err != nil || !bytes.Equal(observed, raw) {
		return "", phase6guestreceipt.ErrUnavailable
	}
	return slice6ReceiptSHA256(raw), nil
}

func (source slice6GuestOperatorFormalSource) verifyRawFiles() error {
	if source.evidence == nil || source.evidence.check() != nil ||
		source.evidence.id != source.runID || len(source.rawFiles) != 23 {
		return errors.New("formal Guest operator raw source absent")
	}
	names := slice6GuestOperatorSourceRawNames()
	if len(names) != 23 {
		return errors.New("formal Guest operator raw source inventory drift")
	}
	for _, name := range names {
		digest := source.rawFiles[name]
		if !guestRevokeFixtureDigestGate(digest) {
			return errors.New("formal Guest operator raw source digest absent")
		}
		raw, err := source.evidence.readFile(name, slice6GuestOperatorSourceRawLimit(name))
		if err != nil || slice6ReceiptSHA256(raw) != digest {
			clear(raw)
			return errors.New("formal Guest operator raw source tampered")
		}
		clear(raw)
	}
	if source.rawProofDigest != slice6GuestOperatorRawProofDigest(source.rawFiles) {
		return errors.New("formal Guest operator raw source binding drift")
	}
	return nil
}

func slice6GuestOperatorRawProofDigest(files map[string]string) string {
	names := slice6GuestOperatorSourceRawNames()
	lines := make([]string, 0, len(names))
	for _, name := range names {
		lines = append(lines, name+"|"+files[name])
	}
	return slice6ReceiptSHA256([]byte(strings.Join(lines, "\n")))
}
