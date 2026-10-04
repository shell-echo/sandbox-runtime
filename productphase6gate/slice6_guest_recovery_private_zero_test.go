//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const slice6GuestRecoveryPrivateSiblingZeroFile = "guest-e-private-siblings-zero.json"

var slice6GuestRecoveryPrivateSiblingPrefixes = []string{
	".sr-p6-product-runtime-observer-",
	".sr-p6-guest-binding-fixture-",
	".sr-p6-terminal-operator-",
	".sr-vault-trust-switch-",
	".sr-guest-material-observer-",
	".sr-guest-signer-observer-",
	".sr-product-identity-observer-",
}

type slice6GuestRecoveryPrivateSiblingAbsent struct {
	Prefix, Path                           string
	ParentDev, ParentIno, RootDev, RootIno uint64
}

type slice6GuestRecoveryPrivateSiblingZero struct {
	Protocol, RunID, RecordedUTC string
	Absent                       []slice6GuestRecoveryPrivateSiblingAbsent
}

// Retain the exact original path and inode class privately; the verifier
// rechecks every original name, never a parent glob or unrelated source root.
func (run *slice6ReceiptEvidenceRun) captureGuestRecoveryPrivateSiblingZero(
	owner *slice6PrivateSiblingOwner) (string, error) {
	if run == nil || run.check() != nil || owner == nil {
		return "", errSlice6ExternalTemp
	}
	owner.mu.Lock()
	if !owner.finished || owner.err != nil || len(owner.leases) != len(slice6GuestRecoveryPrivateSiblingPrefixes) {
		owner.mu.Unlock()
		return "", errSlice6ExternalTemp
	}
	leaves := append([]*slice6PrivateSiblingLease(nil), owner.leases...)
	owner.mu.Unlock()
	receipt := slice6GuestRecoveryPrivateSiblingZero{
		Protocol: "sandbox-runtime.phase6-guest-e-private-siblings-zero.v1",
		RunID:    run.id, RecordedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Absent: make([]slice6GuestRecoveryPrivateSiblingAbsent, 0, len(leaves)),
	}
	for _, lease := range leaves {
		if lease == nil || lease.err != nil || lease.path == "" ||
			!filepath.IsAbs(lease.path) || filepath.Clean(lease.path) != lease.path ||
			lease.parentStat.Ino == 0 || lease.rootStat.Ino == 0 {
			return "", errSlice6ExternalTemp
		}
		prefix := ""
		for _, expected := range slice6GuestRecoveryPrivateSiblingPrefixes {
			if strings.HasPrefix(filepath.Base(lease.path), expected) {
				prefix = expected
				break
			}
		}
		if prefix == "" {
			return "", errSlice6ExternalTemp
		}
		receipt.Absent = append(receipt.Absent, slice6GuestRecoveryPrivateSiblingAbsent{
			Prefix: prefix, Path: lease.path,
			ParentDev: uint64(lease.parentStat.Dev), ParentIno: lease.parentStat.Ino,
			RootDev: uint64(lease.rootStat.Dev), RootIno: lease.rootStat.Ino,
		})
	}
	slices.SortFunc(receipt.Absent, func(a, b slice6GuestRecoveryPrivateSiblingAbsent) int {
		return strings.Compare(a.Prefix, b.Prefix)
	})
	if slice6VerifyGuestRecoveryPrivateSiblingZero(receipt) != nil {
		return "", errSlice6ExternalTemp
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 8<<10 ||
		run.writeV2BoundedPrivateFile(slice6GuestRecoveryPrivateSiblingZeroFile, raw, 8<<10, false) != nil {
		return "", errSlice6ExternalTemp
	}
	if run.verifyGuestRecoveryPrivateSiblingZero() != nil {
		return "", errSlice6ExternalTemp
	}
	return slice6ReceiptSHA256(raw), nil
}

func slice6VerifyGuestRecoveryPrivateSiblingZero(receipt slice6GuestRecoveryPrivateSiblingZero) error {
	if receipt.Protocol != "sandbox-runtime.phase6-guest-e-private-siblings-zero.v1" ||
		len(receipt.RunID) != 32 || !lowerHexSlice6(receipt.RunID) ||
		len(receipt.Absent) != len(slice6GuestRecoveryPrivateSiblingPrefixes) {
		return errSlice6ExternalTemp
	}
	if parsed, err := time.Parse(time.RFC3339Nano, receipt.RecordedUTC); err != nil || parsed.IsZero() {
		return errSlice6ExternalTemp
	}
	wanted := append([]string(nil), slice6GuestRecoveryPrivateSiblingPrefixes...)
	slices.Sort(wanted)
	for index, entry := range receipt.Absent {
		if entry.Prefix != wanted[index] || !filepath.IsAbs(entry.Path) ||
			filepath.Clean(entry.Path) != entry.Path ||
			!strings.HasPrefix(filepath.Base(entry.Path), entry.Prefix) ||
			entry.ParentDev == 0 || entry.ParentIno == 0 ||
			entry.RootDev == 0 || entry.RootIno == 0 {
			return errSlice6ExternalTemp
		}
		var parent unix.Stat_t
		if unix.Lstat(filepath.Dir(entry.Path), &parent) != nil ||
			uint64(parent.Dev) != entry.ParentDev || parent.Ino != entry.ParentIno ||
			parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uint32(os.Getuid()) {
			return errSlice6ExternalTemp
		}
		if _, err := os.Lstat(entry.Path); !errors.Is(err, os.ErrNotExist) {
			return errSlice6ExternalTemp
		}
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryPrivateSiblingZero() error {
	if run == nil || run.check() != nil {
		return errSlice6ExternalTemp
	}
	raw, err := run.readFile(slice6GuestRecoveryPrivateSiblingZeroFile, 8<<10)
	if err != nil {
		return err
	}
	defer clear(raw)
	var receipt slice6GuestRecoveryPrivateSiblingZero
	if json.Unmarshal(raw, &receipt) != nil || receipt.RunID != run.id ||
		slice6VerifyGuestRecoveryPrivateSiblingZero(receipt) != nil {
		return errSlice6ExternalTemp
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errSlice6ExternalTemp
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryPrivateSiblingZeroDigest(digest string) error {
	if run == nil || !guestRevokeFixtureDigestGate(digest) {
		return errSlice6ExternalTemp
	}
	raw, err := run.readFile(slice6GuestRecoveryPrivateSiblingZeroFile, 8<<10)
	if err != nil || slice6ReceiptSHA256(raw) != digest {
		clear(raw)
		return errSlice6ExternalTemp
	}
	clear(raw)
	return run.verifyGuestRecoveryPrivateSiblingZero()
}
