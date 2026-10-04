//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"golang.org/x/sys/unix"
)

const slice6GuestRecoveryFileInventoryName = "guest-e-file-inventory.json"

type slice6GuestRecoveryFileEntry struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
}

type slice6GuestRecoveryFileInventory struct {
	Protocol    string                         `json:"protocol"`
	RunID       string                         `json:"run_id"`
	RecordedUTC string                         `json:"recorded_utc"`
	RootDev     uint64                         `json:"root_dev"`
	RootIno     uint64                         `json:"root_ino"`
	RunDev      uint64                         `json:"run_dev"`
	RunIno      uint64                         `json:"run_ino"`
	Files       []slice6GuestRecoveryFileEntry `json:"files"`
}

// This is the complete successful-E pre-binding inventory. Failure markers,
// cleanup-only v3 results and future final bindings are deliberately excluded.
func slice6GuestRecoveryEFileLimits() map[string]int {
	limits := make(map[string]int)
	add := func(name string, limit int) { limits[name] = limit }
	for _, name := range slice6GuestOperatorSourceRawNames() {
		add(name, slice6GuestOperatorSourceRawLimit(name))
	}
	for _, stage := range []string{"initial", "released", "reconnected", "final_released"} {
		row, backend := slice6GuestOperatorRawNames(stage)
		settings, readExit, checkExit, settingsExit := slice6GuestOperatorAdditionalRawNames(stage)
		for _, name := range []string{row, backend, settings, readExit, checkExit, settingsExit} {
			add(name, 128<<10)
		}
	}
	for _, process := range []string{"product-a", "guest-a", "product-b", "guest-b"} {
		add(slice6GuestRecoveryRawName(process), 128<<10)
	}
	for _, process := range []string{"product-b", "guest-b"} {
		add(slice6GuestRecoveryStartInspectName(process), 640)
	}
	for _, name := range []string{slice6GuestRecoveryEventJournalFile,
		slice6GuestRecoveryCreatedProductRaw, slice6GuestRecoveryCreatedRuntimeRaw,
		slice6GuestRecoveryCreatedReceiptRaw, slice6GuestRecoveryBeforeBFile,
		slice6GuestRecoveryRecoveredCloseFile, "guest-zero-origin.inspect",
		"guest-zero-origin-file-volume.label", "guest-zero-origin-logs-volume.label",
		"guest-zero-origin-receipt.json", "guest-zero-receipt.json",
		"guest-zero-exact-origins.json", slice6GuestRecoveryPrivateSiblingZeroFile,
		slice6EConvergenceFile,
		slice6TerminalV3PlanFile, slice6TerminalV3BindingFile,
		slice6TerminalLedgerProjectionFile} {
		add(name, 128<<10)
	}
	for index, name := range slice6GuestRecoveryActionRawNames {
		add(name, 1024)
		for _, rawName := range slice6GuestRecoveryActionDockerRawNames(index) {
			add(rawName, 16<<10)
		}
	}
	for _, name := range slice6GuestRecoveryDockerZeroRawNames {
		add(name, 512)
	}
	for _, name := range slice6GuestRecoveryExactOriginZeroRawNames {
		add(name, 512)
	}
	add(slice6TerminalV3EvidenceFile, phase6terminalcleanup.MaxEvidenceV3Bytes)
	return limits
}

func slice6GuestRecoveryDirectoryNames(run *slice6ReceiptEvidenceRun) ([]string, error) {
	if run == nil || run.check() != nil {
		return nil, errSlice6ReceiptEvidence
	}
	dup, err := unix.Dup(run.fd)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	dir := os.NewFile(uintptr(dup), "guest-e-run")
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return nil, errSlice6ReceiptEvidence
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names, nil
}

func slice6GuestRecoveryExpectedNames(limits map[string]int, inventory bool) []string {
	names := make([]string, 0, len(limits)+1)
	for name := range limits {
		names = append(names, name)
	}
	if inventory {
		names = append(names, slice6GuestRecoveryFileInventoryName)
	}
	slices.Sort(names)
	return names
}

// Capture is a pre-admission table, not a final E disposition. It pins the
// exact retained files before the independently reopened read-only replay.
func (run *slice6ReceiptEvidenceRun) captureGuestRecoveryEFileInventory() (string, error) {
	if run == nil || run.check() != nil {
		return "", errSlice6ReceiptEvidence
	}
	limits := slice6GuestRecoveryEFileLimits()
	want := slice6GuestRecoveryExpectedNames(limits, false)
	actual, err := slice6GuestRecoveryDirectoryNames(run)
	if err != nil || !slices.Equal(actual, want) {
		return "", errSlice6ReceiptEvidence
	}
	run.mu.Lock()
	files := make(map[string]unix.Stat_t, len(run.files))
	for name, stat := range run.files {
		files[name] = stat
	}
	run.mu.Unlock()
	if len(files) != len(want) {
		return "", errSlice6ReceiptEvidence
	}
	inventory := slice6GuestRecoveryFileInventory{
		Protocol: "sandbox-runtime.phase6-guest-e-file-inventory.v1", RunID: run.id,
		RecordedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		RootDev:     uint64(run.root.stat.Dev), RootIno: run.root.stat.Ino,
		RunDev: uint64(run.stat.Dev), RunIno: run.stat.Ino,
		Files: make([]slice6GuestRecoveryFileEntry, 0, len(want)),
	}
	for _, name := range want {
		stat, ok := files[name]
		if !ok || limits[name] < 1 || stat.Ino == 0 {
			return "", errSlice6ReceiptEvidence
		}
		raw, err := run.readFile(name, limits[name])
		if err != nil {
			return "", errSlice6ReceiptEvidence
		}
		inventory.Files = append(inventory.Files, slice6GuestRecoveryFileEntry{
			Name: name, Bytes: len(raw), SHA256: slice6ReceiptSHA256(raw),
			Dev: uint64(stat.Dev), Ino: stat.Ino,
		})
		clear(raw)
	}
	raw, err := json.Marshal(inventory)
	if err != nil || len(raw) > 32<<10 ||
		run.writeV2BoundedPrivateFile(slice6GuestRecoveryFileInventoryName, raw, 32<<10, false) != nil {
		return "", errSlice6ReceiptEvidence
	}
	return slice6ReceiptSHA256(raw), nil
}

// These two entry points deliberately separate a pre-binding file replay
// from post-close failure evidence. An incomplete marker can never satisfy
// the former, and its absence can never satisfy the latter.
func slice6VerifyGuestRecoveryEFileInventory(rootPath, id, expectedDigest string) error {
	return slice6ReplayGuestRecoveryEFileInventory(rootPath, id, expectedDigest, false, false)
}

func slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, expectedDigest string) error {
	return slice6ReplayGuestRecoveryEFileInventory(rootPath, id, expectedDigest, true, false)
}

func slice6VerifyGuestRecoveryEFinalFileInventory(rootPath, id, expectedDigest string) error {
	return slice6ReplayGuestRecoveryEFileInventory(rootPath, id, expectedDigest, false, true)
}

// Reopens the retained root and run with no writer-owned inode map. The
// expected digest is supplied by the caller/freeze, never loaded from here.
// Neither entry point by itself is a successful E disposition.
func slice6ReplayGuestRecoveryEFileInventory(rootPath, id, expectedDigest string,
	requireIncomplete, requireFinal bool) (result error) {
	if !guestRevokeFixtureDigestGate(expectedDigest) || (requireIncomplete && requireFinal) {
		return errSlice6ReceiptEvidence
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() {
		if root.close() != nil {
			result = errSlice6ReceiptEvidence
		}
	}()
	run, err := root.openRun(id)
	if err != nil {
		return err
	}
	defer func() {
		if unix.Close(run.fd) != nil {
			result = errSlice6ReceiptEvidence
		}
	}()
	limits := slice6GuestRecoveryEFileLimits()
	want := slice6GuestRecoveryExpectedNames(limits, true)
	if requireFinal {
		want = append(want, slice6GuestEFinalBindingFile)
		slices.Sort(want)
	}
	actual, err := slice6GuestRecoveryDirectoryNames(run)
	withIncomplete := append(slices.Clone(want), "incomplete.json")
	slices.Sort(withIncomplete)
	incomplete := slices.Equal(actual, withIncomplete)
	if err != nil || incomplete != requireIncomplete ||
		(!slices.Equal(actual, want) && !incomplete) {
		return errSlice6ReceiptEvidence
	}
	for _, name := range actual {
		var stat unix.Stat_t
		if unix.Fstatat(run.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 ||
			stat.Uid != uint32(os.Getuid()) || stat.Ino == 0 {
			return errSlice6ReceiptEvidence
		}
		run.files[name] = stat
	}
	if incomplete {
		marker, err := run.readFile("incomplete.json", 8192)
		if err != nil || len(marker) < 2 || marker[len(marker)-1] != '\n' {
			return errSlice6ReceiptEvidence
		}
		var state struct {
			Protocol    string `json:"protocol"`
			Disposition string `json:"disposition"`
			RunID       string `json:"run_id"`
			RecordedUTC string `json:"recorded_utc"`
		}
		if json.Unmarshal(marker[:len(marker)-1], &state) != nil {
			return errSlice6ReceiptEvidence
		}
		canonical, err := json.Marshal(state)
		if err != nil || !bytes.Equal(canonical, marker[:len(marker)-1]) ||
			state.Protocol != "sandbox-runtime.phase6-guest-recovery-evidence.v2" ||
			state.Disposition != "incomplete" || state.RunID != id {
			return errSlice6ReceiptEvidence
		}
		if parsed, err := time.Parse(time.RFC3339Nano, state.RecordedUTC); err != nil || parsed.IsZero() {
			return errSlice6ReceiptEvidence
		}
	}
	raw, err := run.readFile(slice6GuestRecoveryFileInventoryName, 32<<10)
	if err != nil || slice6ReceiptSHA256(raw) != expectedDigest {
		return errSlice6ReceiptEvidence
	}
	var inventory slice6GuestRecoveryFileInventory
	if json.Unmarshal(raw, &inventory) != nil {
		return errSlice6ReceiptEvidence
	}
	canonical, err := json.Marshal(inventory)
	if err != nil || !bytes.Equal(raw, canonical) ||
		inventory.Protocol != "sandbox-runtime.phase6-guest-e-file-inventory.v1" ||
		inventory.RunID != id || inventory.RootDev != uint64(root.stat.Dev) ||
		inventory.RootIno != root.stat.Ino || inventory.RunDev != uint64(run.stat.Dev) ||
		inventory.RunIno != run.stat.Ino || len(inventory.Files) != len(limits) {
		return errSlice6ReceiptEvidence
	}
	if parsed, err := time.Parse(time.RFC3339Nano, inventory.RecordedUTC); err != nil || parsed.IsZero() {
		return errSlice6ReceiptEvidence
	}
	for index, name := range slice6GuestRecoveryExpectedNames(limits, false) {
		entry := inventory.Files[index]
		stat := run.files[name]
		if entry.Name != name || entry.Bytes < 0 || entry.Bytes > limits[name] ||
			entry.Dev != uint64(stat.Dev) || entry.Ino != stat.Ino ||
			!guestRevokeFixtureDigestGate(entry.SHA256) {
			return errSlice6ReceiptEvidence
		}
		data, err := run.readFile(name, limits[name])
		if err != nil || len(data) != entry.Bytes || slice6ReceiptSHA256(data) != entry.SHA256 {
			clear(data)
			return errSlice6ReceiptEvidence
		}
		clear(data)
	}
	return run.check()
}
