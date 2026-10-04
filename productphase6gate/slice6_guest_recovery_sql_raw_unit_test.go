//go:build phase6slice6gate

package productphase6gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlice6GuestOperatorRawReadbackIsPrivateAndRechecked(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	runID := strings.Repeat("a", 32)
	run, err := root.newRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	row := []byte("connected|false|true|1791087000000000\n")
	backend := []byte("0\n")
	readback := slice6GuestOperatorReadback{RunID: runID,
		ProfileDigest:         "sha256:" + strings.Repeat("1", 64),
		SourceProofDigest:     "sha256:" + strings.Repeat("2", 64),
		SettingsRecheckExecID: strings.Repeat("9", 64),
		SettingsRecheckDigest: slice6ReceiptSHA256([]byte("true|1791080000000000\n")),
		PostmasterStartMicros: 1791080000000000,
		TargetDigest:          "sha256:" + strings.Repeat("3", 64),
		PostgresID:            strings.Repeat("4", 64),
		PostgresFingerprint:   "sha256:" + strings.Repeat("5", 64),
		OperationDigest:       "sha256:" + strings.Repeat("6", 64),
		ReadExecID:            strings.Repeat("b", 64), CheckExecID: strings.Repeat("c", 64),
		ReadExecStartedUTC:   base.Format(time.RFC3339Nano),
		ReadExecFinishedUTC:  base.Add(time.Millisecond).Format(time.RFC3339Nano),
		CheckExecStartedUTC:  base.Add(2 * time.Millisecond).Format(time.RFC3339Nano),
		CheckExecFinishedUTC: base.Add(3 * time.Millisecond).Format(time.RFC3339Nano),
		SQLDigest:            slice6ReceiptSHA256([]byte(slice6GuestOperatorSelect)),
		BackendSQLDigest:     slice6ReceiptSHA256([]byte(slice6GuestOperatorBackendSelect)),
		OutputSHA256:         slice6ReceiptSHA256(row), RawRow: row, RawBackend: backend,
		State: "connected", NonceNull: false, DBTimeUnexpired: true,
		ExpiresUnixMicros: 1791087000000000}
	settingsRaw := []byte("true|1791080000000000\n")
	prepareReceipts := func(value *slice6GuestOperatorReadback) {
		value.SettingsRecheckRaw = settingsRaw
		checkFinish, err := time.Parse(time.RFC3339Nano, value.CheckExecFinishedUTC)
		if err != nil {
			t.Fatal(err)
		}
		value.SettingsRecheckStartedUTC = checkFinish.Add(time.Millisecond).Format(time.RFC3339Nano)
		value.SettingsRecheckFinishedUTC = checkFinish.Add(2 * time.Millisecond).Format(time.RFC3339Nano)
		value.ReadExecExitRaw = slice6GuestOperatorExecExitReceipt(value.ReadExecID,
			value.PostgresID, value.ReadExecFinishedUTC)
		value.CheckExecExitRaw = slice6GuestOperatorExecExitReceipt(value.CheckExecID,
			value.PostgresID, value.CheckExecFinishedUTC)
		value.SettingsRecheckExitRaw = slice6GuestOperatorExecExitReceipt(value.SettingsRecheckExecID,
			value.PostgresID, value.SettingsRecheckFinishedUTC)
	}
	prepareReceipts(&readback)
	binding, err := run.writeV2GuestOperatorRaw("initial", readback)
	if err != nil || binding.RunID != runID || binding.RowSHA256 != readback.OutputSHA256 ||
		run.verifyV2GuestOperatorRaw(binding) != nil {
		t.Fatalf("private initial SQL raw unavailable: %v", err)
	}
	if _, err := run.writeV2GuestOperatorRaw("initial", readback); err == nil {
		t.Fatal("duplicate raw stage replaced the first readback")
	}
	if _, err := run.writeV2GuestOperatorRaw("unknown", readback); err == nil {
		t.Fatal("unknown SQL raw stage accepted")
	}
	var stages [4]slice6GuestOperatorRawBinding
	stages[0] = binding
	execChars := [3][2]string{{"d", "e"}, {"f", "a"}, {"1", "2"}}
	for index, stage := range []string{"released", "reconnected", "final_released"} {
		later := readback
		later.ReadExecID = strings.Repeat(execChars[index][0], 64)
		later.CheckExecID = strings.Repeat(execChars[index][1], 64)
		later.SettingsRecheckExecID = strings.Repeat(string(rune('8'-index)), 64)
		later.OperationDigest = "sha256:" + strings.Repeat(string(rune('7'+index)), 64)
		shift := time.Duration(index+1) * 10 * time.Millisecond
		later.ReadExecStartedUTC = base.Add(shift).Format(time.RFC3339Nano)
		later.ReadExecFinishedUTC = base.Add(shift + time.Millisecond).Format(time.RFC3339Nano)
		later.CheckExecStartedUTC = base.Add(shift + 2*time.Millisecond).Format(time.RFC3339Nano)
		later.CheckExecFinishedUTC = base.Add(shift + 3*time.Millisecond).Format(time.RFC3339Nano)
		if stage == "released" || stage == "final_released" {
			later.RawRow = []byte("disconnected|true|true|1791087000000000\n")
			later.State, later.NonceNull = "disconnected", true
		}
		later.OutputSHA256 = slice6ReceiptSHA256(later.RawRow)
		prepareReceipts(&later)
		stages[index+1], err = run.writeV2GuestOperatorRaw(stage, later)
		if err != nil {
			t.Fatalf("private %s SQL raw unavailable: %v", stage, err)
		}
	}
	if err := run.verifyV2GuestOperatorStages(stages); err != nil {
		t.Fatalf("ordered private SQL stages unavailable: %v", err)
	}
	drift := stages
	drift[2].ExpiresUnixMicros++
	if err := run.verifyV2GuestOperatorStages(drift); err == nil {
		t.Fatal("cross-stage expiry drift accepted")
	}
	drift = stages
	drift[2].ReadExecID = drift[0].ReadExecID
	if err := run.verifyV2GuestOperatorStages(drift); err == nil {
		t.Fatal("cross-stage Docker exec replay accepted")
	}
	for _, name := range []string{binding.RowFile, binding.BackendFile, binding.SettingsFile,
		binding.ReadExitFile, binding.CheckExitFile, binding.SettingsExitFile} {
		info, err := os.Lstat(filepath.Join(rootPath, runID, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatal("SQL raw file not private")
		}
	}
	file, err := os.OpenFile(filepath.Join(rootPath, runID, binding.RowFile), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{'x'}, 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run.verifyV2GuestOperatorRaw(binding); err == nil {
		t.Fatal("tampered private SQL raw accepted")
	}
	if err := run.closeV2Incomplete(); err != nil {
		t.Fatal(err)
	}
}
