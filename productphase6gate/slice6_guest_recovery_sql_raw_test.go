//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

type slice6GuestOperatorRawBinding struct {
	Stage, RowFile, BackendFile                                         string
	SettingsFile, ReadExitFile, CheckExitFile, SettingsExitFile         string
	RunID, RowSHA256, BackendSHA256                                     string
	SettingsSHA256, ReadExitSHA256, CheckExitSHA256, SettingsExitSHA256 string
	ProfileDigest, SourceProofDigest                                    string
	SettingsRecheckExecID, SettingsRecheckDigest                        string
	PostmasterStartMicros                                               int64
	TargetDigest, PostgresID                                            string
	PGFingerprint, OperationDigest                                      string
	ReadExecID, CheckExecID                                             string
	ReadStartedUTC, ReadFinishedUTC                                     string
	CheckStartedUTC, CheckFinishedUTC                                   string
	SettingsStartedUTC, SettingsFinishedUTC                             string
	State                                                               string
	NonceNull, DBTimeUnexpired                                          bool
	ExpiresUnixMicros                                                   int64
}

func slice6GuestOperatorAdditionalRawNames(stage string) (string, string, string, string) {
	if row, _ := slice6GuestOperatorRawNames(stage); row == "" {
		return "", "", "", ""
	}
	base := "guest-recovery-" + stage + "-"
	return base + "settings.stdout", base + "read-exit.receipt",
		base + "check-exit.receipt", base + "settings-exit.receipt"
}

func slice6GuestOperatorRawNames(stage string) (string, string) {
	switch stage {
	case "initial", "released", "reconnected", "final_released":
		return "guest-recovery-" + stage + "-sql-row.stdout",
			"guest-recovery-" + stage + "-sql-backend.stdout"
	default:
		return "", ""
	}
}

// Store the actual bounded SQL stdout, not a reconstructed row or digest-
// only assertion. Partial writes are retained in an incomplete run, never
// substituted by a fresh query or released as an accepted binding.
func (run *slice6ReceiptEvidenceRun) writeV2GuestOperatorRaw(stage string,
	readback slice6GuestOperatorReadback) (slice6GuestOperatorRawBinding, error) {
	rowName, backendName := slice6GuestOperatorRawNames(stage)
	settingsName, readExitName, checkExitName, settingsExitName := slice6GuestOperatorAdditionalRawNames(stage)
	readStart, readStartErr := time.Parse(time.RFC3339Nano, readback.ReadExecStartedUTC)
	readFinish, readFinishErr := time.Parse(time.RFC3339Nano, readback.ReadExecFinishedUTC)
	checkStart, checkStartErr := time.Parse(time.RFC3339Nano, readback.CheckExecStartedUTC)
	checkFinish, checkFinishErr := time.Parse(time.RFC3339Nano, readback.CheckExecFinishedUTC)
	settingsStart, settingsStartErr := time.Parse(time.RFC3339Nano, readback.SettingsRecheckStartedUTC)
	settingsFinish, settingsFinishErr := time.Parse(time.RFC3339Nano, readback.SettingsRecheckFinishedUTC)
	if run == nil || run.check() != nil || rowName == "" || readback.RunID != run.id ||
		!guestRevokeFixtureDigestGate(readback.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(readback.SourceProofDigest) ||
		!guestRevokeFixtureDigestGate(readback.SettingsRecheckDigest) ||
		len(readback.SettingsRecheckExecID) != 64 || !lowerHexSlice6(readback.SettingsRecheckExecID) ||
		readback.PostmasterStartMicros < 1_577_836_800_000_000 ||
		readback.PostmasterStartMicros > 4_102_444_800_000_000 ||
		!guestRevokeFixtureDigestGate(readback.TargetDigest) ||
		!guestRevokeFixtureDigestGate(readback.PostgresFingerprint) ||
		!guestRevokeFixtureDigestGate(readback.OperationDigest) ||
		len(readback.PostgresID) != 64 || !lowerHexSlice6(readback.PostgresID) ||
		len(readback.ReadExecID) != 64 || !lowerHexSlice6(readback.ReadExecID) ||
		len(readback.CheckExecID) != 64 || !lowerHexSlice6(readback.CheckExecID) ||
		readback.ReadExecID == readback.CheckExecID ||
		readback.SettingsRecheckExecID == readback.ReadExecID ||
		readback.SettingsRecheckExecID == readback.CheckExecID ||
		readStartErr != nil || readFinishErr != nil || checkStartErr != nil || checkFinishErr != nil ||
		!readFinish.After(readStart) || !checkStart.After(readFinish) || !checkFinish.After(checkStart) ||
		settingsStartErr != nil || settingsFinishErr != nil || !settingsStart.After(checkFinish) ||
		!settingsFinish.After(settingsStart) ||
		len(readback.RawRow) < 2 || len(readback.RawRow) > 128 ||
		!bytes.Equal(readback.RawBackend, []byte("0\n")) ||
		slice6ReceiptSHA256(readback.SettingsRecheckRaw) != readback.SettingsRecheckDigest ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: readback.ReadExecID,
			ContainerID: readback.PostgresID, StartedUTC: readback.ReadExecStartedUTC,
			FinishedUTC: readback.ReadExecFinishedUTC, ExitReceipt: readback.ReadExecExitRaw}) != nil ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: readback.CheckExecID,
			ContainerID: readback.PostgresID, StartedUTC: readback.CheckExecStartedUTC,
			FinishedUTC: readback.CheckExecFinishedUTC, ExitReceipt: readback.CheckExecExitRaw}) != nil ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: readback.SettingsRecheckExecID,
			ContainerID: readback.PostgresID, StartedUTC: readback.SettingsRecheckStartedUTC,
			FinishedUTC: readback.SettingsRecheckFinishedUTC,
			ExitReceipt: readback.SettingsRecheckExitRaw}) != nil ||
		slice6ReceiptSHA256(readback.RawRow) != readback.OutputSHA256 ||
		readback.BackendSQLDigest != slice6ReceiptSHA256([]byte(slice6GuestOperatorBackendSelect)) ||
		readback.SQLDigest != slice6ReceiptSHA256([]byte(slice6GuestOperatorSelect)) {
		return slice6GuestOperatorRawBinding{}, phase6guestreceipt.ErrUnavailable
	}
	settingsMicros, settingsErr := slice6ParseGuestOperatorSettingsOutput(readback.SettingsRecheckRaw)
	if settingsErr != nil || settingsMicros != readback.PostmasterStartMicros {
		return slice6GuestOperatorRawBinding{}, phase6guestreceipt.ErrUnavailable
	}
	state, nonceNull, unexpired, expiry, err := slice6CheckGuestOperatorRow(readback.RawRow, nil, false)
	if err != nil || state != readback.State || nonceNull != readback.NonceNull ||
		unexpired != readback.DBTimeUnexpired || expiry != readback.ExpiresUnixMicros ||
		((stage == "released" || stage == "final_released") && (state != "disconnected" || !nonceNull)) ||
		((stage == "initial" || stage == "reconnected") && (state != "connected" || nonceNull)) {
		return slice6GuestOperatorRawBinding{}, phase6guestreceipt.ErrUnavailable
	}
	write := func(name string, raw []byte) error {
		run.mu.Lock()
		if run.check() != nil || run.closed {
			run.mu.Unlock()
			return phase6guestreceipt.ErrUnavailable
		}
		file, err := run.createPrivateFileLocked(name)
		run.mu.Unlock()
		if err != nil {
			return phase6guestreceipt.ErrUnavailable
		}
		written, writeErr := file.Write(raw)
		syncErr := run.syncFile(file)
		closeErr := file.Close()
		if written != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil ||
			run.syncDir(run.fd) != nil {
			return phase6guestreceipt.ErrUnavailable
		}
		observed, err := run.readFile(name, 256)
		defer clear(observed)
		if err != nil || !bytes.Equal(observed, raw) {
			return phase6guestreceipt.ErrUnavailable
		}
		return nil
	}
	if err := write(rowName, readback.RawRow); err != nil {
		return slice6GuestOperatorRawBinding{}, err
	}
	if err := write(backendName, readback.RawBackend); err != nil {
		return slice6GuestOperatorRawBinding{}, err
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{
		{settingsName, readback.SettingsRecheckRaw},
		{readExitName, readback.ReadExecExitRaw},
		{checkExitName, readback.CheckExecExitRaw},
		{settingsExitName, readback.SettingsRecheckExitRaw},
	} {
		if err := write(item.name, item.raw); err != nil {
			return slice6GuestOperatorRawBinding{}, err
		}
	}
	return slice6GuestOperatorRawBinding{Stage: stage,
		RowFile: rowName, BackendFile: backendName, RunID: run.id,
		SettingsFile: settingsName, ReadExitFile: readExitName,
		CheckExitFile: checkExitName, SettingsExitFile: settingsExitName,
		SettingsSHA256:     slice6ReceiptSHA256(readback.SettingsRecheckRaw),
		ReadExitSHA256:     slice6ReceiptSHA256(readback.ReadExecExitRaw),
		CheckExitSHA256:    slice6ReceiptSHA256(readback.CheckExecExitRaw),
		SettingsExitSHA256: slice6ReceiptSHA256(readback.SettingsRecheckExitRaw),
		ProfileDigest:      readback.ProfileDigest, SourceProofDigest: readback.SourceProofDigest,
		SettingsRecheckExecID: readback.SettingsRecheckExecID,
		SettingsRecheckDigest: readback.SettingsRecheckDigest,
		PostmasterStartMicros: readback.PostmasterStartMicros,
		TargetDigest:          readback.TargetDigest, PostgresID: readback.PostgresID,
		PGFingerprint: readback.PostgresFingerprint, OperationDigest: readback.OperationDigest,
		RowSHA256: readback.OutputSHA256, BackendSHA256: slice6ReceiptSHA256(readback.RawBackend),
		ReadExecID: readback.ReadExecID, CheckExecID: readback.CheckExecID,
		ReadStartedUTC: readback.ReadExecStartedUTC, ReadFinishedUTC: readback.ReadExecFinishedUTC,
		CheckStartedUTC: readback.CheckExecStartedUTC, CheckFinishedUTC: readback.CheckExecFinishedUTC,
		SettingsStartedUTC:  readback.SettingsRecheckStartedUTC,
		SettingsFinishedUTC: readback.SettingsRecheckFinishedUTC,
		State:               state, NonceNull: nonceNull, DBTimeUnexpired: unexpired,
		ExpiresUnixMicros: expiry}, nil
}

func (run *slice6ReceiptEvidenceRun) verifyV2GuestOperatorRaw(binding slice6GuestOperatorRawBinding) error {
	rowName, backendName := slice6GuestOperatorRawNames(binding.Stage)
	settingsName, readExitName, checkExitName, settingsExitName := slice6GuestOperatorAdditionalRawNames(binding.Stage)
	if run == nil || run.check() != nil || rowName == "" || binding.RunID != run.id ||
		binding.RowFile != rowName || binding.BackendFile != backendName ||
		binding.SettingsFile != settingsName || binding.ReadExitFile != readExitName ||
		binding.CheckExitFile != checkExitName || binding.SettingsExitFile != settingsExitName ||
		!guestRevokeFixtureDigestGate(binding.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(binding.SourceProofDigest) ||
		!guestRevokeFixtureDigestGate(binding.SettingsRecheckDigest) ||
		len(binding.SettingsRecheckExecID) != 64 || !lowerHexSlice6(binding.SettingsRecheckExecID) ||
		binding.PostmasterStartMicros < 1_577_836_800_000_000 ||
		binding.PostmasterStartMicros > 4_102_444_800_000_000 ||
		!guestRevokeFixtureDigestGate(binding.TargetDigest) ||
		!guestRevokeFixtureDigestGate(binding.PGFingerprint) ||
		!guestRevokeFixtureDigestGate(binding.OperationDigest) ||
		len(binding.PostgresID) != 64 || !lowerHexSlice6(binding.PostgresID) ||
		len(binding.ReadExecID) != 64 || !lowerHexSlice6(binding.ReadExecID) ||
		len(binding.CheckExecID) != 64 || !lowerHexSlice6(binding.CheckExecID) ||
		binding.ReadExecID == binding.CheckExecID {
		return phase6guestreceipt.ErrUnavailable
	}
	if binding.SettingsRecheckExecID == binding.ReadExecID ||
		binding.SettingsRecheckExecID == binding.CheckExecID {
		return phase6guestreceipt.ErrUnavailable
	}
	row, rowErr := run.readFile(rowName, 128)
	backend, backendErr := run.readFile(backendName, 128)
	settings, settingsErr := run.readFile(settingsName, 32)
	readExit, readExitErr := run.readFile(readExitName, 256)
	checkExit, checkExitErr := run.readFile(checkExitName, 256)
	settingsExit, settingsExitErr := run.readFile(settingsExitName, 256)
	defer clear(row)
	defer clear(backend)
	defer clear(settings)
	defer clear(readExit)
	defer clear(checkExit)
	defer clear(settingsExit)
	if rowErr != nil || backendErr != nil || !bytes.Equal(backend, []byte("0\n")) ||
		slice6ReceiptSHA256(row) != binding.RowSHA256 ||
		slice6ReceiptSHA256(backend) != binding.BackendSHA256 ||
		settingsErr != nil || readExitErr != nil || checkExitErr != nil || settingsExitErr != nil ||
		slice6ReceiptSHA256(settings) != binding.SettingsSHA256 ||
		slice6ReceiptSHA256(readExit) != binding.ReadExitSHA256 ||
		slice6ReceiptSHA256(checkExit) != binding.CheckExitSHA256 ||
		slice6ReceiptSHA256(settingsExit) != binding.SettingsExitSHA256 ||
		binding.SettingsSHA256 != binding.SettingsRecheckDigest ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: binding.ReadExecID,
			ContainerID: binding.PostgresID, StartedUTC: binding.ReadStartedUTC,
			FinishedUTC: binding.ReadFinishedUTC, ExitReceipt: readExit}) != nil ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: binding.CheckExecID,
			ContainerID: binding.PostgresID, StartedUTC: binding.CheckStartedUTC,
			FinishedUTC: binding.CheckFinishedUTC, ExitReceipt: checkExit}) != nil ||
		slice6CheckGuestOperatorExecExitReceipt(slice6GuestOperatorExec{ID: binding.SettingsRecheckExecID,
			ContainerID: binding.PostgresID, StartedUTC: binding.SettingsStartedUTC,
			FinishedUTC: binding.SettingsFinishedUTC, ExitReceipt: settingsExit}) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	settingsMicros, settingsParseErr := slice6ParseGuestOperatorSettingsOutput(settings)
	if settingsParseErr != nil || settingsMicros != binding.PostmasterStartMicros {
		return phase6guestreceipt.ErrUnavailable
	}
	state, nonceNull, unexpired, expiry, err := slice6CheckGuestOperatorRow(row, nil, false)
	if err != nil || state != binding.State || nonceNull != binding.NonceNull ||
		unexpired != binding.DBTimeUnexpired || expiry != binding.ExpiresUnixMicros ||
		((binding.Stage == "released" || binding.Stage == "final_released") && (state != "disconnected" || !nonceNull)) ||
		((binding.Stage == "initial" || binding.Stage == "reconnected") && (state != "connected" || nonceNull)) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

// This is a structural cross-stage SQL check only. The caller must still
// bind its action ordering to actual Product/Guest receipts and PG fault.
func (run *slice6ReceiptEvidenceRun) verifyV2GuestOperatorStages(
	bindings [4]slice6GuestOperatorRawBinding) error {
	want := [4]string{"initial", "released", "reconnected", "final_released"}
	ids := make(map[string]bool, 12)
	operations := make(map[string]bool, 4)
	var previousFinish time.Time
	for index, binding := range bindings {
		readStart, readStartErr := time.Parse(time.RFC3339Nano, binding.ReadStartedUTC)
		readFinish, readFinishErr := time.Parse(time.RFC3339Nano, binding.ReadFinishedUTC)
		checkStart, checkStartErr := time.Parse(time.RFC3339Nano, binding.CheckStartedUTC)
		checkFinish, checkFinishErr := time.Parse(time.RFC3339Nano, binding.CheckFinishedUTC)
		settingsStart, settingsStartErr := time.Parse(time.RFC3339Nano, binding.SettingsStartedUTC)
		settingsFinish, settingsFinishErr := time.Parse(time.RFC3339Nano, binding.SettingsFinishedUTC)
		if binding.Stage != want[index] || run.verifyV2GuestOperatorRaw(binding) != nil ||
			binding.RunID != bindings[0].RunID ||
			binding.ProfileDigest != bindings[0].ProfileDigest ||
			binding.SourceProofDigest != bindings[0].SourceProofDigest ||
			binding.SettingsRecheckDigest != bindings[0].SettingsRecheckDigest ||
			binding.PostmasterStartMicros != bindings[0].PostmasterStartMicros ||
			binding.TargetDigest != bindings[0].TargetDigest ||
			binding.PostgresID != bindings[0].PostgresID ||
			binding.PGFingerprint != bindings[0].PGFingerprint ||
			binding.ExpiresUnixMicros != bindings[0].ExpiresUnixMicros ||
			!binding.DBTimeUnexpired ||
			readStartErr != nil || readFinishErr != nil || checkStartErr != nil || checkFinishErr != nil ||
			!readFinish.After(readStart) || !checkStart.After(readFinish) ||
			!checkFinish.After(checkStart) || settingsStartErr != nil || settingsFinishErr != nil ||
			!settingsStart.After(checkFinish) || !settingsFinish.After(settingsStart) ||
			(index > 0 && !readStart.After(previousFinish)) ||
			ids[binding.ReadExecID] || ids[binding.CheckExecID] ||
			ids[binding.SettingsRecheckExecID] || operations[binding.OperationDigest] {
			return phase6guestreceipt.ErrUnavailable
		}
		ids[binding.ReadExecID], ids[binding.CheckExecID], ids[binding.SettingsRecheckExecID] = true, true, true
		operations[binding.OperationDigest] = true
		previousFinish = settingsFinish
	}
	return nil
}
