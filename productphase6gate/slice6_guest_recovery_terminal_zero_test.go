//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type slice6GuestRecoveryTerminalZeroPreflight struct {
	Precleanup               slice6GuestRecoveryPrecleanupInput
	TerminalBindingDigest    string
	OperatorBinaryDigest     string
	OperatorContainerID      string
	DockerZero               slice6GuestRecoveryDockerZeroReceipt
	ExactOriginZero          slice6GuestRecoveryExactOriginZeroReceipt
	PrivateSiblingZeroDigest string
}

// This is a sealed evidence-join preflight, not an accepted E disposition.
// The formal launcher must call it after the exact original operator and
// Docker resources have stopped, before considering non-Docker resource zero.
func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryTerminalZeroPreflight(
	ctx context.Context, input slice6GuestRecoveryTerminalZeroPreflight) (string, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		!guestRevokeFixtureDigestGate(input.TerminalBindingDigest) ||
		!guestRevokeFixtureDigestGate(input.OperatorBinaryDigest) ||
		len(input.OperatorContainerID) != 64 || !lowerHexSlice6(input.OperatorContainerID) {
		return "", errors.New("Guest E terminal-zero preflight input unavailable")
	}
	precleanupDigest, err := run.verifyGuestRecoveryPrecleanup(ctx, input.Precleanup)
	if err != nil || input.DockerZero.PrecleanupDigest != precleanupDigest ||
		input.ExactOriginZero.PrecleanupDigest != precleanupDigest {
		return "", errors.New("Guest E terminal-zero precleanup replay unavailable")
	}
	if run.verifyTerminalV3Binding(input.TerminalBindingDigest, precleanupDigest,
		input.OperatorBinaryDigest, input.OperatorContainerID) != nil ||
		run.verifyGuestRecoveryDockerZeroRaw(input.DockerZero) != nil ||
		run.verifyGuestRecoveryExactOriginZeroRaw(input.Precleanup,
			input.DockerZero, input.ExactOriginZero) != nil ||
		run.verifyGuestRecoveryPrivateSiblingZeroDigest(input.PrivateSiblingZeroDigest) != nil {
		return "", errors.New("Guest E terminal Vault/Docker evidence replay unavailable")
	}
	projectionRaw, err := run.readFile(slice6TerminalLedgerProjectionFile, slice6TerminalLedgerProjectionLimit)
	if err != nil || slice6VerifyTerminalEIssuedSet(projectionRaw, input.Precleanup.Source.profile) != nil {
		clear(projectionRaw)
		return "", errors.New("Guest E exact issued set does not match the fixed launch path")
	}
	clear(projectionRaw)
	terminalRaw, err := run.readFile(slice6TerminalV3BindingFile, 2048)
	if err != nil {
		return "", err
	}
	defer clear(terminalRaw)
	var terminal slice6TerminalV3Binding
	if json.Unmarshal(terminalRaw, &terminal) != nil {
		return "", errors.New("Guest E terminal process interval unavailable")
	}
	operatorStarted, err := time.Parse(time.RFC3339Nano, terminal.OperatorStartUTC)
	if err != nil {
		return "", errors.New("Guest E terminal process start unavailable")
	}
	for _, process := range input.Precleanup.Process {
		finished, parseErr := time.Parse(time.RFC3339Nano, process.FinishedAt)
		if parseErr != nil || !operatorStarted.After(finished) {
			return "", errors.New("Guest E terminal operator overlapped an original Product/Guest PID1")
		}
	}
	for _, stage := range input.Precleanup.SQL {
		finished, parseErr := time.Parse(time.RFC3339Nano, stage.SettingsFinishedUTC)
		if parseErr != nil || !operatorStarted.After(finished) {
			return "", errors.New("Guest E terminal operator preceded final PostgreSQL readback")
		}
	}
	operatorFinished, err := time.Parse(time.RFC3339Nano, terminal.OperatorFinishUTC)
	if err != nil {
		return "", errors.New("Guest E terminal process finish unavailable")
	}
	zeroStarted, err := time.Parse(time.RFC3339Nano, input.DockerZero.StartedUTC)
	if err != nil || zeroStarted.Before(operatorFinished) {
		return "", errors.New("Guest E Docker-zero preceded terminal operator exit")
	}
	exactStarted, err := time.Parse(time.RFC3339Nano, input.ExactOriginZero.StartedUTC)
	if err != nil {
		return "", errors.New("Guest E exact-origin absence interval unavailable")
	}
	zeroFinished, err := time.Parse(time.RFC3339Nano, input.DockerZero.FinishedUTC)
	if err != nil || exactStarted.Before(zeroFinished) {
		return "", errors.New("Guest E exact-origin absence preceded Docker-zero")
	}
	dockerRaw, err := json.Marshal(input.DockerZero)
	if err != nil {
		return "", err
	}
	defer clear(dockerRaw)
	exactRaw, err := json.Marshal(input.ExactOriginZero)
	if err != nil {
		return "", err
	}
	defer clear(exactRaw)
	digest := slice6GuestRecoveryTerminalZeroDigest(run.id, precleanupDigest,
		input.TerminalBindingDigest, slice6ReceiptSHA256(dockerRaw),
		slice6ReceiptSHA256(exactRaw), input.PrivateSiblingZeroDigest)
	if digest == "" {
		return "", errors.New("Guest E terminal-zero digest relationship unavailable")
	}
	return digest, nil
}

func slice6GuestRecoveryTerminalZeroDigest(runID, precleanup, terminal,
	dockerZero, exactZero, privateZero string) string {
	if len(runID) != 32 || !lowerHexSlice6(runID) ||
		!guestRevokeFixtureDigestGate(precleanup) || !guestRevokeFixtureDigestGate(terminal) ||
		!guestRevokeFixtureDigestGate(dockerZero) || !guestRevokeFixtureDigestGate(exactZero) ||
		!guestRevokeFixtureDigestGate(privateZero) {
		return ""
	}
	return slice6ReceiptSHA256([]byte("phase6-guest-e-terminal-zero-preflight.v1|" +
		runID + "|" + precleanup + "|" + terminal + "|" + dockerZero + "|" +
		exactZero + "|" + privateZero))
}

func TestSlice6GuestRecoveryTerminalZeroRejectsMissingOrCrossRunPrecleanup(t *testing.T) {
	const runID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sink := slice6NewTerminalV3DiagnosticSink(t, runID)
	if _, err := sink.Run.newGuestRecoveryFormalTerminalV3Sink(t.Context(),
		slice6GuestRecoveryPrecleanupInput{}); err == nil {
		t.Fatal("formal terminal sink accepted missing E precleanup")
	}
	foreign := slice6GuestRecoveryPrecleanupInput{Source: slice6GuestOperatorFormalSource{
		evidence: sink.Run, runID: strings.Repeat("b", 32)}}
	if _, err := sink.Run.newGuestRecoveryFormalTerminalV3Sink(t.Context(), foreign); err == nil {
		t.Fatal("formal terminal sink accepted a foreign E run")
	}
	if _, err := sink.Run.verifyGuestRecoveryTerminalZeroPreflight(t.Context(),
		slice6GuestRecoveryTerminalZeroPreflight{}); err == nil {
		t.Fatal("terminal-zero preflight accepted absent v3/Docker evidence")
	}
}

func TestSlice6GuestRecoveryTerminalZeroDigestBindsFiveExistingReferences(t *testing.T) {
	runID := strings.Repeat("a", 32)
	refs := [5]string{}
	for index, digit := range []string{"1", "2", "3", "4", "5"} {
		refs[index] = "sha256:" + strings.Repeat(digit, 64)
	}
	want := slice6GuestRecoveryTerminalZeroDigest(runID, refs[0], refs[1], refs[2], refs[3], refs[4])
	if !guestRevokeFixtureDigestGate(want) {
		t.Fatal("terminal-zero digest unavailable")
	}
	for index := range refs {
		copy := refs
		copy[index] = "sha256:" + strings.Repeat("f", 64)
		if slice6GuestRecoveryTerminalZeroDigest(runID, copy[0], copy[1], copy[2], copy[3], copy[4]) == want {
			t.Fatalf("terminal-zero reference %d not bound", index)
		}
	}
	if slice6GuestRecoveryTerminalZeroDigest(strings.Repeat("b", 32), refs[0], refs[1], refs[2], refs[3], refs[4]) == want ||
		slice6GuestRecoveryTerminalZeroDigest(runID, refs[0], refs[1], "", refs[3], refs[4]) != "" {
		t.Fatal("terminal-zero run or missing reference admitted")
	}
}
