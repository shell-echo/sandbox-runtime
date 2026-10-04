//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

const slice6TerminalV3PlanFile = "guest-e-terminal-v3-plan.json"
const slice6TerminalV3EvidenceFile = "guest-e-terminal-v3-stdout.raw"
const slice6TerminalV3BindingFile = "guest-e-terminal-v3-binding.json"
const slice6TerminalV3CleanupOnlyFile = "guest-e-terminal-cleanup-only.json"

type slice6TerminalV3Sink struct {
	Run                *slice6ReceiptEvidenceRun
	PrecleanupDigest   string
	EvidenceDigest     string
	OperatorID         string
	verifiedPrecleanup bool
}

// Stages are a closed diagnostic vocabulary. Never include issuer responses,
// ledger contents or the underlying error in a test log.
type slice6TerminalV3StageError string

func (stage slice6TerminalV3StageError) Error() string {
	return "terminal v3 original stdout or independent replay unavailable: stage=" + string(stage)
}

func (slice6TerminalV3StageError) Unwrap() error { return phase6terminalcleanup.ErrInvalid }

type slice6TerminalV3Check struct {
	stage string
	check func() error
}

func slice6TerminalV3FirstFailure(checks ...slice6TerminalV3Check) error {
	for _, check := range checks {
		if check.check == nil {
			return slice6TerminalV3StageError("unknown")
		}
		if err := check.check(); err != nil {
			if typed, ok := err.(slice6TerminalV3StageError); ok && check.stage == "persist" {
				switch typed {
				case "persist_input", "persist_replay", "persist_crl_time", "persist_projection",
					"persist_projection_time", "persist_unexpected_projection", "persist_plan_encode",
					"persist_plan_write", "persist_evidence_write", "persist_projection_write",
					"persist_binding_encode", "persist_binding_write":
					return typed
				}
				return slice6TerminalV3StageError("unknown")
			}
			switch check.stage {
			case "stdout_decode", "evidence_verify", "identity", "ledger_projection", "issued_set", "persist":
				return slice6TerminalV3StageError(check.stage)
			default:
				return slice6TerminalV3StageError("unknown")
			}
		}
	}
	return nil
}

func TestSlice6TerminalV3FirstFailureNoIssuer(t *testing.T) {
	stages := []string{"stdout_decode", "evidence_verify", "identity", "ledger_projection", "issued_set", "persist"}
	for failAt, want := range stages {
		called := 0
		checks := make([]slice6TerminalV3Check, 0, len(stages))
		for index, stage := range stages {
			index := index
			checks = append(checks, slice6TerminalV3Check{stage: stage, check: func() error {
				called++
				if index == failAt {
					return errors.New("private-token-must-not-appear")
				}
				return nil
			}})
		}
		err := slice6TerminalV3FirstFailure(checks...)
		if err == nil || err.Error() != (slice6TerminalV3StageError(want)).Error() ||
			called != failAt+1 || strings.Contains(err.Error(), "private-token") {
			t.Fatalf("terminal first-failure stage unavailable: %s", want)
		}
	}
	if err := slice6TerminalV3FirstFailure(
		slice6TerminalV3Check{"stdout_decode", func() error { return nil }},
		slice6TerminalV3Check{"persist", func() error {
			return slice6TerminalV3StageError("persist_crl_time")
		}},
	); err == nil || err.Error() != (slice6TerminalV3StageError("persist_crl_time")).Error() {
		t.Fatal("typed persist substage was lost")
	}
	for _, check := range []slice6TerminalV3Check{
		{"untrusted-stage", func() error { return errors.New("private-token") }},
		{"persist", func() error { return slice6TerminalV3StageError("private-token") }},
		{"persist", nil},
	} {
		if err := slice6TerminalV3FirstFailure(check); err == nil ||
			err.Error() != (slice6TerminalV3StageError("unknown")).Error() {
			t.Fatal("untrusted terminal diagnostic escaped closed vocabulary")
		}
	}
}

func TestSlice6ClosedTerminalOperatorStageNoIssuer(t *testing.T) {
	for _, stage := range []string{"input-decode", "evidence-replay", "execute-crl-target",
		"execute-operator-self-revoke"} {
		if slice6ClosedTerminalOperatorStage(stage) != stage {
			t.Fatal("reviewed operator stage was suppressed")
		}
	}
	for _, stage := range []string{"", "private-token", "execute-private-token", "input-decode-extra"} {
		if slice6ClosedTerminalOperatorStage(stage) != "unknown" {
			t.Fatal("unreviewed operator stderr stage escaped")
		}
	}
}

func TestSlice6TerminalV3PersistStagesNoIssuer(t *testing.T) {
	plan, evidenceRaw, projection := slice6FinalV3Fixture(t)
	run := slice6NewTerminalV3DiagnosticSink(t, plan.RunID).Run
	sink := &slice6TerminalV3Sink{Run: run, PrecleanupDigest: "sha256:" + strings.Repeat("a", 64),
		verifiedPrecleanup: true}
	started := time.Now().UTC()
	operatorID, binaryDigest := strings.Repeat("e", 64), "sha256:"+strings.Repeat("b", 64)
	cases := []struct {
		name, operator string
		evidence       []byte
		projection     []byte
		started        time.Time
		want           string
	}{
		{"input", "bad", evidenceRaw, projection, started, "persist_input"},
		{"replay", operatorID, []byte("not-evidence"), projection, started, "persist_replay"},
		{"crl-time", operatorID, evidenceRaw, projection, started.Add(time.Minute), "persist_crl_time"},
		{"projection", operatorID, evidenceRaw, []byte("not-projection"), started, "persist_projection"},
	}
	for _, test := range cases {
		err := sink.persist(plan, test.evidence, test.operator, binaryDigest,
			test.started, test.started, test.projection)
		if err == nil || err.Error() != (slice6TerminalV3StageError(test.want)).Error() {
			t.Fatalf("terminal persist stage unavailable: %s", test.name)
		}
	}
	var shifted slice6TerminalLedgerProjection
	if json.Unmarshal(projection, &shifted) != nil {
		t.Fatal("decode no-issuer projection fixture")
	}
	shifted.ProjectedAt = started.Add(time.Second)
	shiftedRaw, err := json.Marshal(shifted)
	if err != nil || slice6VerifyTerminalLedgerProjection(plan, shiftedRaw) != nil {
		t.Fatal("no-issuer projection timestamp fixture unavailable")
	}
	if err := sink.persist(plan, evidenceRaw, operatorID, binaryDigest,
		started, started, shiftedRaw); err == nil ||
		err.Error() != (slice6TerminalV3StageError("persist_projection_time")).Error() {
		t.Fatal("terminal projection time failure stage unavailable")
	}
	if len(run.files) != 0 {
		t.Fatal("failed terminal persist created private evidence files")
	}
	for _, test := range []struct {
		name, file, want string
		limit            int
	}{
		{"plan", slice6TerminalV3PlanFile, "persist_plan_write", 64 << 10},
		{"evidence", slice6TerminalV3EvidenceFile, "persist_evidence_write", phase6terminalcleanup.MaxEvidenceV3Bytes},
		{"projection", slice6TerminalLedgerProjectionFile, "persist_projection_write", slice6TerminalLedgerProjectionLimit},
		{"binding", slice6TerminalV3BindingFile, "persist_binding_write", 2048},
	} {
		t.Run(test.name, func(t *testing.T) {
			separate := slice6NewTerminalV3DiagnosticSink(t, plan.RunID).Run
			if separate.writeV2BoundedPrivateFile(test.file, []byte(`{"occupied":true}`), test.limit, false) != nil {
				t.Fatal("occupy exact no-issuer private filename")
			}
			writer := &slice6TerminalV3Sink{Run: separate, PrecleanupDigest: sink.PrecleanupDigest,
				verifiedPrecleanup: true}
			if err := writer.persist(plan, evidenceRaw, operatorID, binaryDigest,
				started, started, projection); err == nil ||
				err.Error() != (slice6TerminalV3StageError(test.want)).Error() {
				t.Fatalf("terminal private write failure stage unavailable: %s", test.name)
			}
		})
	}
}

type slice6TerminalV3Binding struct {
	Protocol, RunID, ProfileDigest, PrecleanupDigest string
	PlanDigest, PlanSHA256, EvidenceSHA256           string
	LedgerProjectionSHA256                           string
	OperatorContainerID, OperatorBinaryDigest        string
	EvidenceBytes, LedgerProjectionBytes             int
	OperatorStartUTC, OperatorFinishUTC              string
	RecordedUTC                                      string
}

type slice6TerminalV3CleanupOnly struct {
	Protocol, RunID, Disposition string
	EvidenceDigest, OperatorID   string
	RecordedUTC                  string
}

// A failed E sequence may still run the exact v3 revoker once. This receipt
// explicitly cannot satisfy the formal precleanup-bound terminal verifier.
func (run *slice6ReceiptEvidenceRun) recordTerminalV3CleanupOnly(
	disposition, evidenceDigest, binaryDigest, operatorID string) error {
	if run == nil || run.check() != nil ||
		(disposition != "observed_v3_cleanup_only" && disposition != "unknown_incomplete") {
		return phase6terminalcleanup.ErrInvalid
	}
	if disposition == "observed_v3_cleanup_only" {
		if run.verifyTerminalV3DiagnosticBinding(evidenceDigest, binaryDigest, operatorID) != nil {
			return phase6terminalcleanup.ErrInvalid
		}
	} else if evidenceDigest != "" || operatorID != "" {
		return phase6terminalcleanup.ErrInvalid
	}
	receipt := slice6TerminalV3CleanupOnly{
		Protocol: "sandbox-runtime.phase6-guest-e-terminal-cleanup-only.v1",
		RunID:    run.id, Disposition: disposition,
		EvidenceDigest: evidenceDigest, OperatorID: operatorID,
		RecordedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 768 ||
		run.writeV2BoundedPrivateFile(slice6TerminalV3CleanupOnlyFile, raw, 768, false) != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	retained, err := run.readFile(slice6TerminalV3CleanupOnlyFile, 768)
	if err != nil || !bytes.Equal(raw, retained) {
		return phase6terminalcleanup.ErrInvalid
	}
	return nil
}

func TestSlice6TerminalV3CleanupOnlyCannotBecomeFormalBinding(t *testing.T) {
	run := slice6NewTerminalV3DiagnosticSink(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Run
	if err := run.recordTerminalV3CleanupOnly("observed_v3_cleanup_only", "", "", ""); err == nil {
		t.Fatal("cleanup-only accepted an absent v3 observation")
	}
	if err := run.recordTerminalV3CleanupOnly("unknown_incomplete", "sha256:"+strings.Repeat("b", 64), "", ""); err == nil {
		t.Fatal("unknown cleanup copied an unverified v3 digest")
	}
	if err := run.recordTerminalV3CleanupOnly("unknown_incomplete", "", "", ""); err != nil {
		t.Fatalf("unknown cleanup-only marker unavailable: %v", err)
	}
	if err := run.recordTerminalV3CleanupOnly("unknown_incomplete", "", "", ""); err == nil {
		t.Fatal("cleanup-only marker allowed a second operator outcome")
	}
	if run.verifyTerminalV3Binding("sha256:"+strings.Repeat("b", 64),
		"sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64),
		strings.Repeat("e", 64)) == nil {
		t.Fatal("cleanup-only marker satisfied formal E terminal binding")
	}
}

type slice6GuestRecoveryFormalTerminalRequest struct {
	Run                slice6DockerRun
	Evidence           *slice6ReceiptEvidenceRun
	Precleanup         slice6GuestRecoveryPrecleanupInput
	Composed           slice6VaultComposedInputs
	VaultID            string
	BinaryPath         string
	BinaryDigest       string
	ManagementAccessor string
	General            slice6VaultRoot
	Credential         *slice6TerminalOperatorCredential
	ExternalPostgres   *phase6terminalcleanup.ExternalPostgresRecord
}

// The formal E call has no optional v2 branch. It obtains the durable sink
// only after replaying the sealed precleanup chain in the same evidence run.
func slice6RunGuestRecoveryFormalTerminalOperator(t *testing.T, ctx context.Context,
	request slice6GuestRecoveryFormalTerminalRequest) (string, string, error) {
	if t == nil || ctx == nil || ctx.Err() != nil || request.Evidence == nil ||
		request.Evidence.id != request.Run.id || request.ExternalPostgres == nil {
		return "", "", phase6terminalcleanup.ErrInvalid
	}
	sink, err := request.Evidence.newGuestRecoveryFormalTerminalV3Sink(ctx, request.Precleanup)
	if err != nil {
		return "", "", err
	}
	if err := slice6RunTerminalOperator(t, ctx, request.Run, request.Composed,
		request.VaultID, request.BinaryPath, request.BinaryDigest,
		request.ManagementAccessor, request.General, request.Credential,
		request.ExternalPostgres, sink); err != nil {
		return "", "", err
	}
	if err := request.Evidence.verifyTerminalV3Binding(sink.EvidenceDigest,
		sink.PrecleanupDigest, request.BinaryDigest, sink.OperatorID); err != nil {
		return "", "", err
	}
	return sink.EvidenceDigest, sink.OperatorID, nil
}

func slice6NewTerminalV3DiagnosticSink(t *testing.T, runID string) *slice6TerminalV3Sink {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal-v3-private")
	if os.Mkdir(path, 0o700) != nil {
		t.Fatal("create terminal v3 diagnostic private root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(resolved)
	if err != nil {
		t.Fatal("open terminal v3 diagnostic private root")
	}
	t.Cleanup(func() {
		if err := root.close(); err != nil {
			t.Error("close terminal v3 diagnostic root")
		}
	})
	run, err := root.newRun(runID)
	if err != nil {
		t.Fatal("open terminal v3 diagnostic run")
	}
	t.Cleanup(func() {
		if err := run.closeV2Incomplete(); err != nil {
			t.Error("mark terminal v3 component incomplete")
		}
	})
	return &slice6TerminalV3Sink{Run: run}
}

// A formal terminal sink is obtained only by replaying the sealed, same-run
// E source/action/SQL/PID1 precleanup chain. Diagnostic sinks never set this
// bit and cannot enter the formal terminal path.
func (run *slice6ReceiptEvidenceRun) newGuestRecoveryFormalTerminalV3Sink(
	ctx context.Context, input slice6GuestRecoveryPrecleanupInput) (*slice6TerminalV3Sink, error) {
	if run == nil || run.check() != nil || input.Source.evidence != run || input.Source.runID != run.id {
		return nil, phase6terminalcleanup.ErrInvalid
	}
	digest, err := run.verifyGuestRecoveryPrecleanup(ctx, input)
	if err != nil || !guestRevokeFixtureDigestGate(digest) {
		return nil, phase6terminalcleanup.ErrInvalid
	}
	return &slice6TerminalV3Sink{Run: run, PrecleanupDigest: digest, verifiedPrecleanup: true}, nil
}

type slice6BoundedPrivateOutput struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (output *slice6BoundedPrivateOutput) Write(document []byte) (int, error) {
	if output == nil || output.maximum < 1 {
		return 0, errors.New("private output limit unavailable")
	}
	remaining := output.maximum - output.buffer.Len()
	if remaining < len(document) {
		output.overflow = true
		if remaining > 0 {
			_, _ = output.buffer.Write(document[:remaining])
		}
		return len(document), nil // drain the pipe; never stop remote revocation early
	}
	_, _ = output.buffer.Write(document)
	return len(document), nil
}

func (sink *slice6TerminalV3Sink) persist(plan phase6terminalcleanup.Plan,
	evidenceRaw []byte, operatorID, binaryDigest string, started, finished time.Time,
	ledgerProjection []byte) error {
	if sink == nil || sink.Run == nil || sink.Run.check() != nil ||
		plan.RunID != sink.Run.id || plan.Protocol != phase6terminalcleanup.ProtocolV2ID ||
		len(operatorID) != 64 || !lowerHexSlice6(operatorID) ||
		!guestRevokeFixtureDigestGate(binaryDigest) ||
		(sink.PrecleanupDigest != "" && (!sink.verifiedPrecleanup ||
			!guestRevokeFixtureDigestGate(sink.PrecleanupDigest))) ||
		!slice6TerminalV3TimesBound(started, finished) {
		return slice6TerminalV3StageError("persist_input")
	}
	evidence, err := phase6terminalcleanup.DecodeEvidenceV3(evidenceRaw)
	if err != nil || phase6terminalcleanup.VerifyEvidenceV3(plan, evidence) != nil {
		return slice6TerminalV3StageError("persist_replay")
	}
	verifiedAt, err := time.Parse(time.RFC3339Nano, evidence.CRLVerifiedUTC)
	if err != nil || verifiedAt.Before(started.Add(-5*time.Second)) ||
		verifiedAt.After(finished.Add(5*time.Second)) {
		return slice6TerminalV3StageError("persist_crl_time")
	}
	if sink.PrecleanupDigest != "" {
		if slice6VerifyTerminalLedgerProjection(plan, ledgerProjection) != nil ||
			len(ledgerProjection) > slice6TerminalLedgerProjectionLimit {
			return slice6TerminalV3StageError("persist_projection")
		}
		var projection slice6TerminalLedgerProjection
		if json.Unmarshal(ledgerProjection, &projection) != nil || projection.ProjectedAt.After(started) ||
			projection.ProjectedAt.Before(started.Add(-2*time.Minute)) {
			return slice6TerminalV3StageError("persist_projection_time")
		}
	} else if len(ledgerProjection) != 0 {
		return slice6TerminalV3StageError("persist_unexpected_projection")
	}
	planRaw, err := json.Marshal(plan)
	if err != nil || len(planRaw) < 2 || len(planRaw) > 64<<10 {
		return slice6TerminalV3StageError("persist_plan_encode")
	}
	defer clear(planRaw)
	if sink.Run.writeV2BoundedPrivateFile(slice6TerminalV3PlanFile, planRaw, 64<<10, false) != nil {
		return slice6TerminalV3StageError("persist_plan_write")
	}
	if sink.Run.writeV2BoundedPrivateFile(slice6TerminalV3EvidenceFile,
		evidenceRaw, phase6terminalcleanup.MaxEvidenceV3Bytes, false) != nil {
		return slice6TerminalV3StageError("persist_evidence_write")
	}
	if sink.PrecleanupDigest != "" &&
		sink.Run.writeV2BoundedPrivateFile(slice6TerminalLedgerProjectionFile,
			ledgerProjection, slice6TerminalLedgerProjectionLimit, false) != nil {
		return slice6TerminalV3StageError("persist_projection_write")
	}
	binding := slice6TerminalV3Binding{
		Protocol: "sandbox-runtime.phase6-guest-e-terminal-v3-binding.v1",
		RunID:    sink.Run.id, ProfileDigest: plan.ProfileDigest,
		PrecleanupDigest: sink.PrecleanupDigest,
		PlanDigest:       plan.Digest, PlanSHA256: slice6ReceiptSHA256(planRaw),
		EvidenceSHA256: slice6ReceiptSHA256(evidenceRaw), EvidenceBytes: len(evidenceRaw),
		OperatorContainerID: operatorID, OperatorBinaryDigest: binaryDigest,
		OperatorStartUTC:  started.UTC().Format(time.RFC3339Nano),
		OperatorFinishUTC: finished.UTC().Format(time.RFC3339Nano),
		RecordedUTC:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	if sink.PrecleanupDigest != "" {
		binding.LedgerProjectionSHA256 = slice6ReceiptSHA256(ledgerProjection)
		binding.LedgerProjectionBytes = len(ledgerProjection)
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil || len(bindingRaw) > 2048 {
		return slice6TerminalV3StageError("persist_binding_encode")
	}
	if sink.Run.writeV2BoundedPrivateFile(slice6TerminalV3BindingFile, bindingRaw, 2048, false) != nil {
		return slice6TerminalV3StageError("persist_binding_write")
	}
	sink.EvidenceDigest = slice6ReceiptSHA256(bindingRaw)
	sink.OperatorID = operatorID
	return nil
}

// Formal E replay must bind this private operator observation to an already
// verified E precleanup digest; a component-only empty binding cannot pass.
func (run *slice6ReceiptEvidenceRun) verifyTerminalV3Binding(bindingDigest,
	precleanupDigest, binaryDigest, operatorID string) error {
	if !guestRevokeFixtureDigestGate(precleanupDigest) {
		return phase6terminalcleanup.ErrInvalid
	}
	return run.verifyTerminalV3BindingCore(bindingDigest, precleanupDigest, binaryDigest, operatorID)
}

// Diagnostic replay accepts an empty E digest only for an explicitly
// incomplete component run. It cannot satisfy verifyTerminalV3Binding.
func (run *slice6ReceiptEvidenceRun) verifyTerminalV3DiagnosticBinding(bindingDigest,
	binaryDigest, operatorID string) error {
	return run.verifyTerminalV3BindingCore(bindingDigest, "", binaryDigest, operatorID)
}

func (run *slice6ReceiptEvidenceRun) verifyTerminalV3BindingCore(bindingDigest,
	precleanupDigest, binaryDigest, operatorID string) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(bindingDigest) ||
		!guestRevokeFixtureDigestGate(binaryDigest) || len(operatorID) != 64 || !lowerHexSlice6(operatorID) {
		return phase6terminalcleanup.ErrInvalid
	}
	bindingRaw, err := run.readFile(slice6TerminalV3BindingFile, 2048)
	if err != nil {
		return err
	}
	defer clear(bindingRaw)
	var binding slice6TerminalV3Binding
	if json.Unmarshal(bindingRaw, &binding) != nil ||
		binding.Protocol != "sandbox-runtime.phase6-guest-e-terminal-v3-binding.v1" ||
		binding.RunID != run.id || binding.PrecleanupDigest != precleanupDigest ||
		binding.OperatorBinaryDigest != binaryDigest || binding.OperatorContainerID != operatorID ||
		slice6ReceiptSHA256(bindingRaw) != bindingDigest {
		return phase6terminalcleanup.ErrInvalid
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical, bindingRaw) {
		return phase6terminalcleanup.ErrInvalid
	}
	planRaw, err := run.readFile(slice6TerminalV3PlanFile, 64<<10)
	if err != nil {
		return err
	}
	defer clear(planRaw)
	var plan phase6terminalcleanup.Plan
	if json.Unmarshal(planRaw, &plan) != nil || plan.Protocol != phase6terminalcleanup.ProtocolV2ID ||
		plan.RunID != run.id || plan.ProfileDigest != binding.ProfileDigest ||
		plan.Digest != binding.PlanDigest || slice6ReceiptSHA256(planRaw) != binding.PlanSHA256 {
		return phase6terminalcleanup.ErrInvalid
	}
	canonicalPlan, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(canonicalPlan, planRaw) {
		return phase6terminalcleanup.ErrInvalid
	}
	evidenceRaw, err := run.readFile(slice6TerminalV3EvidenceFile, phase6terminalcleanup.MaxEvidenceV3Bytes)
	if err != nil {
		return err
	}
	defer clear(evidenceRaw)
	if len(evidenceRaw) != binding.EvidenceBytes ||
		slice6ReceiptSHA256(evidenceRaw) != binding.EvidenceSHA256 {
		return phase6terminalcleanup.ErrInvalid
	}
	evidence, err := phase6terminalcleanup.DecodeEvidenceV3(evidenceRaw)
	if err != nil || phase6terminalcleanup.VerifyEvidenceV3(plan, evidence) != nil {
		return phase6terminalcleanup.ErrInvalid
	}
	started, err := time.Parse(time.RFC3339Nano, binding.OperatorStartUTC)
	if err != nil || binding.OperatorStartUTC != started.UTC().Format(time.RFC3339Nano) {
		return phase6terminalcleanup.ErrInvalid
	}
	finished, err := time.Parse(time.RFC3339Nano, binding.OperatorFinishUTC)
	if err != nil || binding.OperatorFinishUTC != finished.UTC().Format(time.RFC3339Nano) ||
		!slice6TerminalV3TimesBound(started, finished) {
		return phase6terminalcleanup.ErrInvalid
	}
	if precleanupDigest != "" {
		if !guestRevokeFixtureDigestGate(binding.LedgerProjectionSHA256) ||
			binding.LedgerProjectionBytes < 2 ||
			binding.LedgerProjectionBytes > slice6TerminalLedgerProjectionLimit {
			return phase6terminalcleanup.ErrInvalid
		}
		projectionRaw, readErr := run.readFile(slice6TerminalLedgerProjectionFile,
			slice6TerminalLedgerProjectionLimit)
		if readErr != nil {
			return phase6terminalcleanup.ErrInvalid
		}
		defer clear(projectionRaw)
		var projection slice6TerminalLedgerProjection
		if len(projectionRaw) != binding.LedgerProjectionBytes ||
			slice6ReceiptSHA256(projectionRaw) != binding.LedgerProjectionSHA256 ||
			slice6VerifyTerminalLedgerProjection(plan, projectionRaw) != nil ||
			json.Unmarshal(projectionRaw, &projection) != nil ||
			projection.ProjectedAt.After(started) ||
			projection.ProjectedAt.Before(started.Add(-2*time.Minute)) {
			return phase6terminalcleanup.ErrInvalid
		}
	} else if binding.LedgerProjectionSHA256 != "" || binding.LedgerProjectionBytes != 0 {
		return phase6terminalcleanup.ErrInvalid
	}
	verifiedAt, err := time.Parse(time.RFC3339Nano, evidence.CRLVerifiedUTC)
	if err != nil || verifiedAt.Before(started.Add(-5*time.Second)) ||
		verifiedAt.After(finished.Add(5*time.Second)) {
		return phase6terminalcleanup.ErrInvalid
	}
	when, err := time.Parse(time.RFC3339Nano, binding.RecordedUTC)
	if err != nil || binding.RecordedUTC != when.UTC().Format(time.RFC3339Nano) ||
		when.Before(finished) || when.After(finished.Add(2*time.Minute)) {
		return phase6terminalcleanup.ErrInvalid
	}
	return nil
}

func slice6TerminalV3TimesBound(started, finished time.Time) bool {
	return !started.IsZero() && !finished.IsZero() && !finished.Before(started) &&
		!finished.After(started.Add(2*time.Minute+5*time.Second))
}

func TestSlice6TerminalV3BoundedOutputDrainsAfterOverflow(t *testing.T) {
	output := &slice6BoundedPrivateOutput{maximum: 4}
	for _, chunk := range []string{"ab", "cdef", "secret"} {
		written, err := output.Write([]byte(chunk))
		if err != nil || written != len(chunk) {
			t.Fatal("private output collector interrupted terminal cleanup")
		}
	}
	if !output.overflow || output.buffer.String() != "abcd" ||
		bytes.Contains(output.buffer.Bytes(), []byte("secret")) {
		t.Fatal("overlong terminal stdout was not bounded and redacted")
	}
}

func TestSlice6TerminalV3FormalBindingRequiresPrecleanup(t *testing.T) {
	run := &slice6ReceiptEvidenceRun{}
	if run.verifyTerminalV3Binding("", "", "", "") == nil {
		t.Fatal("diagnostic terminal evidence entered the formal E verifier")
	}
}

func TestSlice6TerminalV3FormalRunnerRefusesMissingPrecleanupBeforeDocker(t *testing.T) {
	const runID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sink := slice6NewTerminalV3DiagnosticSink(t, runID)
	_, _, err := slice6RunGuestRecoveryFormalTerminalOperator(t, t.Context(),
		slice6GuestRecoveryFormalTerminalRequest{Run: slice6DockerRun{id: runID},
			Evidence: sink.Run, ExternalPostgres: &phase6terminalcleanup.ExternalPostgresRecord{}})
	if err == nil {
		t.Fatal("formal terminal runner reached Docker without sealed E precleanup")
	}
}

func TestSlice6TerminalV3ProcessTimeWindow(t *testing.T) {
	started := time.Now().UTC()
	if !slice6TerminalV3TimesBound(started, started.Add(120*time.Second)) ||
		slice6TerminalV3TimesBound(started, started.Add(126*time.Second)) ||
		slice6TerminalV3TimesBound(started, started.Add(-time.Second)) ||
		slice6TerminalV3TimesBound(time.Time{}, started) {
		t.Fatal("terminal evidence process interval is not closed and bounded")
	}
}
