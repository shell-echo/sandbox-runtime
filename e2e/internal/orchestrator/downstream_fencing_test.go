//go:build darwin || linux

package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	downstreamtransport "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
)

func TestDownstreamFencingRunnerRecordsOnlySuccessfulScenarioAsPassed(t *testing.T) {
	runner := &downstreamFencingRunner{}
	if err := runner.run(context.Background(), "passed", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("scenario failed")
	if err := runner.run(context.Background(), "failed", func(context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("failed scenario error = %v", err)
	}
	if len(runner.report.Scenarios) != 2 || runner.report.Scenarios[0].Status != "passed" ||
		runner.report.Scenarios[1].Status != "failed" {
		t.Fatalf("scenario report = %#v", runner.report.Scenarios)
	}
}

func TestValidateDownstreamReportRequiresOrderedPasses(t *testing.T) {
	names := []string{"one", "two"}
	report := downstreamFencingReport{EvidenceName: downstreamFencingEvidenceName, EvidenceProfile: lock.DownstreamFencingProfile}
	for _, name := range names {
		report.Scenarios = append(report.Scenarios, downstreamFencingScenario{Name: name, Status: "passed"})
	}
	if err := validateDownstreamReport(report, names); err != nil {
		t.Fatalf("valid report: %v", err)
	}
	report.Scenarios[0], report.Scenarios[1] = report.Scenarios[1], report.Scenarios[0]
	if err := validateDownstreamReport(report, names); err == nil {
		t.Fatal("report accepted reordered scenarios")
	}
	report.Scenarios[0], report.Scenarios[1] = report.Scenarios[1], report.Scenarios[0]
	report.Scenarios[1].Status = "failed"
	if err := validateDownstreamReport(report, names); err == nil {
		t.Fatal("report accepted a failed scenario")
	}
}

func TestReadDownstreamObservationsRequiresStrictBoundedFileAndRecords(t *testing.T) {
	valid := downstreamObservationBytes(t,
		downstreamTestObservation(1, downstreamtransport.ObservationActionRead, downstreamtransport.ObservationResultComplete, downstreamtransport.ObservationMessageText, 17),
		downstreamTestObservation(2, downstreamtransport.ObservationActionFailed, downstreamtransport.ObservationResultFenceLost, downstreamtransport.ObservationMessageText, 17),
	)
	tests := []struct {
		name    string
		content []byte
		prepare func(*testing.T, string)
	}{
		{name: "duplicate field", content: []byte(`{"sequence":1,"sequence":1,"type":"resolve","timestamp":"2026-09-06T01:02:03Z","result":"succeeded","message_type":"none","bytes":17}` + "\n")},
		{name: "missing final newline", content: bytes.TrimSuffix(valid, []byte{'\n'})},
		{name: "oversized line", content: append(bytes.Repeat([]byte{'x'}, downstreamRecordMaximum), '\n')},
		{name: "noncanonical timestamp", content: []byte(`{"sequence":1,"type":"resolve","timestamp":"2026-09-06T09:02:03+08:00","result":"succeeded","message_type":"none","bytes":17}` + "\n")},
		{name: "invalid observation combination", content: []byte(`{"sequence":1,"type":"action_failed","timestamp":"2026-09-06T01:02:03Z","result":"succeeded","message_type":"text","bytes":17}` + "\n")},
		{name: "non 0600 mode", content: valid, prepare: func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.jsonl")
			writeDownstreamTestFile(t, path, test.content)
			if test.prepare != nil {
				test.prepare(t, path)
			}
			if _, err := readDownstreamObservations(path, false); err == nil {
				t.Fatal("strict observation reader accepted invalid evidence")
			}
		})
	}

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "observations.jsonl")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(downstreamFileMaximum + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readDownstreamObservations(path, false); err == nil {
			t.Fatal("strict observation reader accepted an oversized file")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.jsonl")
		writeDownstreamTestFile(t, target, valid)
		link := filepath.Join(root, "observations.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readDownstreamObservations(link, false); err == nil {
			t.Fatal("strict observation reader followed a symlink")
		}
	})

	t.Run("non regular", func(t *testing.T) {
		if _, err := readDownstreamObservations(t.TempDir(), false); err == nil {
			t.Fatal("strict observation reader accepted a directory")
		}
	})
}

func TestReadDownstreamObservationsPreservesOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	want := downstreamObservations{
		downstreamTestObservation(1, downstreamtransport.ObservationActionRead, downstreamtransport.ObservationResultComplete, downstreamtransport.ObservationMessageText, 17),
		downstreamTestObservation(2, downstreamtransport.ObservationActionFailed, downstreamtransport.ObservationResultFenceLost, downstreamtransport.ObservationMessageText, 17),
	}
	writeDownstreamTestFile(t, path, downstreamObservationBytes(t, want...))
	got, err := readDownstreamObservations(path, false)
	if err != nil || !downstreamObservationsEqual(want, got) {
		t.Fatalf("ordered observations = %#v, %v", got, err)
	}
}

func TestReadDownstreamGatewayAuditRequiresStrictOrderedMetadata(t *testing.T) {
	valid := []byte(
		`{"sequence":1,"type":"authorized","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"authorized"}` + "\n" +
			`{"sequence":2,"type":"downstream_unavailable","timestamp":"2026-09-06T01:02:04Z","attempt":1,"frames":2,"bytes":17,"reason_code":"downstream_fence_unavailable"}` + "\n",
	)
	path := filepath.Join(t.TempDir(), "gateway-audit.jsonl")
	writeDownstreamTestFile(t, path, valid)
	records, err := readDownstreamGatewayAudit(path)
	if err != nil || len(records) != 2 || records[1].Sequence != 2 {
		t.Fatalf("strict Gateway audit = %#v, %v", records, err)
	}
	for name, contents := range map[string][]byte{
		"empty":           {},
		"partial":         bytes.TrimSuffix(valid, []byte{'\n'}),
		"duplicate":       []byte(`{"sequence":1,"sequence":1,"type":"authorized","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"authorized"}` + "\n"),
		"sequence":        []byte(`{"sequence":2,"type":"authorized","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"authorized"}` + "\n"),
		"unknown type":    []byte(`{"sequence":1,"type":"private","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"private"}` + "\n"),
		"wrong reason":    []byte(`{"sequence":1,"type":"authorized","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"connected"}` + "\n"),
		"unknown field":   []byte(`{"sequence":1,"type":"authorized","timestamp":"2026-09-06T01:02:03Z","attempt":0,"frames":0,"bytes":0,"reason_code":"authorized","private":"value"}` + "\n"),
		"noncanonical at": []byte(`{"sequence":1,"type":"authorized","timestamp":"2026-09-06T09:02:03+08:00","attempt":0,"frames":0,"bytes":0,"reason_code":"authorized"}` + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			invalidPath := filepath.Join(t.TempDir(), "gateway-audit.jsonl")
			writeDownstreamTestFile(t, invalidPath, contents)
			if _, err := readDownstreamGatewayAudit(invalidPath); err == nil {
				t.Fatal("strict Gateway audit reader accepted invalid evidence")
			}
		})
	}
}

func TestAssertDownstreamActionRejectedRequiresAdjacentExactMessageAndNoForward(t *testing.T) {
	read := downstreamTestObservation(1, downstreamtransport.ObservationActionRead, downstreamtransport.ObservationResultComplete, downstreamtransport.ObservationMessageText, 23)
	failed := downstreamTestObservation(2, downstreamtransport.ObservationActionFailed, downstreamtransport.ObservationResultFenceLost, downstreamtransport.ObservationMessageText, 23)
	if err := assertDownstreamActionRejected(nil, downstreamObservations{read, failed}, downstreamtransport.ObservationResultFenceLost); err != nil {
		t.Fatalf("valid rejection proof: %v", err)
	}

	forwarded := downstreamTestObservation(3, downstreamtransport.ObservationActionForwarded, downstreamtransport.ObservationResultSucceeded, downstreamtransport.ObservationMessageText, 23)
	if err := assertDownstreamActionRejected(nil, downstreamObservations{read, failed, forwarded}, downstreamtransport.ObservationResultFenceLost); err == nil {
		t.Fatal("rejection proof accepted a matching forwarded action")
	}
	intervening := downstreamTestObservation(2, downstreamtransport.ObservationUpstreamDial, downstreamtransport.ObservationResultSucceeded, downstreamtransport.ObservationMessageNone, 0)
	failed.Sequence = 3
	if err := assertDownstreamActionRejected(nil, downstreamObservations{read, intervening, failed}, downstreamtransport.ObservationResultFenceLost); err == nil {
		t.Fatal("rejection proof accepted nonadjacent read/failure records")
	}
}

func TestAssertQueuedStaleActionRejectedAllowsOnlyClosedBeforeReadOrExactFenceLoss(t *testing.T) {
	const payloadBytes = 23
	prefix := downstreamObservations{
		downstreamTestObservation(1, downstreamtransport.ObservationStreamTerminated, downstreamtransport.ObservationResultFenceLost, downstreamtransport.ObservationMessageNone, 0),
	}
	read := downstreamTestObservation(2, downstreamtransport.ObservationActionRead, downstreamtransport.ObservationResultComplete, downstreamtransport.ObservationMessageText, payloadBytes)
	failed := downstreamTestObservation(3, downstreamtransport.ObservationActionFailed, downstreamtransport.ObservationResultFenceLost, downstreamtransport.ObservationMessageText, payloadBytes)
	if err := assertQueuedStaleActionRejected(prefix, prefix, payloadBytes); err != nil {
		t.Fatalf("closed-before-read trace: %v", err)
	}
	if err := assertQueuedStaleActionRejected(prefix, append(append(downstreamObservations{}, prefix...), read, failed), payloadBytes); err != nil {
		t.Fatalf("exact ingress rejection trace: %v", err)
	}

	wrongHistory := append(downstreamObservations{}, prefix...)
	wrongHistory[0].Bytes = 1
	wrongBytes := failed
	wrongBytes.Bytes++
	unavailable := failed
	unavailable.Result = downstreamtransport.ObservationResultUnavailable
	forwarded := downstreamTestObservation(4, downstreamtransport.ObservationActionForwarded, downstreamtransport.ObservationResultSucceeded, downstreamtransport.ObservationMessageText, payloadBytes)
	for name, after := range map[string]downstreamObservations{
		"history changed":        wrongHistory,
		"read only":              append(append(downstreamObservations{}, prefix...), read),
		"failed only":            append(append(downstreamObservations{}, prefix...), failed),
		"wrong result":           append(append(downstreamObservations{}, prefix...), read, unavailable),
		"metadata mismatch":      append(append(downstreamObservations{}, prefix...), read, wrongBytes),
		"forwarded after reject": append(append(downstreamObservations{}, prefix...), read, failed, forwarded),
	} {
		t.Run(name, func(t *testing.T) {
			if err := assertQueuedStaleActionRejected(prefix, after, payloadBytes); err == nil {
				t.Fatal("invalid queued-stale trace was accepted")
			}
		})
	}
	if err := assertQueuedStaleActionRejected(prefix, prefix, 0); err == nil {
		t.Fatal("zero-sized queued stale action was accepted")
	}
}

func TestAssertDownstreamTerminalAuditRequiresOneFencedBoundaryEvent(t *testing.T) {
	prefix := []downstreamGatewayAudit{
		{Sequence: 1, Type: "authorized", Attempt: 0, ReasonCode: "authorized"},
		{Sequence: 2, Type: "connected", Attempt: 0, ReasonCode: "connected"},
	}
	for _, kind := range []string{"capacity_lost", "capacity_unavailable", "downstream_fence_lost"} {
		after := append(append([]downstreamGatewayAudit{}, prefix...), downstreamGatewayAudit{
			Sequence: 3, Type: kind, Attempt: 0, ReasonCode: downstreamGatewayAuditReason(kind),
		})
		if err := assertDownstreamTerminalAudit(prefix, after); err != nil {
			t.Fatalf("%s terminal audit: %v", kind, err)
		}
	}

	changed := append([]downstreamGatewayAudit{}, prefix...)
	changed[0].Type = "denied"
	badType := append(append([]downstreamGatewayAudit{}, prefix...), downstreamGatewayAudit{Sequence: 3, Type: "client_closed"})
	badAttempt := append(append([]downstreamGatewayAudit{}, prefix...), downstreamGatewayAudit{Sequence: 3, Type: "capacity_lost", Attempt: 1})
	for name, after := range map[string][]downstreamGatewayAudit{
		"missing":         prefix,
		"history changed": append(changed, downstreamGatewayAudit{Sequence: 3, Type: "capacity_lost"}),
		"wrong type":      badType,
		"wrong attempt":   badAttempt,
		"extra event": append(append(append([]downstreamGatewayAudit{}, prefix...),
			downstreamGatewayAudit{Sequence: 3, Type: "capacity_lost"}), downstreamGatewayAudit{Sequence: 4, Type: "client_closed"}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := assertDownstreamTerminalAudit(prefix, after); err == nil {
				t.Fatal("invalid terminal audit was accepted")
			}
		})
	}
}

func TestCopyDownstreamEvidenceFileDoesNotTruncate(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.jsonl")
	destination := filepath.Join(root, "destination.jsonl")
	contents := bytes.Repeat([]byte("0123456789abcdef"), (3<<20)/16)
	writeDownstreamTestFile(t, source, contents)
	if err := copyDownstreamEvidenceFile(source, destination); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(contents, copied) {
		t.Fatalf("copied %d of %d bytes: %v", len(copied), len(contents), err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("destination mode = %v, %v", info.Mode(), err)
	}
	if err := copyDownstreamEvidenceFile(source, destination); err == nil {
		t.Fatal("strict copy overwrote an existing destination")
	}
}

func TestAssertDownstreamExactFilesRequiresLockedFiveFileSet(t *testing.T) {
	root := t.TempDir()
	for _, name := range downstreamEvidenceFiles {
		writeDownstreamTestFile(t, filepath.Join(root, name), []byte("evidence"))
	}
	if err := assertDownstreamExactFiles(root, downstreamEvidenceFiles); err != nil {
		t.Fatalf("exact evidence set: %v", err)
	}
	writeDownstreamTestFile(t, filepath.Join(root, "extra.json"), []byte("extra"))
	if err := assertDownstreamExactFiles(root, downstreamEvidenceFiles); err == nil {
		t.Fatal("evidence validator accepted an extra file")
	}
}

func TestDownstreamAuthorityACLUsesBothHashedNamespaces(t *testing.T) {
	password := "private-password"
	capacityNamespace := "private-capacity-namespace"
	revocationNamespace := "private-revocation-namespace"
	acl := downstreamAuthorityACL(password, capacityNamespace, revocationNamespace)
	capacityDigest := sha256.Sum256([]byte(capacityNamespace))
	revocationDigest := sha256.Sum256([]byte(revocationNamespace))
	if !strings.Contains(acl, hex.EncodeToString(capacityDigest[:])) || !strings.Contains(acl, hex.EncodeToString(revocationDigest[:])) ||
		strings.Contains(acl, capacityNamespace) || strings.Contains(acl, revocationNamespace) ||
		strings.Contains(acl, "${") || strings.Count(acl, ">"+password) != 1 {
		t.Fatal("authority ACL does not use exact private credentials and hashed namespaces")
	}
}

func TestDownstreamHighWaterKeyMatchesLockedAdapterDerivation(t *testing.T) {
	identity := downstreamFencingIdentity{}
	identity.envelope.Endpoint.TenantID = "tenant-a"
	identity.envelope.Endpoint.SandboxID = "sandbox-a"
	identity.envelope.Endpoint.BrowserSessionID = "browser-a"
	key, err := downstreamHighWaterKey("namespace-a", identity)
	if err != nil {
		t.Fatal(err)
	}
	namespaceDigest := sha256.Sum256([]byte("namespace-a"))
	want := "sandbox-runtime:{" + hex.EncodeToString(namespaceDigest[:]) +
		"}:capacity:action-fence:high-water:6f7bf5896b1b5f75a820d6e4f2645bb3d426ac9d031569ae7b861d688f994cdc"
	if key != want {
		t.Fatalf("high-water key = %q, want exact locked adapter derivation", key)
	}
	for _, private := range []string{"namespace-a", "tenant-a", "sandbox-a", "browser-a"} {
		if strings.Contains(key, private) {
			t.Fatal("high-water key exposed raw private subject material")
		}
	}
}

func TestValidateDownstreamManifestPreservesEvidenceBoundaryAndNonTargets(t *testing.T) {
	manifest := validDownstreamTestManifest()
	if err := validateDownstreamManifest(manifest); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	manifest.Contract.SuiteExercised = true
	if err := validateDownstreamManifest(manifest); err == nil {
		t.Fatal("manifest overclaimed Contract Suite execution")
	}
	manifest = validDownstreamTestManifest()
	manifest.Contract.ContractMetadataOnly = true
	if err := validateDownstreamManifest(manifest); err == nil {
		t.Fatal("manifest rewrote the locked Contract metadata-only flag")
	}
	manifest = validDownstreamTestManifest()
	manifest.NonTargets = manifest.NonTargets[:len(manifest.NonTargets)-1]
	if err := validateDownstreamManifest(manifest); err == nil {
		t.Fatal("manifest omitted a required non-target")
	}
}

func downstreamTestObservation(
	sequence uint64,
	kind downstreamtransport.ObservationType,
	result downstreamtransport.ObservationResult,
	messageType downstreamtransport.ObservationMessageType,
	count uint64,
) downstreamFencingObservation {
	return downstreamFencingObservation{
		Sequence: sequence, Type: kind, Timestamp: "2026-09-06T01:02:03Z",
		Result: result, MessageType: messageType, Bytes: count,
	}
}

func downstreamObservationBytes(t *testing.T, records ...downstreamFencingObservation) []byte {
	t.Helper()
	var result []byte
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, encoded...)
		result = append(result, '\n')
	}
	return result
}

func writeDownstreamTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validDownstreamTestManifest() downstreamFencingManifest {
	return downstreamFencingManifest{
		EvidenceName: downstreamFencingEvidenceName, EvidenceProfile: lock.DownstreamFencingProfile,
		Contract: downstreamFencingContractEvidence{
			DownstreamFencingContract: lock.DownstreamFencingContract{}, ProviderRoutesExercised: []string{"GET /v1/capabilities"},
		},
		ProcessReconstructions: 2,
		Reports:                []string{"report.json"},
		Audits:                 []string{"gateway-audit-a.jsonl", "gateway-audit-b.jsonl"},
		Observations:           []string{"ingress-observations.jsonl"},
		Sanitization: downstreamFencingSanitization{
			ExactFileSet: true, PrivateMaterialScan: true, AuditRecordsValidated: true,
		},
		Cleanup: downstreamFencingCleanup{
			CallersStopped: true, GatewaysStopped: true, ProviderIngressStopped: true,
			ValkeyRemoved: true, BrowserResourcesRemoved: true, SupportImageRemoved: true,
		},
		NonTargets: []string{
			"aggregate conformance", "Provider multi-controller reliability", "hostile multi-tenant isolation",
			"real Agent Platform compatibility", "deployment readiness", "production readiness",
		},
	}
}
