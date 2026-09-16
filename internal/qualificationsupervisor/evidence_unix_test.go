//go:build darwin || linux

package qualificationsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func completeEvidencePhase(t *testing.T, process *StartedProcess, codec *protocol.Codec) PhaseEvidence {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := process.ObserveStartup(ctx, codec); err != nil {
		t.Fatal(err)
	}
	document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
	if _, err := process.DeliverInvocation(ctx, document, []CredentialPayload{{
		ChannelID: "controller-a-provider", Data: []byte("provider-secret"),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := process.Evidence(); ok {
		t.Fatal("evidence published before protocol completion")
	}
	if err := process.ObserveCompletion(ctx); err != nil {
		t.Fatal(err)
	}
	evidence, ok := process.Evidence()
	if !ok {
		t.Fatal("completed process did not publish evidence")
	}
	return evidence
}

func startAdmittedProcess(t *testing.T, frozen *FrozenPreflight, phase string) *StartedProcess {
	t.Helper()
	admission, err := frozen.AdmitPhase(context.Background(), phase)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := PrepareLaunch(context.Background(), admission)
	if err != nil {
		t.Fatal(err)
	}
	process, err := StartProcess(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	return process
}

func observedTranscriptPhase(evidence PhaseEvidence, suffix string) protocol.TranscriptSupervisorPhase {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	return protocol.TranscriptSupervisorPhase{
		ProcessIdentities: protocol.TranscriptComponents{
			Provider: "provider-" + suffix, ExternalCaller: "caller-" + suffix,
			QualificationAdapter: evidence.ProcessIdentity, CallerGateway: "gateway-" + suffix,
		},
		ExecutableDigests: protocol.TranscriptComponents{
			Provider: digestA, ExternalCaller: digestA,
			QualificationAdapter: evidence.ExecutableDigest, CallerGateway: digestA,
		},
		ConfigurationDigests: protocol.TranscriptComponents{
			Provider: digestB, ExternalCaller: digestB,
			QualificationAdapter: evidence.ConfigurationDigest, CallerGateway: digestB,
		},
		StderrWireBytes:             evidence.AdapterStderrWireBytes,
		CredentialPayloadTotalBytes: evidence.Delivery.CredentialPayloadBytes,
	}
}

func TestRealTwoPhaseEvidenceFinalizesClosedTranscript(t *testing.T) {
	codec, err := protocol.NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	path := buildStartupProbe(t, "completion")
	frozen, launch := preparedProbe(t, path)
	initialProcess, err := StartProcess(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = initialProcess.Close() })
	initial := completeEvidencePhase(t, initialProcess, codec)
	reconstructionProcess := startAdmittedProcess(t, frozen, "reconstruction")
	reconstruction := completeEvidencePhase(t, reconstructionProcess, codec)

	if initial.PhaseID != "initial" || initial.InvocationID != "invocation-initial" ||
		reconstruction.PhaseID != "reconstruction" || reconstruction.InvocationID != "invocation-reconstruction" ||
		initial.ProcessIdentity == reconstruction.ProcessIdentity ||
		initial.ProcessIdentity == strconv.Itoa(initialProcess.core.pid) ||
		reconstruction.ProcessIdentity == strconv.Itoa(reconstructionProcess.core.pid) ||
		initial.ExecutableDigest != reconstruction.ExecutableDigest ||
		initial.ConfigurationDigest != reconstruction.ConfigurationDigest ||
		initial.Delivery.InvocationBytes <= 0 || initial.Delivery.CredentialChannelCount != 1 ||
		initial.Delivery.CredentialPayloadBytes != int64(len("provider-secret")) ||
		initial.AdapterStderrWireBytes <= 0 || reconstruction.AdapterStderrWireBytes <= 0 {
		t.Fatalf("unexpected phase evidence: initial=%+v reconstruction=%+v", initial, reconstruction)
	}
	// Returned startup slices and pointers cannot mutate retained evidence.
	*initial.StartupIdentity.CredentialChannels[0].Actor = "changed"
	again, ok := initialProcess.Evidence()
	if !ok || *again.StartupIdentity.CredentialChannels[0].Actor != "controller_a" {
		t.Fatal("phase evidence aliases retained startup identity")
	}

	projection, err := frozen.FinalizeTranscript(
		observedTranscriptPhase(initial, "initial"),
		observedTranscriptPhase(reconstruction, "reconstruction"),
	)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(projection.Document)
	if projection.Digest != "sha256:"+hex.EncodeToString(sum[:]) ||
		bytes.Contains(projection.Document, []byte("provider-secret")) ||
		bytes.Contains(projection.Document, []byte("delivery-ok")) ||
		bytes.Contains(projection.Document, []byte(path)) {
		t.Fatal("transcript digest mismatch or private material retained")
	}
	var document struct {
		InvocationIDs []string `json:"invocation_ids"`
		Phases        []struct {
			PhaseID              string                        `json:"phase_id"`
			ProcessIdentities    protocol.TranscriptComponents `json:"process_identities"`
			ExecutableDigests    protocol.TranscriptComponents `json:"executable_digests"`
			ConfigurationDigests protocol.TranscriptComponents `json:"configuration_digests"`
			BoundedCounts        map[string]int64              `json:"bounded_byte_counts"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(projection.Document, &document); err != nil || len(document.Phases) != 2 ||
		len(document.InvocationIDs) != 2 || document.InvocationIDs[0] != initial.InvocationID ||
		document.InvocationIDs[1] != reconstruction.InvocationID ||
		document.Phases[0].ProcessIdentities.QualificationAdapter != initial.ProcessIdentity ||
		document.Phases[1].ProcessIdentities.QualificationAdapter != reconstruction.ProcessIdentity ||
		document.Phases[0].ExecutableDigests.QualificationAdapter != initial.ExecutableDigest ||
		document.Phases[1].ConfigurationDigests.QualificationAdapter != reconstruction.ConfigurationDigest ||
		document.Phases[0].BoundedCounts["adapter_stderr_wire_bytes"] != initial.AdapterStderrWireBytes ||
		document.Phases[1].BoundedCounts["credential_payload_total_bytes"] != reconstruction.Delivery.CredentialPayloadBytes {
		t.Fatal("transcript did not bind actual adapter phase evidence", err)
	}
	projection.Document[0] = 'x'
	stored, ok := frozen.Transcript()
	if !ok || stored.Document[0] != '{' {
		t.Fatal("returned transcript aliases retained projection")
	}
	stored.Document[0] = 'x'
	againProjection, ok := frozen.Transcript()
	if !ok || againProjection.Document[0] != '{' {
		t.Fatal("retrieved transcript aliases retained projection")
	}
	if _, err := frozen.FinalizeTranscript(
		observedTranscriptPhase(initial, "initial"),
		observedTranscriptPhase(reconstruction, "reconstruction"),
	); !errors.Is(err, ErrEvidence) {
		t.Fatal("run minted a competing transcript", err)
	}
}

func TestFailedRealProcessCannotPublishEvidence(t *testing.T) {
	_, process := deliveredCompletionProbe(t, "nonclean-completion")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := process.ObserveCompletion(ctx); err == nil {
		t.Fatal("nonclean process accepted")
	}
	if _, ok := process.Evidence(); ok {
		t.Fatal("failed process published phase evidence")
	}
}
