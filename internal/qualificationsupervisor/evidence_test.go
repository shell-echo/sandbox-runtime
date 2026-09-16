package qualificationsupervisor

import (
	"errors"
	"testing"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func TestMatchesAdapterEvidenceRejectsEverySupervisorBindingDrift(t *testing.T) {
	digestA := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	evidence := PhaseEvidence{
		ProcessIdentity:  "adapter-process-0123456789abcdef0123456789abcdef",
		ExecutableDigest: digestA, ConfigurationDigest: digestB,
		Delivery: DeliveryStats{CredentialPayloadBytes: 123}, AdapterStderrWireBytes: 456,
	}
	valid := protocol.TranscriptSupervisorPhase{
		ProcessIdentities:           protocol.TranscriptComponents{QualificationAdapter: evidence.ProcessIdentity},
		ExecutableDigests:           protocol.TranscriptComponents{QualificationAdapter: evidence.ExecutableDigest},
		ConfigurationDigests:        protocol.TranscriptComponents{QualificationAdapter: evidence.ConfigurationDigest},
		CredentialPayloadTotalBytes: evidence.Delivery.CredentialPayloadBytes,
		StderrWireBytes:             evidence.AdapterStderrWireBytes,
	}
	if !matchesAdapterEvidence(valid, evidence) {
		t.Fatal("matching evidence rejected")
	}
	tests := []func(*protocol.TranscriptSupervisorPhase){
		func(value *protocol.TranscriptSupervisorPhase) {
			value.ProcessIdentities.QualificationAdapter = "adapter-process-other"
		},
		func(value *protocol.TranscriptSupervisorPhase) {
			value.ExecutableDigests.QualificationAdapter = digestB
		},
		func(value *protocol.TranscriptSupervisorPhase) {
			value.ConfigurationDigests.QualificationAdapter = digestA
		},
		func(value *protocol.TranscriptSupervisorPhase) { value.CredentialPayloadTotalBytes++ },
		func(value *protocol.TranscriptSupervisorPhase) { value.StderrWireBytes++ },
	}
	for index, mutate := range tests {
		changed := valid
		mutate(&changed)
		if matchesAdapterEvidence(changed, evidence) {
			t.Fatalf("binding drift %d accepted", index)
		}
	}
}

func TestEvidenceZeroValuesFailClosed(t *testing.T) {
	var process StartedProcess
	if _, ok := process.Evidence(); ok {
		t.Fatal("zero process published evidence")
	}
	var frozen FrozenPreflight
	if _, ok := frozen.Transcript(); ok {
		t.Fatal("zero preflight published transcript")
	}
	if _, err := frozen.FinalizeTranscript(protocol.TranscriptSupervisorPhase{}, protocol.TranscriptSupervisorPhase{}); !errors.Is(err, ErrEvidence) {
		t.Fatal("zero preflight finalized transcript", err)
	}
}
