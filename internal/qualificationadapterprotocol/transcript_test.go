package qualificationadapterprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

func supervisorForTranscriptTest(phase string) *TranscriptSupervisorPhase {
	d := "sha256:" + strings.Repeat("a", 64)
	return &TranscriptSupervisorPhase{
		ProcessIdentities:    TranscriptComponents{"provider-" + phase, "caller-" + phase, "adapter-" + phase, "gateway-" + phase},
		ExecutableDigests:    TranscriptComponents{d, d, d, d},
		ConfigurationDigests: TranscriptComponents{d, d, d, d},
		StderrWireBytes:      123, CredentialPayloadTotalBytes: 512,
	}
}

// All process facts in these tests are synthetic. No process is started.
func completedTranscriptRun(t *testing.T, c *Codec, branch string, edits ...func(string, map[string]any)) *RunStateMachine {
	t.Helper()
	r := NewRunStateMachine()
	for _, phase := range []string{"initial", "reconstruction"} {
		m, err := r.BeginPhase(phase)
		if err != nil {
			t.Fatal(err)
		}
		outputs, seq := scenarioPrefixForStateTest(phase, branch)
		completion := "stopped"
		if branch == "completed" {
			completion = "completed"
		}
		outputs = append(outputs, phaseOutputExample("invocation_finished", seq, phase, map[string]any{"completion": completion}))
		if branch == "invalid_invocation" {
			outputs = []map[string]any{protocolErrorExample(1, nil, nil, branch)}
		}
		if branch == "internal_failure" {
			outputs = []map[string]any{phaseOutputExample("invocation_accepted", 1, phase, nil), protocolErrorExample(2, "invocation-"+phase, phase, branch)}
		}
		stream := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
		for _, output := range outputs {
			stream = append(stream, marshalProtocolValue(t, output)...)
			stream = append(stream, '\n')
		}
		d := c.NewOutputDecoder(bytes.NewReader(stream))
		if _, err := m.ReadStartup(d); err != nil {
			t.Fatal(err)
		}
		if err := m.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		input := invocationExampleForSchemaTest()
		input["invocation_id"], input["phase"] = "invocation-"+phase, phase
		for _, edit := range edits {
			edit(phase, input)
		}
		wire := append([]byte(" \n\t"), marshalProtocolValue(t, input)...)
		invocation, err := c.DecodeInvocation(bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.RecordInvocationDelivered(invocation); err != nil {
			t.Fatal(err)
		}
		for m.State() != PhaseStateTerminalObserved {
			message := nextOutputForStateTest(t, d)
			var err error
			switch message.MessageType {
			case "invocation_accepted":
				err = m.AcceptInvocationAccepted(message)
			case "scenario_started":
				err = m.AcceptScenarioStarted(message)
			case "scenario_result":
				err = m.AcceptScenarioResult(message)
			default:
				err = m.AcceptTerminal(message)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		finishRunPhaseForTest(t, m)
	}
	return r
}

func TestTranscriptProjectionCountsCanonicalDigestAndIsolation(t *testing.T) {
	c := loadCodecForTest(t)
	for _, branch := range []string{"completed", "not_executed", "invalid_invocation", "internal_failure"} {
		t.Run(branch, func(t *testing.T) {
			r := completedTranscriptRun(t, c, branch)
			a, b := supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")
			got, err := r.ProjectTranscript(a, b)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := jcs.Transform(got.Document)
			if err != nil || !bytes.Equal(canonical, got.Document) {
				t.Fatal("not canonical")
			}
			hash := sha256.Sum256(canonical)
			if got.Digest != "sha256:"+hex.EncodeToString(hash[:]) {
				t.Fatal("digest mismatch")
			}
			var value map[string]any
			if err := json.Unmarshal(got.Document, &value); err != nil {
				t.Fatal(err)
			}
			for i, p := range value["phases"].([]any) {
				phase := p.(map[string]any)
				m := []*PhaseStateMachine{r.initial, r.reconstruction}[i]
				counts := phase["message_counts"].(map[string]any)
				wire := phase["bounded_byte_counts"].(map[string]any)
				wantRecords, wantResults, wantStarts := 2, 0, 0
				if branch == "internal_failure" {
					wantRecords = 3
				}
				if branch == "completed" || branch == "not_executed" {
					wantResults = []int{15, 5}[i]
					wantRecords = wantResults + 3
					if branch == "completed" {
						wantStarts = wantResults
						wantRecords += wantStarts
					}
				}
				if wire["adapter_output_complete_records"] != float64(wantRecords) ||
					counts["scenario_result"] != float64(wantResults) || counts["scenario_started"] != float64(wantStarts) ||
					wire["adapter_stdout_wire_bytes"] != float64(m.decoder.TotalWireBytes()) ||
					wire["invocation_wire_bytes"] != float64(m.invocation.wireBytes) ||
					wire["adapter_stderr_wire_bytes"] != float64(123) ||
					wire["credential_payload_total_bytes"] != float64(512) || wire["credential_channel_count"] != float64(1) {
					t.Fatal("wrong derived counts")
				}
				terminal := phase["terminal_state"].(map[string]any)
				if branch == "invalid_invocation" || branch == "internal_failure" {
					if terminal["error_code"] != branch || terminal["completion"] != nil {
						t.Fatal("error terminal misrepresented")
					}
				}
			}
			for _, private := range []string{"/qualification/", "https://", "wss://", "/caller-state", "file_descriptor", "media_type", "channel_id", "caller_release_identity"} {
				if bytes.Contains(got.Document, []byte(private)) {
					t.Fatal("private invocation/startup value leaked")
				}
			}
			original := append([]byte(nil), got.Document...)
			got.Document[0] = 'x'
			again, err := r.ProjectTranscript(a, b)
			if err != nil || !bytes.Equal(original, again.Document) {
				t.Fatal("projection aliases state")
			}
			a.StderrWireBytes++
			changed, err := r.ProjectTranscript(a, b)
			if err != nil || changed.Digest == again.Digest {
				t.Fatal("supervisor count not digest bound")
			}
		})
	}
}

func TestTranscriptProjectionRejectsMissingInvalidAndIncompleteFacts(t *testing.T) {
	c := loadCodecForTest(t)
	r := completedTranscriptRun(t, c, "not_executed")
	for _, mutate := range []func(*TranscriptSupervisorPhase){
		func(p *TranscriptSupervisorPhase) { p.StderrWireBytes = -1 },
		func(p *TranscriptSupervisorPhase) { p.StderrWireBytes = 262145 },
		func(p *TranscriptSupervisorPhase) { p.CredentialPayloadTotalBytes = -1 },
		func(p *TranscriptSupervisorPhase) { p.CredentialPayloadTotalBytes = 4097 },
		func(p *TranscriptSupervisorPhase) { p.CredentialPayloadTotalBytes = 4194305 },
		func(p *TranscriptSupervisorPhase) { p.ProcessIdentities.Provider = "provider-initial" },
		func(p *TranscriptSupervisorPhase) { p.ProcessIdentities.ExternalCaller = "/private/path" },
		func(p *TranscriptSupervisorPhase) {
			p.ProcessIdentities.QualificationAdapter = strings.Repeat("a", 201)
		},
		func(p *TranscriptSupervisorPhase) { p.ExecutableDigests.Provider = "" },
		func(p *TranscriptSupervisorPhase) { p.ConfigurationDigests.CallerGateway = "secret-value" },
	} {
		a, b := supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")
		mutate(b)
		got, err := r.ProjectTranscript(a, b)
		if err == nil || got.Document != nil || got.Digest != "" || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "/private/path") {
			t.Fatal("invalid metadata accepted or exposed")
		}
	}
	if _, err := r.ProjectTranscript(nil, supervisorForTranscriptTest("reconstruction")); err == nil {
		t.Fatal("missing input accepted")
	}
	for _, incomplete := range []*RunStateMachine{nil, NewRunStateMachine()} {
		if _, err := incomplete.ProjectTranscript(supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")); err == nil {
			t.Fatal("incomplete run projected")
		}
	}
	for _, stage := range []string{"terminal", "eof", "failed"} {
		x := NewRunStateMachine()
		m, _ := x.BeginPhase("initial")
		runPhaseForTest(t, m, c, "initial", marshalProtocolValue(t, startupIdentityForCodecTest()))
		finishRunPhaseForTest(t, m)
		m, _ = x.BeginPhase("reconstruction")
		runPhaseForTest(t, m, c, "reconstruction", marshalProtocolValue(t, startupIdentityForCodecTest()))
		if stage != "terminal" {
			if err := m.ObserveStdoutEOF(); err != nil {
				t.Fatal(err)
			}
		}
		if stage == "failed" {
			_ = m.ObserveProcessExit(false)
		}
		if _, err := x.ProjectTranscript(supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")); err == nil {
			t.Fatal("premature projection")
		}
	}
	// A schema-valid role change must not be silently merged across phases.
	r = completedTranscriptRun(t, c, "not_executed", func(phase string, input map[string]any) {
		if phase == "reconstruction" {
			input["credential_channel_descriptors"].([]any)[0].(map[string]any)["role"] = "gateway_credentials"
		}
	})
	if _, err := r.ProjectTranscript(supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")); err == nil {
		t.Fatal("role mismatch accepted")
	}
}

func TestTranscriptProjectionCountBoundsAndDescriptorOrder(t *testing.T) {
	c := loadCodecForTest(t)
	r := completedTranscriptRun(t, c, "completed", func(_ string, input map[string]any) {
		first := input["credential_channel_descriptors"].([]any)[0].(map[string]any)
		second := cloneMap(first)
		second["role"], second["channel_id"], second["file_descriptor"] = "provider_trust", "trust", float64(4)
		input["credential_channel_descriptors"] = []any{second, first}
	})
	for _, total := range []int64{0, 8192} {
		a, b := supervisorForTranscriptTest("initial"), supervisorForTranscriptTest("reconstruction")
		a.StderrWireBytes, b.StderrWireBytes = 0, 262144
		a.CredentialPayloadTotalBytes, b.CredentialPayloadTotalBytes = total, total
		got, err := r.ProjectTranscript(a, b)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(got.Document, &value); err != nil {
			t.Fatal(err)
		}
		for _, p := range value["phases"].([]any) {
			phase := p.(map[string]any)
			roles := phase["credential_channel_roles"].([]any)
			if len(roles) != 2 || roles[0] != "provider_trust" || roles[1] != "provider_credentials" {
				t.Fatal("descriptor order changed")
			}
			if phase["bounded_byte_counts"].(map[string]any)["credential_channel_count"] != float64(2) {
				t.Fatal("descriptor count not derived")
			}
			types := phase["message_types"].([]any)
			if types[0] != "startup_identity" || types[1] != "invocation_accepted" || types[len(types)-1] != "invocation_finished" {
				t.Fatal("message boundary order changed")
			}
			for i := 2; i < len(types)-1; i += 2 {
				if types[i] != "scenario_started" || types[i+1] != "scenario_result" {
					t.Fatal("scenario wire order changed")
				}
			}
		}
	}
}
