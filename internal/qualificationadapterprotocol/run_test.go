package qualificationadapterprotocol

import (
	"bytes"
	"strings"
	"testing"
)

func runPhaseForTest(t *testing.T, m *PhaseStateMachine, codec *Codec, phase string, startup []byte) *OutputDecoder {
	t.Helper()
	outputs, seq := scenarioPrefixForStateTest(phase, "not_executed")
	outputs = append(outputs, phaseOutputExample("invocation_finished", seq, phase, map[string]any{"completion": "stopped"}))
	stream := append(append([]byte(nil), startup...), '\n')
	for _, output := range outputs {
		stream = append(stream, marshalProtocolValue(t, output)...)
		stream = append(stream, '\n')
	}
	d := codec.NewOutputDecoder(bytes.NewReader(stream))
	if _, err := m.ReadStartup(d); err != nil {
		t.Fatal(err)
	}
	if err := m.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordInvocationDelivered(decodedInvocationForPhaseTest(t, codec, phase)); err != nil {
		t.Fatal(err)
	}
	advanceScenarioPrefixForStateTest(t, m, d)
	if err := m.AcceptTerminal(nextOutputForStateTest(t, d)); err != nil {
		t.Fatal(err)
	}
	return d
}

func finishRunPhaseForTest(t *testing.T, m *PhaseStateMachine) {
	t.Helper()
	if err := m.ObserveStdoutEOF(); err != nil {
		t.Fatal(err)
	}
	if err := m.ObserveProcessExit(true); err != nil {
		t.Fatal(err)
	}
}

func TestRunCanonicalStartupEqualityAndCompletion(t *testing.T) {
	c := loadCodecForTest(t)
	r := NewRunStateMachine()
	first, err := r.BeginPhase("initial")
	if err != nil {
		t.Fatal(err)
	}
	doc := marshalProtocolValue(t, startupIdentityForCodecTest())
	d := runPhaseForTest(t, first, c, "initial", doc)
	finishRunPhaseForTest(t, first)
	second, err := r.BeginPhase("reconstruction")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || r.Complete() {
		t.Fatal("phase reuse or premature completion")
	}
	// Equivalent JSON spelling and whitespace must compare equal under RFC 8785.
	variant := bytes.ReplaceAll(doc, []byte(`"sequence":0`), []byte(`"sequence":0e0`))
	variant = append([]byte("  "), variant...)
	other := runPhaseForTest(t, second, c, "reconstruction", variant)
	if d == other {
		t.Fatal("stdout stream reused")
	}
	finishRunPhaseForTest(t, second)
	if !r.Complete() {
		t.Fatal("both phases should be complete")
	}
	if _, err := r.BeginPhase("reconstruction"); err == nil || !r.Complete() {
		t.Fatal("complete must be absorbing and reject reuse")
	}
}

func TestRunRejectsEarlyReconstruction(t *testing.T) {
	c := loadCodecForTest(t)
	for _, stage := range []string{"absent", "startup", "terminal", "eof", "failed-exit"} {
		t.Run(stage, func(t *testing.T) {
			r := NewRunStateMachine()
			if stage != "absent" {
				m, err := r.BeginPhase("initial")
				if err != nil {
					t.Fatal(err)
				}
				if stage != "startup" {
					runPhaseForTest(t, m, c, "initial", marshalProtocolValue(t, startupIdentityForCodecTest()))
					if stage == "eof" || stage == "failed-exit" {
						if err := m.ObserveStdoutEOF(); err != nil {
							t.Fatal(err)
						}
					}
					if stage == "failed-exit" {
						_ = m.ObserveProcessExit(false)
					}
				}
			}
			_, first := r.BeginPhase("reconstruction")
			if first == nil || r.Complete() {
				t.Fatal("early reconstruction accepted")
			}
			if _, again := r.BeginPhase("initial"); again != first {
				t.Fatal("failure not absorbing")
			}
		})
	}
}

func TestRunErrorTerminalAllowsReconstructionWithoutInventingResults(t *testing.T) {
	c := loadCodecForTest(t)
	r := NewRunStateMachine()
	m, _ := r.BeginPhase("initial")
	stream := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	stream = append(stream, marshalProtocolValue(t, protocolErrorExample(1, nil, nil, "invalid_invocation"))...)
	stream = append(stream, '\n')
	d := c.NewOutputDecoder(bytes.NewReader(stream))
	if _, err := m.ReadStartup(d); err != nil {
		t.Fatal(err)
	}
	if err := m.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordInvocationDelivered(decodedInvocationForTest(t, c)); err != nil {
		t.Fatal(err)
	}
	if err := m.AcceptTerminal(nextOutputForStateTest(t, d)); err != nil {
		t.Fatal(err)
	}
	finishRunPhaseForTest(t, m)
	if len(m.scenarioDispositions) != 0 {
		t.Fatal("invented scenario results")
	}
	second, err := r.BeginPhase("reconstruction")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.ReadStartup(d); err == nil {
		t.Fatal("reused decoder accepted")
	}
	if r.Complete() {
		t.Fatal("failed reconstruction completed")
	}
}

func TestRunRejectsChangedCompleteStartupBeforeInput(t *testing.T) {
	c := loadCodecForTest(t)
	for _, field := range []string{"caller_release_identity", "adapter_release_identity", "credential_channel_requirements"} {
		t.Run(field, func(t *testing.T) {
			r := NewRunStateMachine()
			first, _ := r.BeginPhase("initial")
			runPhaseForTest(t, first, c, "initial", marshalProtocolValue(t, startupIdentityForCodecTest()))
			finishRunPhaseForTest(t, first)
			second, err := r.BeginPhase("reconstruction")
			if err != nil {
				t.Fatal(err)
			}
			value := startupIdentityForCodecTest()
			if field == "credential_channel_requirements" {
				value[field].([]any)[0].(map[string]any)["max_bytes"] = float64(2048)
			} else {
				value[field] = map[string]any{"kind": "source-revision", "value": strings.Repeat("b", 40), "immutable": true}
			}
			d := c.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, value), '\n')))
			_, err = second.ReadStartup(d)
			assertStateFailureValue(t, err, StateFailureInvalidOrder)
			if second.AuthorizeInvocationInput() == nil || r.Complete() {
				t.Fatal("mismatched identity authorized")
			}
		})
	}
}

func TestRunRejectsWrongPhaseAndDuplicateInvocationID(t *testing.T) {
	c := loadCodecForTest(t)
	for _, duplicate := range []bool{false, true} {
		r := NewRunStateMachine()
		m, _ := r.BeginPhase("initial")
		if duplicate {
			runPhaseForTest(t, m, c, "initial", marshalProtocolValue(t, startupIdentityForCodecTest()))
			finishRunPhaseForTest(t, m)
			m, _ = r.BeginPhase("reconstruction")
		}
		if _, err := m.ReadStartup(startupDecoderForTest(t, c)); err != nil {
			t.Fatal(err)
		}
		if err := m.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		value := invocationExampleForSchemaTest()
		value["phase"] = "reconstruction"
		inv, err := c.DecodeInvocation(bytes.NewReader(marshalProtocolValue(t, value)))
		if err != nil {
			t.Fatal(err)
		}
		assertStateFailureValue(t, m.RecordInvocationDelivered(inv), StateFailureInvalidOrder)
	}
}
