package qualificationadapterprotocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPhaseStateMachineAcceptsOneStartupBeforeInvocationInput(t *testing.T) {
	codec := loadCodecForTest(t)
	document := marshalProtocolValue(t, startupIdentityForCodecTest())
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(append([]byte(nil), document...), '\n')))
	machine := NewPhaseStateMachine()

	if machine.State() != PhaseStateAwaitingStartup {
		t.Fatalf("initial state = %q", machine.State())
	}
	message, err := machine.ReadStartup(decoder)
	if err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateReadyForInvocation || message.MessageType != "startup_identity" ||
		message.Sequence == nil || *message.Sequence != 0 || !bytes.Equal(message.Document, document) {
		t.Fatalf("startup result = state %q, message %+v", machine.State(), message)
	}
	if err := machine.AuthorizeInvocationInput(); err != nil {
		t.Fatalf("AuthorizeInvocationInput after startup: %v", err)
	}

	message.Document[0] = 'x'
	if bytes.Equal(machine.startup.Document, message.Document) {
		t.Fatal("accepted startup document aliases caller-owned bytes")
	}
}

func TestPhaseStateMachineBindsInvocationAcceptance(t *testing.T) {
	codec := loadCodecForTest(t)
	startupRecord := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	acceptedRecord := append(marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil)), '\n')
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(startupRecord, acceptedRecord...)))
	machine := NewPhaseStateMachine()

	if _, err := machine.ReadStartup(decoder); err != nil {
		t.Fatal(err)
	}
	if err := machine.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	invocation, err := codec.DecodeInvocation(bytes.NewReader(marshalProtocolValue(t, invocationExampleForSchemaTest())))
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.RecordInvocationDelivered(invocation); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateAwaitingInvocationAcceptance {
		t.Fatalf("state after invocation = %q", machine.State())
	}
	accepted, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptInvocationAccepted(accepted); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateAwaitingNextScenario || machine.lastSequence != 1 {
		t.Fatalf("accepted state = %q, sequence = %d", machine.State(), machine.lastSequence)
	}
}

func TestPhaseStateMachineAcceptsExactLockedScenarioOrder(t *testing.T) {
	codec := loadCodecForTest(t)
	tests := []struct {
		phase string
		cases []string
	}{
		{phase: "initial", cases: lockedInitialCaseIDsForStateTest()},
		{phase: "reconstruction", cases: lockedReconstructionCaseIDsForStateTest()},
	}
	for _, test := range tests {
		t.Run(test.phase, func(t *testing.T) {
			outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, test.phase, nil)}
			for index, caseID := range test.cases {
				outputs = append(outputs, scenarioResultForStateTest(index+2, test.phase, caseID, "not_executed"))
			}
			machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, test.phase, outputs...)
			acceptance, err := decoder.Next()
			if err != nil {
				t.Fatal(err)
			}
			if err := machine.AcceptInvocationAccepted(acceptance); err != nil {
				t.Fatal(err)
			}
			for index, wantCaseID := range test.cases {
				message, err := decoder.Next()
				if err != nil {
					t.Fatal(err)
				}
				if err := machine.AcceptScenarioResult(message); err != nil {
					t.Fatalf("case %d %s: %v", index, wantCaseID, err)
				}
				wantState := PhaseStateAwaitingNextScenario
				if index == len(test.cases)-1 {
					wantState = PhaseStateAwaitingTerminal
				}
				if machine.State() != wantState {
					t.Fatalf("case %d %s state = %q, want %q", index, wantCaseID, machine.State(), wantState)
				}
			}
			if machine.nextCaseIndex != len(test.cases) || len(machine.scenarioDispositions) != len(test.cases) {
				t.Fatalf("accepted cases=%d dispositions=%d, want %d", machine.nextCaseIndex, len(machine.scenarioDispositions), len(test.cases))
			}
		})
	}
}

func TestPhaseStateMachineRequiresStartedBeforeCompletedResult(t *testing.T) {
	codec := loadCodecForTest(t)
	caseID := lockedInitialCaseIDsForStateTest()[0]
	outputs := []map[string]any{
		phaseOutputExample("invocation_accepted", 1, "initial", nil),
		phaseOutputExample("scenario_started", 2, "initial", map[string]any{"case_id": caseID}),
		scenarioResultForStateTest(3, "initial", caseID, "completed"),
		scenarioResultForStateTest(4, "initial", lockedInitialCaseIDsForStateTest()[1], "not_executed"),
	}
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
	acceptInvocationForStateTest(t, machine, decoder)

	started, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptScenarioStarted(started); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateAwaitingStartedResult || machine.startedCaseID != caseID {
		t.Fatalf("started state=%q case=%q", machine.State(), machine.startedCaseID)
	}

	completed, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptScenarioResult(completed); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateAwaitingNextScenario || machine.startedCaseID != "" ||
		len(machine.scenarioDispositions) != 1 || machine.scenarioDispositions[0] != "completed" {
		t.Fatalf("completed state=%q started=%q dispositions=%#v", machine.State(), machine.startedCaseID, machine.scenarioDispositions)
	}

	notExecuted, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptScenarioResult(notExecuted); err != nil {
		t.Fatal(err)
	}
	if len(machine.scenarioDispositions) != 2 || machine.scenarioDispositions[1] != "not_executed" {
		t.Fatalf("mixed dispositions = %#v", machine.scenarioDispositions)
	}
}

func TestPhaseStateMachineAcceptsCompletedFinalScenario(t *testing.T) {
	codec := loadCodecForTest(t)
	cases := lockedReconstructionCaseIDsForStateTest()
	outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, "reconstruction", nil)}
	sequence := 2
	for _, caseID := range cases[:len(cases)-1] {
		outputs = append(outputs, scenarioResultForStateTest(sequence, "reconstruction", caseID, "not_executed"))
		sequence++
	}
	finalCase := cases[len(cases)-1]
	outputs = append(outputs,
		phaseOutputExample("scenario_started", sequence, "reconstruction", map[string]any{"case_id": finalCase}),
		scenarioResultForStateTest(sequence+1, "reconstruction", finalCase, "completed"),
	)
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
	acceptInvocationForStateTest(t, machine, decoder)
	for range cases[:len(cases)-1] {
		message, err := decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		if err := machine.AcceptScenarioResult(message); err != nil {
			t.Fatal(err)
		}
	}
	started, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptScenarioStarted(started); err != nil {
		t.Fatal(err)
	}
	completed, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptScenarioResult(completed); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateAwaitingTerminal || machine.nextCaseIndex != len(cases) {
		t.Fatalf("final completed state=%q cases=%d", machine.State(), machine.nextCaseIndex)
	}
}

func TestPhaseStateMachineRejectsInvalidScenarioTransitions(t *testing.T) {
	codec := loadCodecForTest(t)
	first := lockedInitialCaseIDsForStateTest()[0]
	second := lockedInitialCaseIDsForStateTest()[1]
	tests := []struct {
		name    string
		outputs []map[string]any
		act     func(*testing.T, *PhaseStateMachine, *OutputDecoder)
	}{
		{
			name: "out of profile order",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				scenarioResultForStateTest(2, "initial", second, "not_executed"),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				message := nextOutputForStateTest(t, decoder)
				assertStateFailureValue(t, machine.AcceptScenarioResult(message), StateFailureInvalidOrder)
			},
		},
		{
			name: "completed without start",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				scenarioResultForStateTest(2, "initial", first, "completed"),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				message := nextOutputForStateTest(t, decoder)
				assertStateFailureValue(t, machine.AcceptScenarioResult(message), StateFailureInvalidOrder)
			},
		},
		{
			name: "not executed after start",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				phaseOutputExample("scenario_started", 2, "initial", map[string]any{"case_id": first}),
				scenarioResultForStateTest(3, "initial", first, "not_executed"),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				if err := machine.AcceptScenarioStarted(nextOutputForStateTest(t, decoder)); err != nil {
					t.Fatal(err)
				}
				assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
			},
		},
		{
			name: "second start before result",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				phaseOutputExample("scenario_started", 2, "initial", map[string]any{"case_id": first}),
				phaseOutputExample("scenario_started", 3, "initial", map[string]any{"case_id": first}),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				if err := machine.AcceptScenarioStarted(nextOutputForStateTest(t, decoder)); err != nil {
					t.Fatal(err)
				}
				assertStateFailureValue(t, machine.AcceptScenarioStarted(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
			},
		},
		{
			name: "completed result changes started case",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				phaseOutputExample("scenario_started", 2, "initial", map[string]any{"case_id": first}),
				scenarioResultForStateTest(3, "initial", second, "completed"),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				if err := machine.AcceptScenarioStarted(nextOutputForStateTest(t, decoder)); err != nil {
					t.Fatal(err)
				}
				assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
			},
		},
		{
			name: "noncontiguous sequence",
			outputs: []map[string]any{
				phaseOutputExample("invocation_accepted", 1, "initial", nil),
				scenarioResultForStateTest(3, "initial", first, "not_executed"),
			},
			act: func(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
				assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", test.outputs...)
			acceptInvocationForStateTest(t, machine, decoder)
			test.act(t, machine, decoder)
			if machine.State() != PhaseStateFailed {
				t.Fatalf("state = %q", machine.State())
			}
		})
	}
}

func TestPhaseStateMachineRejectsSkippedOrMutatedScenarioOutput(t *testing.T) {
	codec := loadCodecForTest(t)
	first := lockedInitialCaseIDsForStateTest()[0]
	second := lockedInitialCaseIDsForStateTest()[1]

	t.Run("skipped record", func(t *testing.T) {
		outputs := []map[string]any{
			phaseOutputExample("invocation_accepted", 1, "initial", nil),
			scenarioResultForStateTest(2, "initial", first, "not_executed"),
			scenarioResultForStateTest(3, "initial", second, "not_executed"),
		}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		_ = nextOutputForStateTest(t, decoder)
		assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
	})

	t.Run("mutated disposition projection", func(t *testing.T) {
		outputs := []map[string]any{
			phaseOutputExample("invocation_accepted", 1, "initial", nil),
			scenarioResultForStateTest(2, "initial", first, "not_executed"),
		}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		message := nextOutputForStateTest(t, decoder)
		changed := "completed"
		message.disposition = &changed
		assertStateFailureValue(t, machine.AcceptScenarioResult(message), StateFailureInvalidOrder)
	})

	t.Run("different stream", func(t *testing.T) {
		outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, "initial", nil)}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		other := codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t,
			scenarioResultForStateTest(2, "initial", first, "not_executed")), '\n')))
		assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, other)), StateFailureInvalidOrder)
	})
}

func TestPhaseStateMachineRejectsScenarioAfterFinalResult(t *testing.T) {
	codec := loadCodecForTest(t)
	cases := lockedReconstructionCaseIDsForStateTest()
	outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, "reconstruction", nil)}
	for index, caseID := range cases {
		outputs = append(outputs, scenarioResultForStateTest(index+2, "reconstruction", caseID, "not_executed"))
	}
	outputs = append(outputs, scenarioResultForStateTest(len(cases)+2, "reconstruction", cases[len(cases)-1], "not_executed"))
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
	acceptInvocationForStateTest(t, machine, decoder)
	for range cases {
		if err := machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
	}
	if machine.State() != PhaseStateAwaitingTerminal {
		t.Fatalf("state after final result = %q", machine.State())
	}
	assertStateFailureValue(t, machine.AcceptScenarioResult(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
}

func TestPhaseStateMachineCompletesNormalTerminalBranches(t *testing.T) {
	codec := loadCodecForTest(t)
	tests := []struct {
		name        string
		phase       string
		disposition string
		completion  string
		wantRecords int
	}{
		{name: "all completed at record ceiling", phase: "initial", disposition: "completed", completion: "completed", wantRecords: MaxAdapterOutputRecords},
		{name: "stopped after not executed", phase: "reconstruction", disposition: "not_executed", completion: "stopped", wantRecords: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputs, terminalSequence := scenarioPrefixForStateTest(test.phase, test.disposition)
			outputs = append(outputs, phaseOutputExample("invocation_finished", terminalSequence, test.phase, map[string]any{"completion": test.completion}))
			machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, test.phase, outputs...)
			advanceScenarioPrefixForStateTest(t, machine, decoder)

			if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
				t.Fatal(err)
			}
			if machine.State() != PhaseStateTerminalObserved || machine.terminal.messageType != "invocation_finished" ||
				machine.terminal.completion != test.completion || decoder.Records() != test.wantRecords {
				t.Fatalf("terminal state=%q terminal=%+v records=%d", machine.State(), machine.terminal, decoder.Records())
			}
			if err := machine.ObserveStdoutEOF(); err != nil {
				t.Fatal(err)
			}
			if machine.State() != PhaseStateTerminalEOFObserved {
				t.Fatalf("EOF state = %q", machine.State())
			}
			if err := machine.ObserveProcessExit(true); err != nil {
				t.Fatal(err)
			}
			if machine.State() != PhaseStateComplete {
				t.Fatalf("complete state = %q", machine.State())
			}
		})
	}
}

func TestPhaseStateMachineCompletesProtocolErrorBranches(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("pre binding invalid invocation", func(t *testing.T) {
		errorOutput := protocolErrorExample(1, nil, nil, "invalid_invocation")
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", errorOutput)
		completeProtocolErrorForStateTest(t, machine, decoder, "invalid_invocation")
	})

	t.Run("post binding before scenario", func(t *testing.T) {
		outputs := []map[string]any{
			phaseOutputExample("invocation_accepted", 1, "initial", nil),
			protocolErrorExample(2, "invocation-initial", "initial", "caller_start_failed"),
		}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		completeProtocolErrorForStateTest(t, machine, decoder, "caller_start_failed")
	})

	t.Run("post binding after scenario start", func(t *testing.T) {
		first := lockedInitialCaseIDsForStateTest()[0]
		outputs := []map[string]any{
			phaseOutputExample("invocation_accepted", 1, "initial", nil),
			phaseOutputExample("scenario_started", 2, "initial", map[string]any{"case_id": first}),
			protocolErrorExample(3, "invocation-initial", "initial", "scenario_execution_failed"),
		}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		if err := machine.AcceptScenarioStarted(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
		completeProtocolErrorForStateTest(t, machine, decoder, "scenario_execution_failed")
	})

	t.Run("post binding after all scenario results", func(t *testing.T) {
		outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", "not_executed")
		outputs = append(outputs, protocolErrorExample(terminalSequence, "invocation-reconstruction", "reconstruction", "output_failed"))
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
		advanceScenarioPrefixForStateTest(t, machine, decoder)
		completeProtocolErrorForStateTest(t, machine, decoder, "output_failed")
	})
}

func TestPhaseStateMachineRejectsTerminalBeforeAllScenarioResults(t *testing.T) {
	codec := loadCodecForTest(t)
	outputs := []map[string]any{
		phaseOutputExample("invocation_accepted", 1, "initial", nil),
		phaseOutputExample("invocation_finished", 2, "initial", map[string]any{"completion": "completed"}),
	}
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
	acceptInvocationForStateTest(t, machine, decoder)
	assertStateFailureValue(t, machine.AcceptTerminal(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
}

func TestPhaseStateMachineRejectsMismatchedNormalCompletion(t *testing.T) {
	codec := loadCodecForTest(t)
	tests := []struct {
		disposition string
		completion  string
	}{
		{disposition: "not_executed", completion: "completed"},
		{disposition: "completed", completion: "stopped"},
	}
	for _, test := range tests {
		t.Run(test.disposition+"-as-"+test.completion, func(t *testing.T) {
			outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", test.disposition)
			outputs = append(outputs, phaseOutputExample("invocation_finished", terminalSequence, "reconstruction", map[string]any{"completion": test.completion}))
			machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
			advanceScenarioPrefixForStateTest(t, machine, decoder)
			assertStateFailureValue(t, machine.AcceptTerminal(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
		})
	}
}

func TestPhaseStateMachineRejectsMutatedTerminalProjection(t *testing.T) {
	codec := loadCodecForTest(t)
	outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", "completed")
	outputs = append(outputs, phaseOutputExample("invocation_finished", terminalSequence, "reconstruction", map[string]any{"completion": "stopped"}))
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
	advanceScenarioPrefixForStateTest(t, machine, decoder)
	message := nextOutputForStateTest(t, decoder)
	changed := "completed"
	message.completion = &changed
	assertStateFailureValue(t, machine.AcceptTerminal(message), StateFailureInvalidOrder)
}

func TestPhaseStateMachineRejectsWrongProtocolErrorBranch(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("post binding code before acceptance", func(t *testing.T) {
		message := protocolErrorExample(2, "invocation-initial", "initial", "caller_start_failed")
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", message)
		assertStateFailureValue(t, machine.AcceptTerminal(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
	})

	t.Run("pre binding code after acceptance", func(t *testing.T) {
		outputs := []map[string]any{
			phaseOutputExample("invocation_accepted", 1, "initial", nil),
			protocolErrorExample(1, nil, nil, "invalid_invocation"),
		}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		assertStateFailureValue(t, machine.AcceptTerminal(nextOutputForStateTest(t, decoder)), StateFailureInvalidOrder)
	})
}

func TestPhaseStateMachineRejectsOutputAfterTerminal(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("complete record", func(t *testing.T) {
		outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", "not_executed")
		outputs = append(outputs,
			phaseOutputExample("invocation_finished", terminalSequence, "reconstruction", map[string]any{"completion": "stopped"}),
			protocolErrorExample(terminalSequence+1, "invocation-reconstruction", "reconstruction", "internal_failure"),
		)
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
		advanceScenarioPrefixForStateTest(t, machine, decoder)
		if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
		assertStateFailureValue(t, machine.ObserveStdoutEOF(), StateFailureInvalidOrder)
	})

	t.Run("truncated bytes", func(t *testing.T) {
		outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", "not_executed")
		outputs = append(outputs, phaseOutputExample("invocation_finished", terminalSequence, "reconstruction", map[string]any{"completion": "stopped"}))
		machine, decoder := machineWithRawOutputSuffixForStateTest(t, codec, "reconstruction", outputs, []byte("truncated"))
		advanceScenarioPrefixForStateTest(t, machine, decoder)
		if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
		err := machine.ObserveStdoutEOF()
		assertDecodeFailureValue(t, err, DecodeFailureInvalidFraming)
		if machine.State() != PhaseStateFailed {
			t.Fatalf("state = %q", machine.State())
		}
	})
}

func TestPhaseStateMachineRejectsEarlyEOFAndProcessExit(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("EOF before terminal", func(t *testing.T) {
		outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, "initial", nil)}
		machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", outputs...)
		acceptInvocationForStateTest(t, machine, decoder)
		assertStateFailureValue(t, machine.ObserveStdoutEOF(), StateFailureUnexpectedEOF)
	})

	t.Run("process exit before EOF", func(t *testing.T) {
		machine, decoder := machineWithStoppedTerminalForStateTest(t, codec)
		if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
		assertStateFailureValue(t, machine.ObserveProcessExit(true), StateFailureUnexpectedExit)
	})

	t.Run("non clean process exit", func(t *testing.T) {
		machine, decoder := machineWithStoppedTerminalForStateTest(t, codec)
		if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
			t.Fatal(err)
		}
		if err := machine.ObserveStdoutEOF(); err != nil {
			t.Fatal(err)
		}
		assertStateFailureValue(t, machine.ObserveProcessExit(false), StateFailureUnexpectedExit)
	})
}

func TestPhaseStateMachineCompleteAndFailedStatesAreAbsorbing(t *testing.T) {
	codec := loadCodecForTest(t)
	machine, decoder := machineWithStoppedTerminalForStateTest(t, codec)
	if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveStdoutEOF(); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveProcessExit(true); err != nil {
		t.Fatal(err)
	}
	assertStateFailureValue(t, machine.ObserveProcessExit(true), StateFailureUnexpectedExit)
	if machine.State() != PhaseStateComplete {
		t.Fatalf("complete state changed to %q", machine.State())
	}

	failed := NewPhaseStateMachine()
	first := failed.ObserveProcessExit(true)
	assertStateFailureValue(t, first, StateFailureUnexpectedExit)
	second := failed.ObserveStdoutEOF()
	if second != first || failed.State() != PhaseStateFailed {
		t.Fatalf("failed state not absorbing: first=%v second=%v state=%q", first, second, failed.State())
	}
}

func TestPhaseStateMachineRejectsUnboundInvocationAcceptance(t *testing.T) {
	tests := map[string]func(map[string]any){
		"sequence": func(value map[string]any) {
			value["sequence"] = float64(2)
		},
		"invocation id": func(value map[string]any) {
			value["invocation_id"] = "other-invocation"
		},
		"phase": func(value map[string]any) {
			value["phase"] = "reconstruction"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			codec := loadCodecForTest(t)
			acceptance := outputExample("invocation_accepted", 1, nil)
			mutate(acceptance)
			machine, decoder := machineAwaitingAcceptanceForTest(t, codec, acceptance)
			message, err := decoder.Next()
			if err != nil {
				t.Fatal(err)
			}
			err = machine.AcceptInvocationAccepted(message)
			assertStateFailureValue(t, err, StateFailureInvalidOrder)
			if machine.State() != PhaseStateFailed || strings.Contains(err.Error(), "other-invocation") {
				t.Fatalf("failure state = %q, error = %v", machine.State(), err)
			}
		})
	}
}

func TestPhaseStateMachineRejectsNonAcceptanceAfterInvocation(t *testing.T) {
	codec := loadCodecForTest(t)
	started := outputExample("scenario_started", 1, map[string]any{
		"case_id": "initial.locked-capability-discovery",
	})
	machine, decoder := machineAwaitingAcceptanceForTest(t, codec, started)
	message, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	err = machine.AcceptInvocationAccepted(message)
	assertStateFailureValue(t, err, StateFailureInvalidOrder)
}

func TestPhaseStateMachineRequiresAuthorizedValidatedInvocation(t *testing.T) {
	t.Run("not authorized", func(t *testing.T) {
		codec := loadCodecForTest(t)
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		invocation := decodedInvocationForTest(t, codec)
		err := machine.RecordInvocationDelivered(invocation)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})

	t.Run("unvalidated", func(t *testing.T) {
		codec := loadCodecForTest(t)
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		if err := machine.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		value := invocationExampleForSchemaTest()
		invocationID := value["invocation_id"].(string)
		phase := value["phase"].(string)
		invocation := DecodedMessage{MessageType: "invocation", InvocationID: &invocationID, Phase: &phase}
		err := machine.RecordInvocationDelivered(invocation)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})

	t.Run("different codec authority instance", func(t *testing.T) {
		startupCodec := loadCodecForTest(t)
		invocationCodec := loadCodecForTest(t)
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, startupCodec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		if err := machine.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		err := machine.RecordInvocationDelivered(decodedInvocationForTest(t, invocationCodec))
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})
}

func TestPhaseStateMachineRejectsMutatedDecodedEnvelopes(t *testing.T) {
	t.Run("invocation projection", func(t *testing.T) {
		codec := loadCodecForTest(t)
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		if err := machine.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		invocation := decodedInvocationForTest(t, codec)
		changed := "changed-invocation"
		invocation.InvocationID = &changed
		err := machine.RecordInvocationDelivered(invocation)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})

	t.Run("invocation document", func(t *testing.T) {
		codec := loadCodecForTest(t)
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		if err := machine.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		invocation := decodedInvocationForTest(t, codec)
		invocation.Document[0] = ' '
		err := machine.RecordInvocationDelivered(invocation)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})

	t.Run("acceptance projection", func(t *testing.T) {
		codec := loadCodecForTest(t)
		acceptance := outputExample("invocation_accepted", 1, nil)
		machine, decoder := machineAwaitingAcceptanceForTest(t, codec, acceptance)
		message, err := decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		changed := "reconstruction"
		message.Phase = &changed
		err = machine.AcceptInvocationAccepted(message)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})
}

func TestPhaseStateMachineRejectsSkippedOrDifferentOutputStream(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("skipped record", func(t *testing.T) {
		acceptance := outputExample("invocation_accepted", 1, nil)
		machine, decoder := machineAwaitingAcceptanceForTest(t, codec, acceptance, acceptance)
		if _, err := decoder.Next(); err != nil {
			t.Fatal(err)
		}
		message, err := decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		err = machine.AcceptInvocationAccepted(message)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})

	t.Run("different stream", func(t *testing.T) {
		acceptance := outputExample("invocation_accepted", 1, nil)
		machine, _ := machineAwaitingAcceptanceForTest(t, codec, acceptance)
		other := codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, acceptance), '\n')))
		message, err := other.Next()
		if err != nil {
			t.Fatal(err)
		}
		err = machine.AcceptInvocationAccepted(message)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
	})
}

func TestPhaseStateMachineRejectsInvocationInputBeforeStartup(t *testing.T) {
	machine := NewPhaseStateMachine()
	err := machine.AuthorizeInvocationInput()
	assertStateFailureValue(t, err, StateFailureInvalidOrder)
	if machine.State() != PhaseStateFailed {
		t.Fatalf("state = %q", machine.State())
	}

	codec := loadCodecForTest(t)
	decoder := startupDecoderForTest(t, codec)
	_, repeated := machine.ReadStartup(decoder)
	if repeated != err {
		t.Fatalf("machine did not retain first failure: first=%v repeated=%v", err, repeated)
	}
}

func TestPhaseStateMachineRejectsMissingOrOutOfOrderStartup(t *testing.T) {
	codec := loadCodecForTest(t)
	tests := []struct {
		name    string
		decoder *OutputDecoder
		want    StateFailure
	}{
		{name: "missing", decoder: codec.NewOutputDecoder(bytes.NewReader(nil)), want: StateFailureUnexpectedEOF},
		{name: "wrong first record", decoder: codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil)), '\n'))), want: StateFailureInvalidOrder},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := NewPhaseStateMachine()
			_, err := machine.ReadStartup(test.decoder)
			assertStateFailureValue(t, err, test.want)
			if machine.State() != PhaseStateFailed {
				t.Fatalf("state = %q", machine.State())
			}
			if strings.Contains(err.Error(), "invocation_accepted") {
				t.Fatal("state error leaked adapter output")
			}
		})
	}
}

func TestPhaseStateMachineRejectsDuplicateStartupAndInputAuthorization(t *testing.T) {
	codec := loadCodecForTest(t)

	t.Run("startup", func(t *testing.T) {
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		_, err := machine.ReadStartup(decoder)
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
		if machine.State() != PhaseStateFailed {
			t.Fatalf("state = %q", machine.State())
		}
	})

	t.Run("invocation input authorization", func(t *testing.T) {
		machine := NewPhaseStateMachine()
		decoder := startupDecoderForTest(t, codec)
		if _, err := machine.ReadStartup(decoder); err != nil {
			t.Fatal(err)
		}
		if err := machine.AuthorizeInvocationInput(); err != nil {
			t.Fatal(err)
		}
		err := machine.AuthorizeInvocationInput()
		assertStateFailureValue(t, err, StateFailureInvalidOrder)
		if machine.State() != PhaseStateFailed {
			t.Fatalf("state = %q", machine.State())
		}
	})
}

func TestPhaseStateMachinePreservesSanitizedDecoderFailure(t *testing.T) {
	codec := loadCodecForTest(t)
	startup := startupIdentityForCodecTest()
	startup["protocol_semantics_digest"] = "sha256:" + strings.Repeat("f", 64)
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, startup), '\n')))
	machine := NewPhaseStateMachine()

	_, err := machine.ReadStartup(decoder)
	assertDecodeFailureValue(t, err, DecodeFailureAuthority)
	if machine.State() != PhaseStateFailed {
		t.Fatalf("state = %q", machine.State())
	}
	_, repeated := machine.ReadStartup(decoder)
	if repeated != err {
		t.Fatalf("machine did not retain decoder failure: first=%v repeated=%v", err, repeated)
	}
}

func TestPhaseStateMachineFailsClosedForUnavailableValues(t *testing.T) {
	machine := NewPhaseStateMachine()
	_, err := machine.ReadStartup(nil)
	assertStateFailureValue(t, err, StateFailureInvalidOrder)

	var unavailable *PhaseStateMachine
	if unavailable.State() != PhaseStateFailed {
		t.Fatalf("nil state = %q", unavailable.State())
	}
	_, err = unavailable.ReadStartup(nil)
	assertStateFailureValue(t, err, StateFailureInvalidOrder)
	if err := unavailable.AuthorizeInvocationInput(); err == nil {
		t.Fatal("nil machine authorized invocation input")
	}
	if err := unavailable.AcceptScenarioStarted(DecodedMessage{}); err == nil {
		t.Fatal("nil machine accepted scenario start")
	}
	if err := unavailable.AcceptScenarioResult(DecodedMessage{}); err == nil {
		t.Fatal("nil machine accepted scenario result")
	}
}

func startupDecoderForTest(t *testing.T, codec *Codec) *OutputDecoder {
	t.Helper()
	record := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	return codec.NewOutputDecoder(bytes.NewReader(record))
}

func decodedInvocationForTest(t *testing.T, codec *Codec) DecodedMessage {
	t.Helper()
	return decodedInvocationForPhaseTest(t, codec, "initial")
}

func decodedInvocationForPhaseTest(t *testing.T, codec *Codec, phase string) DecodedMessage {
	t.Helper()
	value := invocationExampleForSchemaTest()
	value["invocation_id"] = "invocation-" + phase
	value["phase"] = phase
	invocation, err := codec.DecodeInvocation(bytes.NewReader(marshalProtocolValue(t, value)))
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func machineAwaitingAcceptanceForTest(t *testing.T, codec *Codec, nextOutputs ...map[string]any) (*PhaseStateMachine, *OutputDecoder) {
	t.Helper()
	return machineAwaitingAcceptanceForPhaseTest(t, codec, "initial", nextOutputs...)
}

func machineAwaitingAcceptanceForPhaseTest(t *testing.T, codec *Codec, phase string, nextOutputs ...map[string]any) (*PhaseStateMachine, *OutputDecoder) {
	t.Helper()
	stream := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	for _, output := range nextOutputs {
		stream = append(stream, marshalProtocolValue(t, output)...)
		stream = append(stream, '\n')
	}
	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))
	machine := NewPhaseStateMachine()
	if _, err := machine.ReadStartup(decoder); err != nil {
		t.Fatal(err)
	}
	if err := machine.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	if err := machine.RecordInvocationDelivered(decodedInvocationForPhaseTest(t, codec, phase)); err != nil {
		t.Fatal(err)
	}
	return machine, decoder
}

func acceptInvocationForStateTest(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
	t.Helper()
	message := nextOutputForStateTest(t, decoder)
	if err := machine.AcceptInvocationAccepted(message); err != nil {
		t.Fatal(err)
	}
}

func nextOutputForStateTest(t *testing.T, decoder *OutputDecoder) DecodedMessage {
	t.Helper()
	message, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func phaseOutputExample(messageType string, sequence int, phase string, extra map[string]any) map[string]any {
	value := outputExample(messageType, sequence, extra)
	value["invocation_id"] = "invocation-" + phase
	value["phase"] = phase
	return value
}

func scenarioResultForStateTest(sequence int, phase, caseID, disposition string) map[string]any {
	extra := map[string]any{
		"case_id": caseID, "disposition": disposition,
		"interactions": []any{}, "assertions": []any{}, "observation_ids": []any{},
		"reason_code": "prerequisite_not_satisfied",
	}
	if disposition == "completed" {
		extra["interactions"] = []any{map[string]any{
			"interaction_id": "completed-interaction", "surface": "provider_http", "actor": "controller_a",
			"method": "GET", "route_template": "/v1/capabilities", "logical_request_id": "completed-request",
			"replay_of": nil, "wire_attempts": float64(1), "transient_outcomes": []any{},
			"final_outcome": map[string]any{
				"transport": "http-response", "status_code": float64(200), "error_code": nil,
				"retryable": false, "retry_after_present": false,
			},
			"mutation_write_observed": false, "observation_ids": []any{"completed-observation"},
		}}
		extra["observation_ids"] = []any{"completed-observation"}
		extra["reason_code"] = nil
	}
	return phaseOutputExample("scenario_result", sequence, phase, extra)
}

func scenarioPrefixForStateTest(phase, disposition string) ([]map[string]any, int) {
	cases := lockedCaseIDsForPhaseStateTest(phase)
	outputs := []map[string]any{phaseOutputExample("invocation_accepted", 1, phase, nil)}
	sequence := 2
	for _, caseID := range cases {
		if disposition == "completed" {
			outputs = append(outputs, phaseOutputExample("scenario_started", sequence, phase, map[string]any{"case_id": caseID}))
			sequence++
		}
		outputs = append(outputs, scenarioResultForStateTest(sequence, phase, caseID, disposition))
		sequence++
	}
	return outputs, sequence
}

func advanceScenarioPrefixForStateTest(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder) {
	t.Helper()
	acceptInvocationForStateTest(t, machine, decoder)
	for machine.State() != PhaseStateAwaitingTerminal {
		message := nextOutputForStateTest(t, decoder)
		var err error
		switch message.MessageType {
		case "scenario_started":
			err = machine.AcceptScenarioStarted(message)
		case "scenario_result":
			err = machine.AcceptScenarioResult(message)
		default:
			t.Fatalf("unexpected prefix message %q", message.MessageType)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func completeProtocolErrorForStateTest(t *testing.T, machine *PhaseStateMachine, decoder *OutputDecoder, wantCode string) {
	t.Helper()
	if err := machine.AcceptTerminal(nextOutputForStateTest(t, decoder)); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateTerminalObserved || machine.terminal.messageType != "protocol_error" ||
		machine.terminal.errorCode != wantCode || machine.terminal.completion != "" {
		t.Fatalf("protocol terminal state=%q terminal=%+v", machine.State(), machine.terminal)
	}
	if err := machine.ObserveStdoutEOF(); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveProcessExit(true); err != nil {
		t.Fatal(err)
	}
	if machine.State() != PhaseStateComplete {
		t.Fatalf("complete state = %q", machine.State())
	}
}

func machineWithStoppedTerminalForStateTest(t *testing.T, codec *Codec) (*PhaseStateMachine, *OutputDecoder) {
	t.Helper()
	outputs, terminalSequence := scenarioPrefixForStateTest("reconstruction", "not_executed")
	outputs = append(outputs, phaseOutputExample("invocation_finished", terminalSequence, "reconstruction", map[string]any{"completion": "stopped"}))
	machine, decoder := machineAwaitingAcceptanceForPhaseTest(t, codec, "reconstruction", outputs...)
	advanceScenarioPrefixForStateTest(t, machine, decoder)
	return machine, decoder
}

func machineWithRawOutputSuffixForStateTest(t *testing.T, codec *Codec, phase string, outputs []map[string]any, suffix []byte) (*PhaseStateMachine, *OutputDecoder) {
	t.Helper()
	stream := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	for _, output := range outputs {
		stream = append(stream, marshalProtocolValue(t, output)...)
		stream = append(stream, '\n')
	}
	stream = append(stream, suffix...)
	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))
	machine := NewPhaseStateMachine()
	if _, err := machine.ReadStartup(decoder); err != nil {
		t.Fatal(err)
	}
	if err := machine.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	if err := machine.RecordInvocationDelivered(decodedInvocationForPhaseTest(t, codec, phase)); err != nil {
		t.Fatal(err)
	}
	return machine, decoder
}

func lockedCaseIDsForPhaseStateTest(phase string) []string {
	if phase == "initial" {
		return lockedInitialCaseIDsForStateTest()
	}
	return lockedReconstructionCaseIDsForStateTest()
}

func lockedInitialCaseIDsForStateTest() []string {
	return []string{
		"initial.locked-capability-discovery",
		"initial.protected-lifecycle-create",
		"initial.replay-semantics",
		"initial.lifecycle-completion-and-status",
		"initial.exec-result-and-usage-evidence",
		"initial.stale-fencing-rejection",
		"initial.exec-cancellation",
		"initial.terminal-session-and-opaque-handoff",
		"initial.gateway-terminal-byte-round-trip",
		"initial.gateway-wrong-caller-and-cross-tenant-rejection",
		"initial.gateway-grant-expiry",
		"initial.gateway-revocation",
		"initial.artifact-staging-and-evidence",
		"initial.provider-cross-tenant-artifact-rejection",
		"initial.provider-mtls-caller-binding-rejection",
	}
}

func lockedReconstructionCaseIDsForStateTest() []string {
	return []string{
		"reconstruction.locked-capability-discovery",
		"reconstruction.durable-lifecycle",
		"reconstruction.retained-exec-usage-and-artifact-evidence",
		"reconstruction.durable-opaque-handoff",
		"reconstruction.same-shell-reconnect",
	}
}

func assertStateFailureValue(t *testing.T, err error, want StateFailure) {
	t.Helper()
	if errors.Is(err, io.EOF) {
		t.Fatalf("state failure exposed raw EOF: %v", err)
	}
	if got, ok := StateFailureOf(err); !ok || got != want {
		t.Fatalf("StateFailureOf(%v) = %q, %v; want %q", err, got, ok, want)
	}
}
