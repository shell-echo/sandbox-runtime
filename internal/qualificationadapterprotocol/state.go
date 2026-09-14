package qualificationadapterprotocol

import (
	"crypto/sha256"
	"errors"
	"io"
)

// PhaseState is the externally visible portion of the locked per-process
// protocol state currently implemented by PhaseStateMachine. Later P2.7c.2b
// slices extend the machine beyond one completed phase.
type PhaseState string

const (
	PhaseStateAwaitingStartup              PhaseState = "awaiting-startup"
	PhaseStateReadyForInvocation           PhaseState = "ready-for-invocation"
	PhaseStateAwaitingInvocationAcceptance PhaseState = "awaiting-invocation-acceptance"
	PhaseStateAwaitingNextScenario         PhaseState = "awaiting-next-scenario"
	PhaseStateAwaitingStartedResult        PhaseState = "awaiting-started-result"
	PhaseStateAwaitingTerminal             PhaseState = "awaiting-terminal"
	PhaseStateTerminalObserved             PhaseState = "terminal-observed"
	PhaseStateTerminalEOFObserved          PhaseState = "terminal-eof-observed"
	PhaseStateComplete                     PhaseState = "complete"
	PhaseStateFailed                       PhaseState = "failed"
)

// StateFailure is a stable, sanitized state-machine failure classification.
// It contains no adapter output, invocation value, path, endpoint, or process
// diagnostic.
type StateFailure string

const (
	StateFailureInvalidOrder   StateFailure = "invalid-or-out-of-order-message"
	StateFailureUnexpectedEOF  StateFailure = "unexpected-eof"
	StateFailureUnexpectedExit StateFailure = "unexpected-process-exit"
)

// StateError deliberately exposes only a bounded failure classification.
type StateError struct {
	Failure StateFailure
}

func (e *StateError) Error() string {
	return "adapter protocol state failed: " + string(e.Failure)
}

// StateFailureOf returns the stable classification for a state-machine error.
func StateFailureOf(err error) (StateFailure, bool) {
	var stateErr *StateError
	if !errors.As(err, &stateErr) {
		return "", false
	}
	return stateErr.Failure, true
}

// PhaseStateMachine enforces one complete per-process protocol through
// P2.7c.2b.5. Process launch and the bounded wait that supplies the exit event
// remain responsibilities of the qualificationsupervisor package.
type PhaseStateMachine struct {
	expectedPhase             string
	priorPhase                *PhaseStateMachine
	state                     PhaseState
	failure                   error
	startup                   DecodedMessage
	invocation                invocationReference
	invocationInputAuthorized bool
	lastSequence              int
	observedOutputWireBytes   int64
	messageTypes              []string
	credentialRoles           []string
	credentialPayloadLimit    int64
	caseOrder                 []string
	nextCaseIndex             int
	startedCaseID             string
	scenarioDispositions      []string
	terminal                  terminalReference
	codec                     *Codec
	decoder                   *OutputDecoder
}

type invocationReference struct {
	invocationID  string
	phase         string
	documentBytes int64
	wireBytes     int64
}

type terminalReference struct {
	messageType string
	completion  string
	errorCode   string
}

// NewPhaseStateMachine creates one startup state machine for one fresh adapter
// process. State machines must never be reused across phases.
func NewPhaseStateMachine() *PhaseStateMachine {
	return &PhaseStateMachine{state: PhaseStateAwaitingStartup}
}

// State returns the current sanitized state label.
func (m *PhaseStateMachine) State() PhaseState {
	if m == nil {
		return PhaseStateFailed
	}
	return m.state
}

// ReadStartup consumes and validates the first complete adapter output record.
// An empty stream, a non-startup first record, a duplicate call, or a prior
// invocation-input authorization failure permanently fails this machine.
// Decoder failures are already sanitized and are preserved as the first
// terminal error.
func (m *PhaseStateMachine) ReadStartup(decoder *OutputDecoder) (DecodedMessage, error) {
	if m == nil {
		return DecodedMessage{}, stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return DecodedMessage{}, m.failure
	}
	if m.state != PhaseStateAwaitingStartup || decoder == nil {
		return DecodedMessage{}, m.fail(StateFailureInvalidOrder)
	}

	message, err := decoder.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return DecodedMessage{}, m.fail(StateFailureUnexpectedEOF)
		}
		m.failure = err
		m.state = PhaseStateFailed
		return DecodedMessage{}, err
	}
	if !decodedEnvelopeIntact(message) || message.MessageType != "startup_identity" || message.Sequence == nil || *message.Sequence != 0 {
		return DecodedMessage{}, m.fail(StateFailureInvalidOrder)
	}
	if message.validatedBy == nil || message.outputDecoder != decoder || message.direction != decodedAdapterToHarness ||
		message.WireBytes != message.DocumentBytes+1 || decoder.Records() != 1 || decoder.TotalWireBytes() != message.WireBytes {
		return DecodedMessage{}, m.fail(StateFailureInvalidOrder)
	}
	if _, err := StartupIdentityFrom(message); err != nil {
		return DecodedMessage{}, m.fail(StateFailureInvalidOrder)
	}

	if !m.startupMatchesPrior(message) {
		return DecodedMessage{}, m.fail(StateFailureInvalidOrder)
	}
	m.startup = cloneDecodedMessage(message)
	m.codec = message.validatedBy
	m.decoder = decoder
	m.lastSequence = 0
	m.observedOutputWireBytes = message.WireBytes
	m.messageTypes = []string{message.MessageType}
	m.state = PhaseStateReadyForInvocation
	return cloneDecodedMessage(message), nil
}

// AuthorizeInvocationInput is the one-shot gate a process supervisor
// must pass before writing any invocation byte. This method grants the permit
// only; RecordInvocationDelivered records the later completed delivery.
func (m *PhaseStateMachine) AuthorizeInvocationInput() error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state != PhaseStateReadyForInvocation || m.invocationInputAuthorized || m.decoder == nil || m.decoder.Records() != 1 {
		return m.fail(StateFailureInvalidOrder)
	}
	m.invocationInputAuthorized = true
	return nil
}

// RecordInvocationDelivered records the exact schema-valid invocation after a
// supervisor has written those same bytes and closed adapter stdin. The
// physical write is deliberately outside this runtime-independent component.
func (m *PhaseStateMachine) RecordInvocationDelivered(invocation DecodedMessage) error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state != PhaseStateReadyForInvocation || !m.invocationInputAuthorized ||
		m.codec == nil || m.decoder == nil || m.decoder.Records() != 1 ||
		invocation.validatedBy != m.codec || invocation.direction != decodedHarnessToAdapter ||
		invocation.outputDecoder != nil || invocation.MessageType != "invocation" || invocation.Sequence != nil ||
		invocation.InvocationID == nil || invocation.Phase == nil || invocation.CaseID != nil ||
		invocation.WireBytes != invocation.DocumentBytes || !decodedEnvelopeIntact(invocation) {
		return m.fail(StateFailureInvalidOrder)
	}
	caseOrder, ok := m.codec.orderedCaseIDs(*invocation.Phase)
	if (m.expectedPhase != "" && *invocation.Phase != m.expectedPhase) ||
		(m.priorPhase != nil && *invocation.InvocationID == m.priorPhase.invocation.invocationID) {
		return m.fail(StateFailureInvalidOrder)
	}
	if !ok {
		return m.fail(StateFailureInvalidOrder)
	}
	// Retain only the allowlisted role labels, never descriptor values or the
	// raw invocation document. InvocationFrom also enforces semantic channel-ID
	// and file-descriptor uniqueness beyond JSON Schema's whole-item equality.
	details, err := InvocationDetailsFrom(invocation)
	if err != nil {
		return m.fail(StateFailureInvalidOrder)
	}
	m.credentialRoles = make([]string, len(details.CredentialChannels))
	for i, channel := range details.CredentialChannels {
		m.credentialRoles[i] = channel.Role
		m.credentialPayloadLimit += channel.MaxBytes
	}
	m.invocation = invocationReference{
		invocationID:  *invocation.InvocationID,
		phase:         *invocation.Phase,
		documentBytes: invocation.DocumentBytes,
		wireBytes:     invocation.WireBytes,
	}
	m.caseOrder = caseOrder
	m.nextCaseIndex = 0
	m.startedCaseID = ""
	m.scenarioDispositions = make([]string, 0, len(caseOrder))
	m.state = PhaseStateAwaitingInvocationAcceptance
	return nil
}

// AcceptInvocationAccepted advances only the normal acceptance branch. The
// caller must pass the next record decoded from the same stdout stream. A
// pre-binding protocol_error is a separate terminal branch implemented by
// P2.7c.2b.5 rather than being reclassified here.
func (m *PhaseStateMachine) AcceptInvocationAccepted(message DecodedMessage) error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state != PhaseStateAwaitingInvocationAcceptance || !m.validNextBoundOutput(message, "invocation_accepted") ||
		message.CaseID != nil || message.disposition != nil {
		return m.fail(StateFailureInvalidOrder)
	}
	m.recordOutput(message)
	m.state = PhaseStateAwaitingNextScenario
	return nil
}

// AcceptScenarioStarted accepts the next locked profile case only. A started
// case must be followed by a completed result for that same case.
func (m *PhaseStateMachine) AcceptScenarioStarted(message DecodedMessage) error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state != PhaseStateAwaitingNextScenario || m.nextCaseIndex >= len(m.caseOrder) ||
		!m.validNextBoundOutput(message, "scenario_started") || message.disposition != nil ||
		!sameStringValue(message.CaseID, m.caseOrder[m.nextCaseIndex]) {
		return m.fail(StateFailureInvalidOrder)
	}
	m.recordOutput(message)
	m.startedCaseID = m.caseOrder[m.nextCaseIndex]
	m.state = PhaseStateAwaitingStartedResult
	return nil
}

// AcceptScenarioResult enforces the two locked disposition branches. A
// completed result requires the immediately preceding scenario_started for the
// same case; a not_executed result forbids a preceding start. Every accepted
// result advances exactly one case in profile order.
func (m *PhaseStateMachine) AcceptScenarioResult(message DecodedMessage) error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if (m.state != PhaseStateAwaitingNextScenario && m.state != PhaseStateAwaitingStartedResult) ||
		m.nextCaseIndex >= len(m.caseOrder) || !m.validNextBoundOutput(message, "scenario_result") ||
		!sameStringValue(message.CaseID, m.caseOrder[m.nextCaseIndex]) {
		return m.fail(StateFailureInvalidOrder)
	}

	wantDisposition := "not_executed"
	if m.state == PhaseStateAwaitingStartedResult {
		if m.startedCaseID != m.caseOrder[m.nextCaseIndex] {
			return m.fail(StateFailureInvalidOrder)
		}
		wantDisposition = "completed"
	}
	if !sameStringValue(message.disposition, wantDisposition) {
		return m.fail(StateFailureInvalidOrder)
	}

	m.recordOutput(message)
	m.scenarioDispositions = append(m.scenarioDispositions, wantDisposition)
	m.nextCaseIndex++
	m.startedCaseID = ""
	if m.nextCaseIndex == len(m.caseOrder) {
		m.state = PhaseStateAwaitingTerminal
	} else {
		m.state = PhaseStateAwaitingNextScenario
	}
	return nil
}

// AcceptTerminal accepts exactly one of the two locked terminal branches. A
// normal invocation_finished is legal only after every case result and must
// summarize the observed dispositions. protocol_error uses the disjoint
// pre-binding and post-binding identity/error-code rules.
func (m *PhaseStateMachine) AcceptTerminal(message DecodedMessage) error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	switch message.MessageType {
	case "invocation_finished":
		return m.acceptInvocationFinished(message)
	case "protocol_error":
		return m.acceptProtocolError(message)
	default:
		return m.fail(StateFailureInvalidOrder)
	}
}

func (m *PhaseStateMachine) acceptInvocationFinished(message DecodedMessage) error {
	if m.state != PhaseStateAwaitingTerminal || len(m.scenarioDispositions) != len(m.caseOrder) ||
		!m.validNextBoundOutput(message, "invocation_finished") || message.CaseID != nil || message.disposition != nil ||
		message.errorCode != nil || message.terminal != nil ||
		!sameStringValue(message.completion, m.expectedCompletion()) {
		return m.fail(StateFailureInvalidOrder)
	}
	m.recordOutput(message)
	m.terminal = terminalReference{messageType: message.MessageType, completion: *message.completion}
	m.state = PhaseStateTerminalObserved
	return nil
}

func (m *PhaseStateMachine) acceptProtocolError(message DecodedMessage) error {
	if message.CaseID != nil || message.disposition != nil || message.completion != nil ||
		!sameBoolValue(message.terminal, true) {
		return m.fail(StateFailureInvalidOrder)
	}

	preBinding := m.state == PhaseStateAwaitingInvocationAcceptance
	if preBinding {
		if !m.validNextOutput(message, "protocol_error") || message.InvocationID != nil || message.Phase != nil ||
			!sameStringValue(message.errorCode, "invalid_invocation") {
			return m.fail(StateFailureInvalidOrder)
		}
	} else {
		if (m.state != PhaseStateAwaitingNextScenario && m.state != PhaseStateAwaitingStartedResult &&
			m.state != PhaseStateAwaitingTerminal) || !m.validNextBoundOutput(message, "protocol_error") ||
			message.errorCode == nil || !containsString(postBindingProtocolErrorCodes, *message.errorCode) {
			return m.fail(StateFailureInvalidOrder)
		}
	}

	m.recordOutput(message)
	m.terminal = terminalReference{messageType: message.MessageType, errorCode: *message.errorCode}
	m.state = PhaseStateTerminalObserved
	return nil
}

// ObserveStdoutEOF reads the bound stdout decoder once. EOF is accepted only
// after a terminal record and only when no additional byte was consumed.
// Complete, malformed, or truncated output after a terminal record fails
// closed without exposing its contents.
func (m *PhaseStateMachine) ObserveStdoutEOF() error {
	if m == nil {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state == PhaseStateComplete {
		return stateFailure(StateFailureInvalidOrder)
	}
	if m.decoder == nil {
		return m.fail(StateFailureInvalidOrder)
	}
	_, err := m.decoder.Next()
	if err == nil {
		return m.fail(StateFailureInvalidOrder)
	}
	if !errors.Is(err, io.EOF) {
		m.failure = err
		m.state = PhaseStateFailed
		return err
	}
	if m.state != PhaseStateTerminalObserved {
		return m.fail(StateFailureUnexpectedEOF)
	}
	if m.decoder.TotalWireBytes() != m.observedOutputWireBytes {
		return m.fail(StateFailureInvalidOrder)
	}
	m.state = PhaseStateTerminalEOFObserved
	return nil
}

// ObserveProcessExit consumes the process-exit event supplied by a bounded-wait
// supervisor. Only a clean exit after terminal and stdout EOF
// completes the phase; this method does not inspect or wait on a process.
func (m *PhaseStateMachine) ObserveProcessExit(clean bool) error {
	if m == nil {
		return stateFailure(StateFailureUnexpectedExit)
	}
	if m.failure != nil {
		return m.failure
	}
	if m.state == PhaseStateComplete {
		return stateFailure(StateFailureUnexpectedExit)
	}
	if m.state != PhaseStateTerminalEOFObserved || !clean {
		return m.fail(StateFailureUnexpectedExit)
	}
	m.state = PhaseStateComplete
	return nil
}

func (m *PhaseStateMachine) expectedCompletion() string {
	for _, disposition := range m.scenarioDispositions {
		if disposition == "not_executed" {
			return "stopped"
		}
	}
	return "completed"
}

func (m *PhaseStateMachine) validNextBoundOutput(message DecodedMessage, messageType string) bool {
	if !m.validNextOutput(message, messageType) || !sameStringValue(message.InvocationID, m.invocation.invocationID) ||
		!sameStringValue(message.Phase, m.invocation.phase) {
		return false
	}
	return true
}

func (m *PhaseStateMachine) validNextOutput(message DecodedMessage, messageType string) bool {
	if m.decoder == nil || m.codec == nil || message.validatedBy != m.codec || message.outputDecoder != m.decoder ||
		message.direction != decodedAdapterToHarness || message.MessageType != messageType || message.Sequence == nil ||
		*message.Sequence != m.lastSequence+1 || m.decoder.Records() != *message.Sequence+1 ||
		message.WireBytes != message.DocumentBytes+1 ||
		m.decoder.TotalWireBytes() != m.observedOutputWireBytes+message.WireBytes || !decodedEnvelopeIntact(message) {
		return false
	}
	return true
}

func (m *PhaseStateMachine) recordOutput(message DecodedMessage) {
	m.lastSequence = *message.Sequence
	m.observedOutputWireBytes += message.WireBytes
	m.messageTypes = append(m.messageTypes, message.MessageType)
}

func (m *PhaseStateMachine) fail(failure StateFailure) error {
	if m.state == PhaseStateComplete {
		return stateFailure(failure)
	}
	if m.failure == nil {
		m.failure = stateFailure(failure)
		m.state = PhaseStateFailed
	}
	return m.failure
}

func stateFailure(failure StateFailure) error {
	return &StateError{Failure: failure}
}

func cloneDecodedMessage(message DecodedMessage) DecodedMessage {
	cloned := message
	cloned.Document = append([]byte(nil), message.Document...)
	cloned.Sequence = cloneInt(message.Sequence)
	cloned.InvocationID = cloneString(message.InvocationID)
	cloned.Phase = cloneString(message.Phase)
	cloned.CaseID = cloneString(message.CaseID)
	cloned.protocolSchemaDigest = cloneString(message.protocolSchemaDigest)
	cloned.protocolSemanticsDigest = cloneString(message.protocolSemanticsDigest)
	cloned.disposition = cloneString(message.disposition)
	cloned.completion = cloneString(message.completion)
	cloned.errorCode = cloneString(message.errorCode)
	cloned.terminal = cloneBool(message.terminal)
	return cloned
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func sameStringValue(value *string, want string) bool {
	return value != nil && *value == want
}

func sameBoolValue(value *bool, want bool) bool {
	return value != nil && *value == want
}

func decodedEnvelopeIntact(message DecodedMessage) bool {
	if message.validatedBy == nil || int64(len(message.Document)) != message.DocumentBytes ||
		sha256.Sum256(message.Document) != message.documentDigest {
		return false
	}
	decoded, err := message.validatedBy.decodeDocument(message.Document, message.WireBytes)
	if err != nil {
		return false
	}
	return decoded.MessageType == message.MessageType && equalOptionalInt(decoded.Sequence, message.Sequence) &&
		equalOptionalString(decoded.InvocationID, message.InvocationID) && equalOptionalString(decoded.Phase, message.Phase) &&
		equalOptionalString(decoded.CaseID, message.CaseID) &&
		equalOptionalString(decoded.protocolSchemaDigest, message.protocolSchemaDigest) &&
		equalOptionalString(decoded.protocolSemanticsDigest, message.protocolSemanticsDigest) &&
		equalOptionalString(decoded.disposition, message.disposition) &&
		equalOptionalString(decoded.completion, message.completion) &&
		equalOptionalString(decoded.errorCode, message.errorCode) &&
		equalOptionalBool(decoded.terminal, message.terminal)
}

func equalOptionalInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalOptionalBool(left, right *bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
