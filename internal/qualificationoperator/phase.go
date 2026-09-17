package qualificationoperator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationsupervisor"
)

var ErrPhaseExecution = errors.New("qualification phase execution failed")

type ProviderRestarter interface {
	Restart(context.Context) (string, error)
}

type PhaseRouting interface {
	Arm(context.Context) error
}

type PhaseExecutor struct {
	preflight   *qualificationsupervisor.FrozenPreflight
	codec       *protocol.Codec
	credentials *Credentials
	restarter   ProviderRestarter
	routing     PhaseRouting

	mu                sync.Mutex
	initialInvocation string
	initialProcesses  map[string]string
	phaseEvidence     map[string]qualificationsupervisor.PhaseEvidence
	plannedProcesses  map[string]map[string]string
	progressByPhase   map[string][]qualificationharness.ScenarioProgress
	terminalByPhase   map[string]string
}

func NewPhaseExecutor(preflight *qualificationsupervisor.FrozenPreflight, codec *protocol.Codec, credentials *Credentials, restarter ProviderRestarter, routing PhaseRouting, initialProviderIdentity string) (*PhaseExecutor, error) {
	if preflight == nil || codec == nil || credentials == nil || restarter == nil || routing == nil || initialProviderIdentity == "" {
		return nil, ErrPhaseExecution
	}
	return &PhaseExecutor{
		preflight: preflight, codec: codec, credentials: credentials, restarter: restarter, routing: routing,
		initialProcesses: map[string]string{"provider": initialProviderIdentity},
		phaseEvidence:    make(map[string]qualificationsupervisor.PhaseEvidence, 2), plannedProcesses: make(map[string]map[string]string, 2),
		progressByPhase: make(map[string][]qualificationharness.ScenarioProgress, 2), terminalByPhase: make(map[string]string, 2),
	}, nil
}

func (e *PhaseExecutor) StartInitial(ctx context.Context, directive qualificationharness.InitialPhaseDirective) (qualificationharness.InitialPhaseSession, error) {
	if directive.PhaseID != qualificationharness.InitialPhaseID || len(directive.CaseIDs) != 15 {
		return nil, ErrPhaseExecution
	}
	invocationID, err := randomLabel("qualification-initial-")
	if err != nil {
		return nil, ErrPhaseExecution
	}
	session, err := e.start(ctx, "initial", invocationID)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.initialInvocation = invocationID
	e.initialProcesses["qualification_adapter"] = session.process.ProcessIdentity()
	e.initialProcesses["external_caller"], _ = randomLabel("caller-process-")
	e.initialProcesses["caller_gateway"], _ = randomLabel("gateway-process-")
	e.plannedProcesses["initial"] = cloneLabels(e.initialProcesses)
	e.mu.Unlock()
	return session, nil
}

func (e *PhaseExecutor) StartReconstruction(ctx context.Context, directive qualificationharness.ReconstructionPhaseDirective) (qualificationharness.ReconstructionPhaseSession, qualificationharness.ReconstructionStartProgress, error) {
	if directive.PhaseID != qualificationharness.ReconstructionPhaseID || len(directive.CaseIDs) != 5 || len(directive.RestartComponents) != 4 {
		return nil, qualificationharness.ReconstructionStartProgress{}, ErrPhaseExecution
	}
	providerIdentity, err := e.restarter.Restart(ctx)
	if err != nil {
		return nil, qualificationharness.ReconstructionStartProgress{}, ErrPhaseExecution
	}
	invocationID, err := randomLabel("qualification-reconstruction-")
	if err != nil {
		return nil, qualificationharness.ReconstructionStartProgress{}, ErrPhaseExecution
	}
	session, err := e.start(ctx, "reconstruction", invocationID)
	if err != nil {
		return nil, qualificationharness.ReconstructionStartProgress{}, err
	}
	reconstruction := map[string]string{"provider": providerIdentity, "qualification_adapter": session.process.ProcessIdentity()}
	reconstruction["external_caller"], _ = randomLabel("caller-process-")
	reconstruction["caller_gateway"], _ = randomLabel("gateway-process-")
	e.mu.Lock()
	initialInvocation := e.initialInvocation
	initial := cloneLabels(e.initialProcesses)
	e.plannedProcesses["reconstruction"] = cloneLabels(reconstruction)
	e.mu.Unlock()
	progress := qualificationharness.ReconstructionStartProgress{
		InitialInvocationID: initialInvocation, ReconstructionInvocationID: invocationID,
		ProcessReplacements: make([]qualificationharness.ProcessReplacementProgress, 0, len(directive.RestartComponents)),
	}
	for _, component := range directive.RestartComponents {
		if initial[component] == "" || reconstruction[component] == "" {
			_ = session.Close()
			return nil, qualificationharness.ReconstructionStartProgress{}, ErrPhaseExecution
		}
		progress.ProcessReplacements = append(progress.ProcessReplacements, qualificationharness.ProcessReplacementProgress{
			Component: component, InitialProcessIdentity: initial[component], ReconstructionProcessIdentity: reconstruction[component],
		})
	}
	return session, progress, nil
}

func (e *PhaseExecutor) start(ctx context.Context, phase, invocationID string) (*phaseSession, error) {
	if err := e.routing.Arm(ctx); err != nil {
		return nil, ErrPhaseExecution
	}
	admission, err := e.preflight.AdmitPhase(ctx, phase)
	if err != nil {
		return nil, ErrPhaseExecution
	}
	launch, err := qualificationsupervisor.PrepareLaunch(ctx, admission)
	if err != nil {
		return nil, ErrPhaseExecution
	}
	process, err := qualificationsupervisor.StartProcess(ctx, launch)
	if err != nil {
		return nil, ErrPhaseExecution
	}
	startup, err := process.ObserveStartup(ctx, e.codec)
	if err != nil {
		_ = process.Close()
		return nil, ErrPhaseExecution
	}
	locations := admission.Locations()
	descriptors := make([]map[string]any, len(startup.CredentialChannels))
	payloads := make([]qualificationsupervisor.CredentialPayload, len(startup.CredentialChannels))
	for index, requirement := range startup.CredentialChannels {
		payload, ok := e.credentials.Payloads[requirement.ChannelID]
		if !ok {
			_ = process.Close()
			return nil, ErrPhaseExecution
		}
		descriptors[index] = map[string]any{
			"channel_id": requirement.ChannelID, "role": requirement.Role, "actor": requirement.Actor,
			"media_type": requirement.MediaType, "max_bytes": requirement.MaxBytes, "file_descriptor": 3 + index,
		}
		payloads[index] = qualificationsupervisor.CredentialPayload{ChannelID: requirement.ChannelID, Data: payload}
	}
	document, err := json.Marshal(map[string]any{
		"format_version": 1, "protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion,
		"message_type": "invocation", "invocation_id": invocationID, "phase": phase,
		"profile_path": locations.ProfilePath, "provider_origin": locations.ProviderOrigin,
		"gateway_probe_endpoint": locations.GatewayProbeEndpoint, "credential_channel_descriptors": descriptors,
		"caller_state_root": locations.CallerStateRoot,
	})
	if err != nil {
		_ = process.Close()
		return nil, ErrPhaseExecution
	}
	if _, err := process.DeliverInvocation(ctx, document, payloads); err != nil {
		_ = process.Close()
		return nil, ErrPhaseExecution
	}
	session := &phaseSession{owner: e, phase: phase, process: process, progress: make(chan qualificationharness.ScenarioProgress, 15), done: make(chan error, 1), accepted: make(chan struct{})}
	go func() {
		err := process.ObserveCompletionWithCallbacks(ctx, func() error {
			close(session.accepted)
			return nil
		}, func(progress qualificationsupervisor.ScenarioProgress) error {
			projected := qualificationharness.ScenarioProgress{CaseID: progress.CaseID, Disposition: progress.Disposition, Interactions: make([]qualificationharness.InteractionProgress, len(progress.Interactions))}
			if progress.ReasonCode != nil {
				value := *progress.ReasonCode
				projected.ReasonCode = &value
			}
			for index, interaction := range progress.Interactions {
				projected.Interactions[index] = qualificationharness.InteractionProgress{InteractionID: interaction.InteractionID, WireAttempts: interaction.WireAttempts}
			}
			e.mu.Lock()
			e.progressByPhase[phase] = append(e.progressByPhase[phase], projected)
			e.mu.Unlock()
			select {
			case session.progress <- projected:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		})
		if code := process.TerminalErrorCode(); code != "" {
			e.mu.Lock()
			e.terminalByPhase[phase] = code
			e.mu.Unlock()
		}
		if err == nil {
			if evidence, ok := process.Evidence(); ok {
				e.mu.Lock()
				e.phaseEvidence[phase] = evidence
				e.mu.Unlock()
			} else {
				err = ErrPhaseExecution
			}
		}
		close(session.progress)
		session.done <- err
	}()
	select {
	case <-session.accepted:
		return session, nil
	case err := <-session.done:
		_ = process.Close()
		return nil, errors.Join(ErrPhaseExecution, err)
	case <-ctx.Done():
		_ = process.Close()
		return nil, errors.Join(ErrPhaseExecution, context.Cause(ctx))
	}
}

func (e *PhaseExecutor) TerminalErrorCode(phase string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.terminalByPhase[phase]
}

type phaseSession struct {
	owner      *PhaseExecutor
	phase      string
	process    *qualificationsupervisor.StartedProcess
	progress   chan qualificationharness.ScenarioProgress
	done       chan error
	accepted   chan struct{}
	finishOnce sync.Once
	finishErr  error
}

func (s *phaseSession) NextScenario(ctx context.Context) (qualificationharness.ScenarioProgress, error) {
	select {
	case progress, ok := <-s.progress:
		if !ok {
			return qualificationharness.ScenarioProgress{}, ErrPhaseExecution
		}
		return progress, nil
	case <-ctx.Done():
		return qualificationharness.ScenarioProgress{}, context.Cause(ctx)
	}
}

func (s *phaseSession) Finish(ctx context.Context) error {
	s.finishOnce.Do(func() {
		select {
		case s.finishErr = <-s.done:
		case <-ctx.Done():
			s.finishErr = context.Cause(ctx)
		}
	})
	if s.finishErr != nil {
		return ErrPhaseExecution
	}
	return nil
}

func (s *phaseSession) Close() error {
	if s == nil || s.process == nil {
		return nil
	}
	return s.process.Close()
}

func (e *PhaseExecutor) Evidence(phase string) (qualificationsupervisor.PhaseEvidence, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	value, ok := e.phaseEvidence[phase]
	return value, ok
}

func (e *PhaseExecutor) PlannedProcesses(phase string) map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneLabels(e.plannedProcesses[phase])
}

func (e *PhaseExecutor) Progress(phase string) []qualificationharness.ScenarioProgress {
	e.mu.Lock()
	defer e.mu.Unlock()
	values := e.progressByPhase[phase]
	result := make([]qualificationharness.ScenarioProgress, len(values))
	copy(result, values)
	for index := range result {
		result[index].Interactions = append([]qualificationharness.InteractionProgress(nil), values[index].Interactions...)
	}
	return result
}

func randomLabel(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func cloneLabels(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
