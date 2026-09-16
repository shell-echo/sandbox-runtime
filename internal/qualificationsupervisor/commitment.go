package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"

	"github.com/gowebpki/jcs"
	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

var ErrPreflight = errors.New("adapter committed preflight rejected")

// Shared by value copies so one descriptor set cannot mint two commitments.
// All custody APIs are single-owner, not concurrently callable.
type custodyClaim struct{ claimed bool }

// This is a supervisor-local, closed digest preimage, not a Provider wire DTO.
// New configurable inputs require a new version; no post-freeze overrides are
// permitted. Argv/env/pipe layout must be derived from the pinned transport.
type commitmentDocument struct {
	FormatVersion           int                   `json:"format_version"`
	Locations               LocationConfiguration `json:"locations"`
	ExecutablePath          string                `json:"executable_path"`
	ExecutableDigest        string                `json:"executable_digest"`
	ExecutableByteLimit     int64                 `json:"executable_byte_limit"`
	ProfileDigest           string                `json:"profile_digest"`
	ProfileFileDigest       string                `json:"profile_file_digest"`
	ProtocolID              string                `json:"protocol_id"`
	ProtocolVersion         string                `json:"protocol_version"`
	ProtocolSchemaDigest    string                `json:"protocol_schema_digest"`
	ProtocolSemanticsDigest string                `json:"protocol_semantics_digest"`
	TransportID             string                `json:"transport_id"`
}

type frozenCore struct {
	files               *LocationFiles
	executable          *Executable
	budget              *runBudget
	digest              string
	run                 *protocol.RunStateMachine
	evidence            map[string]PhaseEvidence
	transcript          *protocol.TranscriptProjection
	transcriptAttempted bool
	current             *PhaseAdmission
	failure             error
	closed              bool
	closeErr            error
	launch              *launchCore
	process             *processCore
}

// FrozenPreflight owns the retained descriptors after FinalizePreflight.
// Copies share the same single-owner state; methods must not race. This proves
// local preflight ordering only, not absence of upstream secret acquisition,
// real process execution, or isolation from same-UID/namespace writers.
type FrozenPreflight struct{ core *frozenCore }

// PhaseAdmission is a one-phase logical admission, bound to the live commitment.
// It cannot authorize invocation/credential bytes: startup identity must still
// pass the protocol machine first. Process operations recheck this exact
// admission before use. It is not independent process observation evidence.
type PhaseAdmission struct {
	owner          *frozenCore
	machine        *protocol.PhaseStateMachine
	phase          string
	launchPrepared bool
}

// FinalizePreflight rechecks custody and commits all static configuration under
// RFC 8785/SHA-256 before issuing any phase admission. Success transfers ownership
// and empties the two source holders; failure leaves their ownership unchanged.
// It performs no credential acquisition, network I/O or process start. The
// operator must supply static inputs before acquiring secrets/correlations.
func FinalizePreflight(ctx context.Context, prepared *PreparedConfiguration, files *LocationFiles, executable *Executable) (*FrozenPreflight, error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if ctx == nil || prepared == nil || files == nil || executable == nil ||
		!prepared.Matches(files.configuration) || files.claim == nil || executable.claim == nil ||
		files.claim.claimed || executable.claim.claimed || prepared.budget == nil ||
		files.budget != prepared.budget || executable.budget != prepared.budget {
		return nil, ErrPreflight
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	runContext, err := prepared.budget.context()
	if err != nil {
		return nil, err
	}
	operationContext, release, err := clippedContext(runContext, ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if files.Recheck(operationContext) != nil || executable.Recheck(operationContext) != nil {
		return nil, preflightError(operationContext)
	}
	document := commitmentDocument{
		FormatVersion: 1, Locations: prepared.locations,
		ExecutablePath: executable.path, ExecutableDigest: executable.digest, ExecutableByteLimit: executable.limit,
		ProfileDigest: qualificationprofile.ExpectedProfileDigest, ProfileFileDigest: files.profileDigest,
		ProtocolID: protocol.ProtocolID, ProtocolVersion: protocol.ProtocolVersion,
		ProtocolSchemaDigest: protocol.ExpectedProtocolSchemaDigest, ProtocolSemanticsDigest: protocol.ExpectedProtocolSemanticsDigest,
		TransportID: "darwin-linux-inherited-pipe-v1",
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrPreflight
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return nil, ErrPreflight
	}
	sum := sha256.Sum256(canonical)
	if err := contextFailure(operationContext); err != nil {
		return nil, err
	}
	ownedFiles, ownedExecutable := *files, *executable
	files.claim.claimed, executable.claim.claimed = true, true
	*files, *executable = LocationFiles{}, Executable{}
	return &FrozenPreflight{core: &frozenCore{
		files: &ownedFiles, executable: &ownedExecutable,
		budget: prepared.budget, digest: "sha256:" + hex.EncodeToString(sum[:]), run: protocol.NewRunStateMachine(),
		evidence: make(map[string]PhaseEvidence, 2),
	}}, nil
}

func preflightError(ctx context.Context) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	return ErrPreflight
}

// Digest is the adapter_configuration commitment, never its raw preimage.
// It remains historical metadata after Close, not a claim of current custody.
func (f *FrozenPreflight) Digest() string {
	if f == nil || f.core == nil {
		return ""
	}
	return f.core.digest
}

func (c *frozenCore) check(ctx context.Context) error {
	if c == nil || c.closed {
		return ErrPreflight
	}
	if c.failure != nil {
		return c.failure
	}
	if ctx == nil {
		c.failure = ErrPreflight
		return c.failure
	}
	if err := contextFailure(ctx); err != nil {
		c.failure = err
		return err
	}
	runContext, err := c.budget.context()
	if err != nil {
		c.failure = err
		return err
	}
	operationContext, release, err := clippedContext(runContext, ctx)
	if err != nil {
		c.failure = err
		return err
	}
	defer release()
	if c.files.Recheck(operationContext) != nil || c.executable.Recheck(operationContext) != nil {
		c.failure = preflightError(operationContext)
		return c.failure
	}
	return nil
}

// AdmitPhase is one-shot in initial/reconstruction order. Reconstruction uses
// the existing protocol gate (terminal, EOF and supplied clean exit), not a new
// caller-supplied completion boolean. Invalid ordering/custody is absorbing.
func (f *FrozenPreflight) AdmitPhase(ctx context.Context, phase string) (*PhaseAdmission, error) {
	if f == nil || f.core == nil {
		return nil, ErrPreflight
	}
	c := f.core
	if err := c.check(ctx); err != nil {
		return nil, err
	}
	if c.launch != nil && !c.launch.closed {
		c.failure = ErrPreflight
		return nil, c.failure
	}
	if c.process != nil && !c.process.cleanlyReaped() {
		c.failure = ErrPreflight
		return nil, c.failure
	}
	machine, err := c.run.BeginPhase(phase)
	if err != nil {
		c.failure = ErrPreflight
		return nil, c.failure
	}
	admission := &PhaseAdmission{owner: c, machine: machine, phase: phase}
	c.current = admission
	return admission, nil
}

// Recheck requires the exact currently admitted token and live custody.
// Call immediately before later protected work; it is not an atomic exec bind.
func (a *PhaseAdmission) Recheck(ctx context.Context) error {
	if a == nil || a.owner == nil || a.owner.current != a {
		return ErrPreflight
	}
	if p := a.owner.process; p != nil && p.admission == a && p.isStopping() {
		a.owner.failure = ErrPreflight
		return ErrPreflight
	}
	if err := a.owner.check(ctx); err != nil {
		return err
	}
	if a.machine.State() == protocol.PhaseStateFailed || a.machine.State() == protocol.PhaseStateComplete {
		a.owner.failure = ErrPreflight
		return ErrPreflight
	}
	return nil
}

// Machine exposes the already-owned protocol machine for future observed I/O.
// Its events are supervisor inputs, not proof that I/O happened.
func (a *PhaseAdmission) Machine() *protocol.PhaseStateMachine {
	if a == nil {
		return nil
	}
	return a.machine
}

// Locations returns a local-only copy of the original static strings.
func (a *PhaseAdmission) Locations() LocationConfiguration {
	if a == nil || a.owner == nil {
		return LocationConfiguration{}
	}
	return a.owner.files.configuration
}

// Close revokes every admission and closes descriptors, retaining caller state.
func (f *FrozenPreflight) Close() error {
	if f == nil || f.core == nil {
		return nil
	}
	c := f.core
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	var errProcess error
	if c.process != nil {
		errProcess = c.process.close()
	}
	var errLaunch error
	if c.launch != nil {
		errLaunch = c.launch.close()
	}
	errFiles, errExecutable := c.files.Close(), c.executable.Close()
	c.budget.close()
	if errProcess != nil || errLaunch != nil || errFiles != nil || errExecutable != nil {
		c.closeErr = errors.Join(ErrPreflight, errProcess)
	}
	return c.closeErr
}
