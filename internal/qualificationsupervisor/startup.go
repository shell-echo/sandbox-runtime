package qualificationsupervisor

import (
	"context"
	"errors"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrStartup = errors.New("adapter startup validation failed")

type startupResult struct {
	identity protocol.StartupIdentity
	err      error
}

// ObserveStartup exclusively consumes the first stdout record through the
// locked Codec and the already-bound phase machine. It returns a structured
// copy, never raw stdout. No invocation/credential writer is exposed before or
// after this call. Process stdout remains owned by the retained decoder for
// later state transitions. The release identities are process assertions;
// independent artifact provenance remains an external qualification gate.
//
// This method is one-shot across StartedProcess copies. It may run concurrently
// with Close/context cleanup, but not with any other process protocol method.
func (p *StartedProcess) ObserveStartup(ctx context.Context, codec *protocol.Codec) (protocol.StartupIdentity, error) {
	if p == nil || p.core == nil {
		return protocol.StartupIdentity{}, ErrStartup
	}
	core := p.core
	core.protocolMu.Lock()
	defer core.protocolMu.Unlock()
	if core.startupAttempted || core.isStopping() {
		core.admission.owner.failure = ErrStartup
		_ = core.close()
		return protocol.StartupIdentity{}, ErrStartup
	}
	core.startupAttempted = true
	if ctx == nil {
		core.admission.owner.failure = ErrStartup
		cleanupErr := core.close()
		return protocol.StartupIdentity{}, errors.Join(ErrStartup, cleanupErr)
	}
	operationContext, release, err := clippedContext(core.runContext, ctx)
	if err != nil {
		core.admission.owner.failure = err
		cleanupErr := core.close()
		return protocol.StartupIdentity{}, errors.Join(ErrStartup, err, cleanupErr)
	}
	defer release()
	ctx = operationContext
	decoder := codec.NewOutputDecoder(processOutput{core.parent[1]})
	result := make(chan startupResult, 1)
	go func() {
		message, err := core.admission.machine.ReadStartup(decoder)
		if err != nil {
			result <- startupResult{err: err}
			return
		}
		identity, err := protocol.StartupIdentityFrom(message)
		result <- startupResult{identity: identity, err: err}
	}()
	var observed startupResult
	select {
	case observed = <-result:
	case <-ctx.Done():
		_ = core.close()
		<-result // closing stdout makes the bounded decoder return
		observed.err = contextFailure(ctx)
	case <-core.done:
		observed = <-result
	}
	if observed.err != nil {
		core.admission.owner.failure = observed.err
		cleanupErr := core.close()
		return protocol.StartupIdentity{}, errors.Join(ErrStartup, observed.err, cleanupErr)
	}
	if err := core.admission.Recheck(ctx); err != nil {
		core.admission.owner.failure = err
		cleanupErr := core.close()
		return protocol.StartupIdentity{}, errors.Join(ErrStartup, err, cleanupErr)
	}
	core.decoder = decoder
	core.codec = codec
	core.startup = protocol.CloneStartupIdentity(observed.identity)
	core.startupValidated = true
	return protocol.CloneStartupIdentity(core.startup), nil
}

// StartupIdentity returns a defensive copy only after successful observation.
func (p *StartedProcess) StartupIdentity() (protocol.StartupIdentity, bool) {
	if p == nil || p.core == nil {
		return protocol.StartupIdentity{}, false
	}
	p.core.protocolMu.Lock()
	defer p.core.protocolMu.Unlock()
	if !p.core.startupValidated {
		return protocol.StartupIdentity{}, false
	}
	return protocol.CloneStartupIdentity(p.core.startup), true
}
