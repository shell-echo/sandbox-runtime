package qualificationsupervisor

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrLaunch = errors.New("adapter launch preparation rejected")

// Transport-derived constants, not operator-provided arguments/environment.
// argv[0] is fixed; there are no application arguments or inherited env values.
const launchArgv0 = "qualification-adapter"
const launchCredentialSlots = protocol.MaxCredentialChannels

type launchCore struct {
	admission         *PhaseAdmission
	path, directory   string
	argv, environment []string
	child             [3 + launchCredentialSlots]*os.File
	parent            [3 + launchCredentialSlots]*os.File
	closed            bool
}

// PreparedLaunch owns unused anonymous pipes, NOT a started process. All
// handles and writable endpoints stay private. StartProcess transfers ownership
// to StartedProcess; input remains gated by later work. Copies share one
// single-owner lifetime and must not race.
type PreparedLaunch struct{ core *launchCore }

// PrepareLaunch consumes one exact fresh admission. It checks an empty private
// working directory, reserves stdin/stdout/stderr and eight credential slots,
// and rechecks custody after allocation. No bytes are written and no process,
// goroutine, shell, PATH lookup, environment lookup or credential acquisition
// occurs. StartProcess maps slots to child fds 3..10;
// they are not yet channel roles or authorization to deliver credentials.
func PrepareLaunch(ctx context.Context, a *PhaseAdmission) (*PreparedLaunch, error) {
	return prepareLaunch(ctx, a, os.Pipe)
}

func prepareLaunch(ctx context.Context, a *PhaseAdmission, pipe func() (*os.File, *os.File, error)) (_ *PreparedLaunch, resultErr error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if a == nil || a.owner == nil || a.owner.current != a {
		return nil, ErrLaunch
	}
	if a.launchPrepared {
		a.owner.failure = ErrLaunch
		return nil, ErrLaunch
	}
	a.launchPrepared = true
	l := &launchCore{admission: a, path: a.owner.executable.path,
		directory: a.owner.files.configuration.WorkingDirectory, argv: []string{launchArgv0}, environment: []string{}}
	defer func() {
		if resultErr != nil {
			_ = l.close()
			a.owner.failure = resultErr
		}
	}()
	if err := l.check(ctx); err != nil {
		return nil, err
	}
	for i := range l.child {
		if err := contextFailure(ctx); err != nil {
			return nil, err
		}
		r, w, err := pipe()
		l.child[i], l.parent[i] = r, w
		if i == 1 || i == 2 {
			l.child[i], l.parent[i] = w, r
		}
		if err != nil || r == nil || w == nil {
			return nil, ErrLaunch
		}
	}
	if err := l.check(ctx); err != nil {
		return nil, err
	}
	a.owner.launch = l
	return &PreparedLaunch{core: l}, nil
}

func (l *launchCore) check(ctx context.Context) error {
	if l == nil || l.closed || ctx == nil {
		return ErrLaunch
	}
	if err := l.admission.Recheck(ctx); err != nil {
		if contextFailure(ctx) != nil {
			return contextFailure(ctx)
		}
		return ErrLaunch
	}
	if l.admission.machine.State() != protocol.PhaseStateAwaitingStartup {
		return ErrLaunch
	}
	// Reopen, rather than consuming the retained descriptor's directory offset.
	// Enumerate only the work directory, never the caller-state directory.
	pin, err := openDirectoryPin(ctx, l.directory)
	if err != nil {
		if contextFailure(ctx) != nil {
			return contextFailure(ctx)
		}
		return ErrLaunch
	}
	defer pin.file.Close()
	if !sameDirectory(pin.info, l.admission.owner.files.work.info) || !admissibleDirectory(pin.info, true) {
		return ErrLaunch
	}
	names, err := pin.file.Readdirnames(1)
	if len(names) != 0 || !errors.Is(err, io.EOF) {
		return ErrLaunch
	}
	return contextFailure(ctx)
}

// Recheck is still preparation-only. StartProcess additionally establishes
// process ownership and cleanup; neither is an atomic pathname/exec binding.
func (l *PreparedLaunch) Recheck(ctx context.Context) error {
	if l == nil || l.core == nil {
		return ErrLaunch
	}
	err := l.core.check(ctx)
	if err != nil && l.core.admission.owner.failure == nil {
		l.core.admission.owner.failure = err
	}
	return err
}

func (l *launchCore) close() error {
	if l == nil || l.closed {
		return nil
	}
	l.closed = true
	var result error
	for i := range l.child {
		for _, file := range []*os.File{l.child[i], l.parent[i]} {
			if file != nil && file.Close() != nil {
				result = ErrLaunch
			}
		}
		l.child[i], l.parent[i] = nil, nil
	}
	return result
}

// Close releases all endpoints without writing bytes and revokes admission.
// It never removes directories. FrozenPreflight.Close also closes this object.
// After StartProcess transfers ownership, this becomes a no-op; close the
// StartedProcess or its frozen owner instead.
func (l *PreparedLaunch) Close() error {
	if l == nil || l.core == nil || l.core.closed {
		return nil
	}
	if l.core.admission.owner.failure == nil {
		l.core.admission.owner.failure = ErrLaunch
	}
	return l.core.close()
}
