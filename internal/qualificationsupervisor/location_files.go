package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

var (
	ErrLocationFiles = errors.New("adapter location filesystem preflight failed")
	// On failure after mkdir, callers must account for the new directory. It is
	// never removed automatically, even if it appears empty.
	ErrStateDirectoryRetained = errors.New("new caller state directory retained for operator inspection")
)

const maxLocationProfileBytes int64 = 2 << 20

type directoryPin struct {
	file      *os.File
	path      string
	info      os.FileInfo
	ancestors []os.FileInfo // root through leaf, metadata only
}

// LocationFiles retains read-only, close-on-exec descriptors. It is single-owner
// and must not race Close/Recheck. No descriptor or pathname is exported into
// evidence. This is filesystem preflight, NOT a finalized configuration or a
// start permit. Trusted operator custody of the namespace remains required;
// rechecking cannot prevent a later owner/root write, rename or mount race.
// Admission checks POSIX mode/owner metadata, not ACLs, mount policy or isolation
// from same-UID processes. The operator must exclude extra ACL grants and
// untrusted namespace writers; this is not a hostile multi-tenant boundary.
type LocationFiles struct {
	claim                                             *custodyClaim
	budget                                            *runBudget
	configuration                                     LocationConfiguration
	profile                                           *os.File
	profileInfo                                       os.FileInfo
	profileDigest                                     string
	profileParent, work, evidence, stateParent, state *directoryPin
}

// OpenLocationFiles opens existing profile/work/evidence/parent paths without
// following any symlink and exclusively creates the state leaf with mode 0700.
// It never opens caller-state entries, acquires credentials or starts processes.
// The locked profile document is verified here; repository schema/Contract
// verification is still a separate definition gate. Local filesystems must be
// healthy: context checks cannot interrupt kernel-blocked syscalls.
func OpenLocationFiles(ctx context.Context, prepared *PreparedConfiguration) (_ *LocationFiles, resultErr error) {
	if !supportedPlatform(runtime.GOOS) {
		return nil, ErrUnsupportedPlatform
	}
	if ctx == nil || prepared == nil || !prepared.Matches(prepared.locations) {
		return nil, ErrLocationFiles
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	callerContext := ctx
	// This is the first possible supervisor preflight read. Starting here keeps
	// lexical validation outside the locked execution clock.
	runContext, err := prepared.budget.startContext()
	if err != nil {
		return nil, err
	}
	operationContext, release, err := clippedContext(runContext, ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx = operationContext
	f := &LocationFiles{claim: &custodyClaim{}, budget: prepared.budget, configuration: prepared.locations}
	created := false
	defer func() {
		if resultErr != nil {
			_ = f.Close()
			if created {
				resultErr = errors.Join(resultErr, ErrStateDirectoryRetained)
			}
		}
	}()
	f.profile, err = openNoFollow(f.configuration.ProfilePath)
	if err != nil {
		return nil, ErrLocationFiles
	}
	f.profileInfo, err = f.profile.Stat()
	if err != nil || !admissibleProfile(f.profileInfo) {
		return nil, ErrLocationFiles
	}
	document, err := io.ReadAll(io.LimitReader(locationContextReader{ctx, f.profile}, maxLocationProfileBytes+1))
	if err != nil {
		return nil, locationError(ctx)
	}
	if int64(len(document)) != f.profileInfo.Size() || int64(len(document)) > maxLocationProfileBytes ||
		qualificationprofile.VerifyCodingShellV1ProfileDocument(document) != nil {
		return nil, ErrLocationFiles
	}
	sum := sha256.Sum256(document)
	f.profileDigest = "sha256:" + hex.EncodeToString(sum[:])
	for _, item := range []struct {
		target **directoryPin
		path   string
	}{
		{&f.profileParent, path.Dir(f.configuration.ProfilePath)},
		{&f.work, f.configuration.WorkingDirectory}, {&f.evidence, f.configuration.EvidenceRoot},
		{&f.stateParent, path.Dir(f.configuration.CallerStateRoot)},
	} {
		if err := contextFailure(ctx); err != nil {
			return nil, err
		}
		*item.target, err = openDirectoryPin(ctx, item.path)
		if err != nil {
			return nil, locationError(ctx)
		}
		if !admissibleDirectory((*item.target).info, false) {
			return nil, ErrLocationFiles
		}
	}
	// Detect physical ancestor aliases before mutation as well as lexical ones.
	if containsDirectory(f.profileParent, f.work) || containsDirectory(f.profileParent, f.evidence) ||
		containsDirectory(f.stateParent, f.work) || containsDirectory(f.stateParent, f.evidence) {
		return nil, ErrLocationFiles
	}
	if err := f.recheckProfile(ctx); err != nil {
		return nil, err
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	created, err = createStateDirectory(f.stateParent.file, path.Base(f.configuration.CallerStateRoot))
	if err != nil {
		return nil, ErrLocationFiles
	}
	if err := callerContext.Err(); err != nil {
		return nil, err
	}
	f.state, err = openDirectoryPin(ctx, f.configuration.CallerStateRoot)
	if err != nil {
		return nil, locationError(ctx)
	}
	// Bind the opened path back to the retained mkdir parent, not only a name.
	if !stateMatchesParent(f.stateParent.file, path.Base(f.configuration.CallerStateRoot), f.state.info) {
		return nil, ErrLocationFiles
	}
	if err := f.Recheck(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

type locationContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r locationContextReader) Read(p []byte) (int, error) {
	if err := contextFailure(r.ctx); err != nil {
		return 0, err
	}
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	return r.source.Read(p)
}

func locationError(ctx context.Context) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	return ErrLocationFiles
}

func containsDirectory(child, ancestor *directoryPin) bool {
	for _, info := range child.ancestors {
		if os.SameFile(info, ancestor.info) {
			return true
		}
	}
	return false
}

func (f *LocationFiles) recheckProfile(ctx context.Context) error {
	before, err := f.profile.Stat()
	if err != nil || !admissibleProfile(before) || !sameProfileSnapshot(f.profileInfo, before) {
		return ErrLocationFiles
	}
	digest, n, err := digestReader(ctx, io.NewSectionReader(f.profile, 0, maxLocationProfileBytes+1), maxLocationProfileBytes)
	if err != nil {
		return locationError(ctx)
	}
	if digest != f.profileDigest || n != before.Size() {
		return ErrLocationFiles
	}
	after, err := f.profile.Stat()
	if err != nil || !admissibleProfile(after) || !sameProfileSnapshot(before, after) {
		return ErrLocationFiles
	}
	current, err := openNoFollow(f.configuration.ProfilePath)
	if err != nil {
		return ErrLocationFiles
	}
	info, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil || !admissibleProfile(info) || !sameProfileSnapshot(after, info) {
		return ErrLocationFiles
	}
	return contextFailure(ctx)
}

// Recheck rehashes only the profile; directories are inspected only by metadata.
// It deliberately ignores directory mtime/size so caller-owned state can evolve.
// No state entry is enumerated or read, and no pathname is repaired or replaced.
func (f *LocationFiles) Recheck(ctx context.Context) error {
	if ctx == nil || f == nil || f.profile == nil || f.state == nil {
		return ErrLocationFiles
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	if err := f.recheckProfile(ctx); err != nil {
		return err
	}
	for _, pin := range []*directoryPin{f.profileParent, f.work, f.evidence, f.stateParent, f.state} {
		if pin == nil || pin.file == nil {
			return ErrLocationFiles
		}
		info, err := pin.file.Stat()
		if err != nil || !admissibleDirectory(info, pin == f.state) || !sameDirectory(pin.info, info) {
			return ErrLocationFiles
		}
		current, err := openDirectoryPin(ctx, pin.path)
		if err != nil {
			return locationError(ctx)
		}
		closeErr := current.file.Close()
		if closeErr != nil || !sameDirectory(info, current.info) || len(pin.ancestors) != len(current.ancestors) {
			return ErrLocationFiles
		}
		for i := range pin.ancestors {
			if !sameDirectory(pin.ancestors[i], current.ancestors[i]) {
				return ErrLocationFiles
			}
		}
	}
	if containsDirectory(f.profileParent, f.state) || containsDirectory(f.profileParent, f.work) ||
		containsDirectory(f.profileParent, f.evidence) || containsDirectory(f.state, f.work) ||
		containsDirectory(f.work, f.state) || containsDirectory(f.state, f.evidence) || containsDirectory(f.evidence, f.state) {
		return ErrLocationFiles
	}
	return contextFailure(ctx)
}

// Close releases descriptors only. The state directory (including caller data)
// is retained on success and failure; teardown requires separate ownership.
func (f *LocationFiles) Close() error {
	if f == nil {
		return nil
	}
	var result error
	if f.profile != nil {
		if f.profile.Close() != nil {
			result = ErrLocationFiles
		}
		f.profile = nil
	}
	for _, pin := range []*directoryPin{f.profileParent, f.work, f.evidence, f.stateParent, f.state} {
		if pin != nil && pin.file != nil {
			if pin.file.Close() != nil {
				result = ErrLocationFiles
			}
			pin.file = nil
		}
	}
	return result
}
