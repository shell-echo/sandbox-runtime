package phase6rolecandidate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const controlArchiveBytes int64 = 64 << 20
const controlWorkspaceBytes int64 = 512 << 20

var ErrInvalidControlCandidate = errors.New("invalid held Control source candidate")

// ControlCandidateInput contains public, non-release planning inputs only.
// A key file establishes byte correspondence, never its approval or origin.
type ControlCandidateInput struct {
	SourceRoot string `json:"source_root"`
	Profile    string `json:"profile"`
	PublicKey  string `json:"public_key"`
	Archive    string `json:"archive"`
}

// ControlSourceCandidateReview cannot be used as an ordinary Manifest/source
// proof, signature credential, Store permit or ImageSupply admission input.
type ControlSourceCandidateReview struct {
	Admission             string `json:"admission"`
	Classification        string `json:"classification"`
	OperatorKeyOrigin     string `json:"operator_key_origin"`
	ProfileBytesDigest    string `json:"profile_bytes_digest"`
	SourceRevision        string `json:"source_revision"`
	SourceTreeDigest      string `json:"source_tree_digest"`
	Platform              string `json:"platform"`
	BuildTarget           string `json:"build_target"`
	Package               string `json:"package"`
	PublicKeyDigest       string `json:"public_key_digest"`
	ToolchainDigest       string `json:"toolchain_digest"`
	DependencyLockDigest  string `json:"dependency_lock_digest"`
	DockerfileDigest      string `json:"dockerfile_digest"`
	BuildScriptDigest     string `json:"build_script_digest"`
	BuildParametersDigest string `json:"build_parameters_digest"`
	ArchiveDigest         string `json:"archive_digest"`
	ArchiveSize           int64  `json:"archive_size"`
	DescriptorProofDigest string `json:"descriptor_proof_digest"`
	RoleDigest            string `json:"role_digest"`
	LoaderDigest          string `json:"loader_digest"`
	ProbeDigest           string `json:"probe_digest"`
}

// ReviewControlSourceCandidate reopens public originals, then independently
// builds the three fixed trust-target packages. All OCI consumers read one
// private run-owned snapshot, retained until every byte/source recheck ends.
// The operator must supply trusted tool/namespace custody and an external hard
// wall supervisor. Context cannot interrupt every filesystem or OCI syscall.
func ReviewControlSourceCandidate(ctx context.Context, input ControlCandidateInput) (out ControlSourceCandidateReview, err error) {
	fail := ErrInvalidControlCandidate
	stage := "input"
	defer func() {
		if err != nil {
			out = ControlSourceCandidateReview{}
			err = fmt.Errorf("%w: %s", fail, stage)
		}
	}()
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(input.SourceRoot) || filepath.Clean(input.SourceRoot) != input.SourceRoot {
		return out, fail
	}
	root, rootErr := filepath.EvalSymlinks(input.SourceRoot)
	temporaryBase, temporaryErr := filepath.EvalSymlinks(os.TempDir())
	if rootErr != nil || root != input.SourceRoot || temporaryErr != nil || !outsideSource(input.SourceRoot, temporaryBase) {
		return out, fail
	}
	for _, path := range []string{input.Profile, input.PublicKey, input.Archive} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !outsideSource(input.SourceRoot, path) {
			return out, fail
		}
	}
	var opened []*candidateFile
	defer func() {
		for _, file := range opened {
			if file.Close() != nil {
				err = fail
			}
		}
		if err != nil {
			out = ControlSourceCandidateReview{}
		}
	}()
	open := func(path string, maximum int64) (*candidateFile, error) {
		file, e := openCandidateFile(path, maximum)
		if e == nil {
			opened = append(opened, file)
		}
		return file, e
	}
	stage = "profile-original"
	profile, err := open(input.Profile, 4<<20)
	if err != nil {
		return out, fail
	}
	var document bytes.Buffer
	profileDigest, err := profile.copy(ctx, &document)
	if err != nil {
		return out, fail
	}
	stage = "public-key-original"
	public, err := open(input.PublicKey, 32)
	if err != nil {
		return out, fail
	}
	var key bytes.Buffer
	pin, err := public.copy(ctx, &key)
	if err != nil || key.Len() != 32 {
		return out, fail
	}
	stage = "bootstrap-declaration"
	review, err := phase6security.ReviewControlBootstrap(document.Bytes())
	if err != nil || review.Bootstrap.Target != phase6security.ControlTrustTarget ||
		review.Bootstrap.KeyDigest != pin || review.ProfileBytesDigest != profileDigest {
		return out, fail
	}
	var service *phase6security.ControlServiceIdentityV1
	for i := range review.Services {
		if review.Services[i].Principal.Name == "provider-docker-control" && review.Services[i].Launch.Target == phase6security.ControlTrustTarget {
			service = &review.Services[i]
		}
	}
	if service == nil || service.Principal.ImageIdentityKind != phase6security.ImageIdentityOCIIndex {
		return out, fail
	}
	recipe := roleBuildRecipe{"./cmd/provider-docker-control", "control-delivery"}
	ldflags := "-buildid= -X github.com/shell-echo/sandbox-runtime/internal/controlbootstrap.publicKeyPin=" + pin
	collect := func() (SourceInputs, error) {
		return collectSourceInputs(ctx, input.SourceRoot, service.Principal.Name, service.Principal.ImagePlatform,
			phase6security.ControlTrustTarget, recipe, ldflags)
	}
	stage = "clean-source"
	source, err := collect()
	if err != nil || service.Launch.SourceRevision != source.SourceRevision || service.Launch.SourceTreeDigest != source.SourceTreeDigest {
		return out, fail
	}
	stage = "archive-original"
	archive, err := open(input.Archive, controlArchiveBytes)
	if err != nil {
		return out, fail
	}
	stage = "workspace"
	work, err := os.MkdirTemp(temporaryBase, "sandbox-runtime-control-source-")
	if err != nil {
		return out, fail
	}
	identity, statErr := os.Lstat(work)
	defer func() {
		actual, e := os.Lstat(work)
		if statErr != nil || e != nil || !os.SameFile(identity, actual) || !actual.IsDir() || actual.Mode().Perm() != 0o700 {
			err = fail // Preserve an unknown replacement; never remove it.
			return
		}
		if os.RemoveAll(work) != nil {
			err = fail
		}
	}()
	canonicalWork, err := filepath.EvalSymlinks(work)
	if err != nil || statErr != nil {
		return out, fail
	}
	work = canonicalWork
	stage = "storage-space"
	if candidateStorageSpace(ctx, input.SourceRoot, work) != nil {
		return out, fail
	}
	stage = "snapshot-copy"
	snapshotDir := filepath.Join(work, "snapshot")
	buildDir := filepath.Join(work, "build")
	if os.Mkdir(snapshotDir, 0o700) != nil || os.Mkdir(buildDir, 0o700) != nil {
		return out, fail
	}
	snapshotPath := filepath.Join(snapshotDir, "image.oci.tar")
	destination, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return out, fail
	}
	archiveDigest, copyErr := archive.copy(ctx, destination)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return out, fail
	}
	snapshot, err := open(snapshotPath, controlArchiveBytes)
	if err != nil {
		return out, fail
	}
	if digest, e := snapshot.copy(ctx, nil); e != nil || digest != archiveDigest {
		return out, fail
	}
	stage = "snapshot-OCI"
	p := service.Principal
	docs, err := phase6security.ReadOCIArchiveDocuments(snapshotPath, p.ImageIdentityKind, p.ImageDigest, p.ImageSelectedManifestDigest, p.ImageConfigDigest)
	if err != nil || ctx.Err() != nil {
		return out, fail
	}
	stage = "service-image"
	proof, err := phase6security.ReviewControlServiceImage(document.Bytes(), p.Name, snapshotPath, docs)
	if err != nil || ctx.Err() != nil {
		return out, fail
	}
	digests := make([]string, 0, 3)
	for _, binary := range []struct {
		name, pkg, flags, digest string
		read                     func(string, []byte, []byte) ([]byte, error)
	}{
		{"role", recipe.packagePath, ldflags, service.Launch.ExecutableDigest, phase6security.ReadVerifiedOCIArchiveRoleExecutable},
		{"loader", "./cmd/phase6-fd-loader", "-buildid=", service.Launch.LoaderDigest, phase6security.ReadVerifiedOCIArchiveFDLoader},
		{"probe", "./tools/control-process-observe", "-buildid=", service.Launch.ProbeDigest, phase6security.ReadVerifiedOCIArchiveControlProbe},
	} {
		stage = "source-binary-" + binary.name
		original, e := binary.read(snapshotPath, docs.Manifest, docs.Config)
		if e != nil || ctx.Err() != nil || hashBytes(original) != binary.digest {
			return out, fail
		}
		rebuilt, e := rebuildExecutable(ctx, input.SourceRoot, filepath.Join(buildDir, binary.name), source.Platform, binary.pkg, binary.flags)
		if e != nil || !bytes.Equal(original, rebuilt) {
			return out, fail
		}
		digests = append(digests, hashBytes(rebuilt))
	}
	stage = "source-reopen"
	again, err := collect()
	if err != nil || again != source {
		return out, fail
	}
	stage = "originals-reopen"
	for _, item := range []struct {
		file   *candidateFile
		digest string
	}{{profile, profileDigest}, {public, pin}, {archive, archiveDigest}, {snapshot, archiveDigest}} {
		if digest, e := item.file.copy(ctx, nil); e != nil || digest != item.digest {
			return out, fail
		}
	}
	if ctx.Err() != nil {
		return out, fail
	}
	return ControlSourceCandidateReview{
		Admission: "held-not-a-permit", Classification: "offline-byte-correspondence-only", OperatorKeyOrigin: "not-verified",
		ProfileBytesDigest: profileDigest, SourceRevision: source.SourceRevision, SourceTreeDigest: source.SourceTreeDigest,
		Platform: source.Platform, BuildTarget: source.BuildTarget, Package: recipe.packagePath, PublicKeyDigest: pin,
		ToolchainDigest: source.ToolchainDigest, DependencyLockDigest: source.DependencyLockDigest,
		DockerfileDigest: source.DockerfileDigest, BuildScriptDigest: source.BuildScriptDigest, BuildParametersDigest: source.BuildParametersDigest,
		ArchiveDigest: archiveDigest, ArchiveSize: archive.size(), DescriptorProofDigest: proof.ProofDigest,
		RoleDigest: digests[0], LoaderDigest: digests[1], ProbeDigest: digests[2],
	}, nil
}

func candidateStorageSpace(ctx context.Context, sourceRoot, privateRoot string) error {
	command := exec.CommandContext(ctx, "go", "env", "-json", "GOCACHE", "GOMODCACHE", "GOTMPDIR")
	command.Env = offlineGoEnvironment()
	raw, err := command.Output()
	var paths map[string]string
	if err != nil || json.Unmarshal(raw, &paths) != nil || len(paths) != 3 {
		return ErrInvalidControlCandidate
	}
	paths["TMPDIR"], paths["workspace"] = os.TempDir(), privateRoot
	for key, path := range paths {
		if key == "GOTMPDIR" && path == "" {
			continue
		}
		var selectorErr error
		path, selectorErr = candidateDirectorySelector(path)
		if selectorErr != nil {
			return ErrInvalidControlCandidate
		}
		var missing []string
		for {
			if _, err := os.Stat(path); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) || filepath.Dir(path) == path {
				return ErrInvalidControlCandidate
			}
			missing = append(missing, filepath.Base(path))
			path = filepath.Dir(path)
		}
		realParent, err := filepath.EvalSymlinks(path)
		if err != nil {
			return ErrInvalidControlCandidate
		}
		realPath := realParent
		for i := len(missing) - 1; i >= 0; i-- {
			realPath = filepath.Join(realPath, missing[i])
		}
		if !outsideSource(sourceRoot, realPath) || key != "workspace" &&
			(realPath == privateRoot || strings.HasPrefix(realPath, privateRoot+string(filepath.Separator))) {
			return ErrInvalidControlCandidate
		}
		if ctx.Err() != nil || candidateSpace(realParent) != nil {
			return ErrInvalidControlCandidate
		}
	}
	return nil
}

// Directory selectors may carry the standard TMPDIR trailing separator.
// Never lexically clean interior dots/aliases before physical resolution.
func candidateDirectorySelector(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrInvalidControlCandidate
	}
	trimmed := strings.TrimRight(path, string(filepath.Separator))
	if trimmed == "" {
		trimmed = string(filepath.Separator)
	}
	if filepath.Clean(trimmed) != trimmed {
		return "", ErrInvalidControlCandidate
	}
	return trimmed, nil
}

func candidateSpaceAvailable(blocks uint64, blockSize int64) bool {
	if blockSize <= 0 {
		return false
	}
	required := uint64(controlWorkspaceBytes) / uint64(blockSize)
	if uint64(controlWorkspaceBytes)%uint64(blockSize) != 0 {
		required++
	}
	return blocks >= required
}
