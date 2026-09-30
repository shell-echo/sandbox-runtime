// Package phase6rolecandidate collects independently reproducible inputs for
// repository-local Phase 6 role images. It does not itself publish an image or
// qualify a running deployment.
package phase6rolecandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const baseImageDigest = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"

var ErrInvalidSourceInputs = errors.New("invalid Phase 6 local role source inputs")

// SourceInputs binds a reviewed deployment to the exact clean source tree and
// local builder inputs. BuildContextDigest is established later by comparing
// the independently rebuilt binary to the image's extracted executable.
type SourceInputs struct {
	Deployment            string `json:"deployment"`
	BuildTarget           string `json:"build_target"`
	Platform              string `json:"platform"`
	SourceRevision        string `json:"source_revision"`
	SourceTreeDigest      string `json:"source_tree_digest"`
	DockerfileDigest      string `json:"dockerfile_digest"`
	BuildScriptDigest     string `json:"build_script_digest"`
	ToolchainDigest       string `json:"toolchain_digest"`
	BaseImageDigest       string `json:"base_image_digest"`
	DependencyLockDigest  string `json:"dependency_lock_digest"`
	BuildParametersDigest string `json:"build_parameters_digest"`
}

// VerifySource re-derives every field from the exact clean checkout and active
// Go installation. A stored digest map is never accepted by shape alone.
func (s SourceInputs) VerifySource(ctx context.Context, sourceRoot string) error {
	observed, err := CollectSourceInputs(ctx, sourceRoot, s.Deployment, s.Platform)
	if err != nil || observed != s {
		return ErrInvalidSourceInputs
	}
	return nil
}

func CollectSourceInputs(ctx context.Context, sourceRoot, deployment, platform string) (SourceInputs, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(sourceRoot) || filepath.Clean(sourceRoot) != sourceRoot ||
		sourceRoot == string(filepath.Separator) || (platform != "linux/amd64" && platform != "linux/arm64/v8") {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	target, err := phase6security.Slice6DesiredImageTarget(deployment)
	if err != nil || target == phase6security.Slice6BrowserPublishedImage ||
		target == phase6security.Slice6DesktopCandidateImage {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	info, err := os.Lstat(sourceRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	status, err := gitOutput(ctx, sourceRoot, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	revision, err := gitOutput(ctx, sourceRoot, "rev-parse", "HEAD")
	if err != nil || len(revision) != 40 || !lowerHex(revision) {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	tree, err := desktopcandidate.SourceTreeDigest(sourceRoot)
	if err != nil {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	committedTree, err := desktopcandidate.SourceTreeDigestAtRevision(sourceRoot, revision)
	if err != nil || committedTree != tree {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	dockerfilePath := filepath.Join(sourceRoot, "profiles", "phase6", "local-role", "Dockerfile")
	buildScriptPath := filepath.Join(sourceRoot, "profiles", "phase6", "local-role", "build.sh")
	dockerfile, err := privateSourceFile(dockerfilePath)
	if err != nil || !strings.HasPrefix(string(dockerfile), "FROM alpine@"+baseImageDigest+" AS role-base\n") {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	script, err := privateSourceFile(buildScriptPath)
	if err != nil || len(script) == 0 {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	goMod, err := privateSourceFile(filepath.Join(sourceRoot, "go.mod"))
	if err != nil {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	goSum, err := privateSourceFile(filepath.Join(sourceRoot, "go.sum"))
	if err != nil {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	toolchain, err := exactToolchainDigest(ctx)
	if err != nil {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	parameters := struct {
		Target    string `json:"target"`
		Stage     string `json:"stage"`
		Platform  string `json:"platform"`
		BuildMode string `json:"build_mode"`
		GoFlags   string `json:"go_flags"`
		Docker    string `json:"docker"`
	}{Target: target, Stage: "direct", Platform: platform, BuildMode: "CGO_ENABLED=0 GOOS=linux GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local",
		GoFlags: "-mod=readonly -trimpath -buildvcs=false -ldflags=-buildid=",
		Docker:  "--no-cache --network none --provenance=false --pull=false SOURCE_DATE_EPOCH=0"}
	if _, needsLoader := phase6fdloader.SpecificationFor(target); needsLoader {
		parameters.Stage = "fd-loader"
	}
	parameterBytes, err := json.Marshal(parameters)
	if err != nil {
		return SourceInputs{}, ErrInvalidSourceInputs
	}
	return SourceInputs{Deployment: deployment, BuildTarget: target, Platform: platform,
		SourceRevision: revision, SourceTreeDigest: tree,
		DockerfileDigest: hashBytes(dockerfile), BuildScriptDigest: hashBytes(script),
		ToolchainDigest: toolchain, BaseImageDigest: baseImageDigest,
		DependencyLockDigest:  hashFields("sandbox-runtime/phase6-role-dependency-lock/v1", goMod, goSum),
		BuildParametersDigest: hashFields("sandbox-runtime/phase6-role-build-parameters/v1", parameterBytes)}, nil
}

func gitOutput(ctx context.Context, root string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = root
	document, err := command.Output()
	return strings.TrimSpace(string(document)), err
}

func privateSourceFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 8<<20 {
		return nil, ErrInvalidSourceInputs
	}
	document, err := os.ReadFile(path)
	if err != nil || int64(len(document)) != info.Size() {
		return nil, ErrInvalidSourceInputs
	}
	return document, nil
}

func exactToolchainDigest(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOVERSION", "GOROOT")
	document, err := command.Output()
	fields := strings.Split(strings.TrimSpace(string(document)), "\n")
	if err != nil || len(fields) != 2 || fields[0] != "go1.26.8" || !filepath.IsAbs(fields[1]) {
		return "", ErrInvalidSourceInputs
	}
	root := fields[1]
	toolDir := filepath.Join(root, "pkg", "tool", runtime.GOOS+"_"+runtime.GOARCH)
	files := []string{filepath.Join(root, "bin", "go"), filepath.Join(toolDir, "compile"), filepath.Join(toolDir, "link")}
	parts := make([][]byte, 0, len(files)+1)
	parts = append(parts, []byte(fields[0]))
	for _, path := range files {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 128<<20 {
			return "", ErrInvalidSourceInputs
		}
		file, err := os.Open(path)
		if err != nil {
			return "", ErrInvalidSourceInputs
		}
		hash := sha256.New()
		count, copyErr := io.Copy(hash, io.LimitReader(file, 128<<20+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || count != info.Size() {
			return "", ErrInvalidSourceInputs
		}
		parts = append(parts, []byte("sha256:"+hex.EncodeToString(hash.Sum(nil))))
	}
	stdlibDigest, err := digestToolchainSource(ctx, filepath.Join(root, "src"))
	if err != nil {
		return "", ErrInvalidSourceInputs
	}
	parts = append(parts, []byte(stdlibDigest))
	return hashFields("sandbox-runtime/phase6-role-toolchain/v1", parts...), nil
}

func digestToolchainSource(ctx context.Context, root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidSourceInputs
	}
	var parts [][]byte
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil || entry == nil {
			return ErrInvalidSourceInputs
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrInvalidSourceInputs
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(parts) >= 300000 {
			return ErrInvalidSourceInputs
		}
		info, err := entry.Info()
		if err != nil || info.Size() < 0 || info.Size() > 16<<20 || total+info.Size() > 1<<30 {
			return ErrInvalidSourceInputs
		}
		total += info.Size()
		contents, err := os.ReadFile(path)
		if err != nil || int64(len(contents)) != info.Size() {
			return ErrInvalidSourceInputs
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "" || filepath.IsAbs(relative) || strings.HasPrefix(relative, "..") {
			return ErrInvalidSourceInputs
		}
		parts = append(parts, []byte(filepath.ToSlash(relative)),
			[]byte{byte(info.Mode().Perm() >> 8), byte(info.Mode().Perm())},
			[]byte(hashBytes(contents)))
		return nil
	})
	if err != nil || len(parts) == 0 {
		return "", ErrInvalidSourceInputs
	}
	return hashFields("sandbox-runtime/phase6-role-stdlib-source/v1", parts...), nil
}

func hashBytes(value []byte) string {
	hash := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func hashFields(domain string, values ...[]byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain + "\x00"))
	for _, value := range values {
		length := uint64(len(value))
		_, _ = hash.Write([]byte{byte(length >> 56), byte(length >> 48), byte(length >> 40), byte(length >> 32),
			byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
		_, _ = hash.Write(value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func lowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
