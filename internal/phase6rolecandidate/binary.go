package phase6rolecandidate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidBuildContext = errors.New("invalid Phase 6 local role build context")

// BuildContextProof binds the independently rebuilt source executable to the
// effective regular file in the selected OCI archive's ordered layers.
type BuildContextProof struct {
	BinaryDigest       string
	LoaderBinaryDigest string
	BuildContextDigest string
}

// VerifyBuildContext performs a second hermetic Go build from the clean source
// revision and compares its bytes directly to the verified image executable.
// The caller must additionally retain and verify the archive/index/config
// probe and observe the final running role container in the complete gate.
func VerifyBuildContext(ctx context.Context, sourceRoot string, inputs SourceInputs,
	archivePath string, manifestDocument, configDocument []byte) (BuildContextProof, error) {
	if ctx == nil || ctx.Err() != nil || inputs.VerifySource(ctx, sourceRoot) != nil {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	imageBinary, err := phase6security.ReadVerifiedOCIArchiveRoleExecutable(archivePath, manifestDocument, configDocument)
	if err != nil || len(imageBinary) == 0 || len(imageBinary) > maxPhase6RoleBinaryBytes {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	workdir, err := os.MkdirTemp("", "sandbox-runtime-phase6-role-rebuild-")
	if err != nil {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	defer os.RemoveAll(workdir)
	outputPath := filepath.Join(workdir, "role")
	packagePath := "."
	if inputs.BuildTarget != "core" {
		packagePath = "./cmd/" + inputs.BuildTarget
	}
	architecture := "amd64"
	if inputs.Platform == "linux/arm64/v8" {
		architecture = "arm64"
	}
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", outputPath, packagePath)
	command.Dir = sourceRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture,
		"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=")
	if _, err := command.CombinedOutput(); err != nil {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxPhase6RoleBinaryBytes {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	rebuilt, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(rebuilt, imageBinary) {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	binaryDigest := hashBytes(rebuilt)
	loaderDigest := ""
	loaderContext := ""
	if _, needsLoader := phase6fdloader.SpecificationFor(inputs.BuildTarget); needsLoader {
		imageLoader, err := phase6security.ReadVerifiedOCIArchiveFDLoader(archivePath, manifestDocument, configDocument)
		if err != nil || len(imageLoader) == 0 || len(imageLoader) > maxPhase6RoleBinaryBytes {
			return BuildContextProof{}, ErrInvalidBuildContext
		}
		loaderPath := filepath.Join(workdir, "loader")
		loaderBuild := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
			"-ldflags=-buildid=", "-o", loaderPath, "./cmd/phase6-fd-loader")
		loaderBuild.Dir = sourceRoot
		loaderBuild.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture,
			"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=")
		if _, err := loaderBuild.CombinedOutput(); err != nil {
			return BuildContextProof{}, ErrInvalidBuildContext
		}
		loaderInfo, err := os.Lstat(loaderPath)
		if err != nil || !loaderInfo.Mode().IsRegular() || loaderInfo.Size() < 1 || loaderInfo.Size() > maxPhase6RoleBinaryBytes {
			return BuildContextProof{}, ErrInvalidBuildContext
		}
		rebuiltLoader, err := os.ReadFile(loaderPath)
		if err != nil || !bytes.Equal(rebuiltLoader, imageLoader) {
			return BuildContextProof{}, ErrInvalidBuildContext
		}
		loaderDigest = hashBytes(rebuiltLoader)
		loaderContext = "loader:0555:epoch0"
	}
	return BuildContextProof{BinaryDigest: binaryDigest,
		LoaderBinaryDigest: loaderDigest,
		BuildContextDigest: hashFields("sandbox-runtime/phase6-role-build-context/v2",
			[]byte(binaryDigest), []byte(loaderDigest), []byte(inputs.DockerfileDigest),
			[]byte("role:0555:epoch0"), []byte(loaderContext), []byte("Dockerfile:0644:epoch0"))}, nil
}

const maxPhase6RoleBinaryBytes = 128 << 20
