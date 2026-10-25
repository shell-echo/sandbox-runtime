package phase6rolecandidate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

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
	recipe, err := recipeForTarget(inputs.BuildTarget)
	if err != nil {
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
	rebuilt, err := rebuildExecutable(ctx, sourceRoot, outputPath, inputs.Platform, recipe.packagePath, "-buildid=")
	if err != nil || !bytes.Equal(rebuilt, imageBinary) {
		return BuildContextProof{}, ErrInvalidBuildContext
	}
	binaryDigest := hashBytes(rebuilt)
	loaderDigest := ""
	loaderContext := ""
	if recipe.stage == "fd-loader" {
		imageLoader, err := phase6security.ReadVerifiedOCIArchiveFDLoader(archivePath, manifestDocument, configDocument)
		if err != nil || len(imageLoader) == 0 || len(imageLoader) > maxPhase6RoleBinaryBytes {
			return BuildContextProof{}, ErrInvalidBuildContext
		}
		loaderPath := filepath.Join(workdir, "loader")
		rebuiltLoader, err := rebuildExecutable(ctx, sourceRoot, loaderPath, inputs.Platform, "./cmd/phase6-fd-loader", "-buildid=")
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
