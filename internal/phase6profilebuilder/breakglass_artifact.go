package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidBreakGlassArtifact = errors.New("invalid Phase 6 Slice 6 break-glass executable artifact")

// LoadSlice6BreakGlassExecutableArtifact independently rebuilds the finite
// operator from the same clean source already admitted by ImageSupply. The
// operator binary is outside the carrier layer and outside the source tree.
func LoadSlice6BreakGlassExecutableArtifact(ctx context.Context, images ImageSupply, binaryPath string) (phase6security.Slice6BreakGlassExecutableArtifact, error) {
	if ctx == nil || ctx.Err() != nil || images.Platform != "linux/arm64/v8" ||
		!cleanAbsolute(binaryPath) || !outsideSource(images.sourceRoot, binaryPath) ||
		!cleanAbsolute(images.sourceRoot) {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	sourceInputs, err := phase6rolecandidate.CollectSourceInputs(ctx, images.sourceRoot,
		"break-glass-controller", images.Platform)
	if err != nil || sourceInputs.SourceRevision != images.RuntimeRevision ||
		sourceInputs.SourceTreeDigest != images.RuntimeTreeDigest {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	version, err := exec.CommandContext(ctx, "go", "env", "GOVERSION").Output()
	if err != nil || string(bytes.TrimSpace(version)) != "go1.26.8" {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	source, size, err := readSlice6OperatorBinary(binaryPath)
	if err != nil {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, err
	}
	defer clear(source)
	rebuildDir, err := os.MkdirTemp("", "phase6-break-glass-rebuild-")
	if err != nil {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	defer os.RemoveAll(rebuildDir)
	rebuiltPath := filepath.Join(rebuildDir, "phase6-break-glass-operator")
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", rebuiltPath, "./cmd/phase6-break-glass-operator")
	command.Dir = images.sourceRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64",
		"GOTOOLCHAIN=local", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
	if _, err := command.CombinedOutput(); err != nil {
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	rebuilt, err := os.ReadFile(rebuiltPath)
	if err != nil || !bytes.Equal(source, rebuilt) {
		clear(rebuilt)
		return phase6security.Slice6BreakGlassExecutableArtifact{}, ErrInvalidBreakGlassArtifact
	}
	clear(rebuilt)
	digest := sha256.Sum256(source)
	artifact := phase6security.Slice6BreakGlassExecutableArtifact{ID: "break-glass-operator",
		SourceRevision: images.RuntimeRevision, SourceTreeDigest: images.RuntimeTreeDigest,
		Toolchain: "go1.26.8", ToolchainDigest: sourceInputs.ToolchainDigest,
		BuildTarget:     "./cmd/phase6-break-glass-operator",
		BuildParameters: phase6security.Slice6BreakGlassBuildParameters, Platform: "linux/arm64/v8",
		BinaryDigest: "sha256:" + hex.EncodeToString(digest[:]), BinaryBytes: size,
		ContainerPath:                 "/phase6-break-glass-operator",
		CarrierReference:              "docker.io/library/alpine@" + phase6security.Slice6BreakGlassCarrierIndexDigest,
		CarrierIndexDigest:            phase6security.Slice6BreakGlassCarrierIndexDigest,
		CarrierSelectedManifestDigest: phase6security.Slice6BreakGlassCarrierManifestDigest,
		CarrierConfigDigest:           phase6security.Slice6BreakGlassCarrierConfigDigest,
		CarrierPlatform:               "linux/arm64/v8"}
	return artifact, nil
}

func readSlice6OperatorBinary(path string) ([]byte, int64, error) {
	if !cleanAbsolute(path) || !privateFileParent(path) {
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	parent, parentErr := os.Lstat(filepath.Dir(path))
	before, err := os.Lstat(path)
	if parentErr != nil || !slice6OwnedByCurrentUser(parent) || err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o555 ||
		before.Size() < 1 || before.Size() > 32<<20 || !slice6OwnedByCurrentUser(before) {
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	content := make([]byte, before.Size())
	count, err := io.ReadFull(file, content)
	after, afterErr := os.Lstat(path)
	parentAfter, parentAfterErr := os.Lstat(filepath.Dir(path))
	if err != nil || int64(count) != before.Size() || afterErr != nil || parentAfterErr != nil ||
		!os.SameFile(opened, after) || !os.SameFile(parent, parentAfter) ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		clear(content)
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	image, err := elf.NewFile(bytes.NewReader(content))
	if err != nil || image.Class != elf.ELFCLASS64 || image.Machine != elf.EM_AARCH64 || image.Type != elf.ET_EXEC {
		clear(content)
		return nil, 0, ErrInvalidBreakGlassArtifact
	}
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			clear(content)
			return nil, 0, ErrInvalidBreakGlassArtifact
		}
	}
	return content, before.Size(), nil
}

func verifySlice6OperatorBinarySource(path string, artifact phase6security.Slice6BreakGlassExecutableArtifact) error {
	content, size, err := readSlice6OperatorBinary(path)
	if err != nil {
		return ErrInvalidBreakGlassArtifact
	}
	defer clear(content)
	digest := sha256.Sum256(content)
	if size != artifact.BinaryBytes || "sha256:"+hex.EncodeToString(digest[:]) != artifact.BinaryDigest {
		return ErrInvalidBreakGlassArtifact
	}
	return nil
}
