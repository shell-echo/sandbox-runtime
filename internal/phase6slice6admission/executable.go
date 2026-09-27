package phase6slice6admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"
)

const maxSlice6VerifierBytes = 64 << 20

var replaceDirective = regexp.MustCompile(`(?m)^\s*replace(?:\s|\()`) // local module replacement is not part of E.

// VerifyExecutable binds the final CLI's *actual* executable to the clean E
// source by an independent, deterministic byte-for-byte rebuild. It is for
// the final command, not for arbitrary gate/test binaries. It proves only
// reproducibility on this trusted host/toolchain, not a signature or origin.
func VerifyExecutable(ctx context.Context, sourceRoot, revision, treeDigest string) error {
	actual, err := os.Executable()
	if err != nil {
		return ErrInvalidAdmission
	}
	return verifyBinary(ctx, sourceRoot, revision, treeDigest, actual)
}

func verifyBinary(ctx context.Context, sourceRoot, revision, treeDigest, actualPath string) (result error) {
	if ctx == nil || ctx.Err() != nil || !absolutePath(sourceRoot) || !absolutePath(actualPath) ||
		runtime.Version() != "go1.26.8" || verifySource(ctx, sourceRoot, revision, treeDigest) != nil ||
		verifyModuleLock(sourceRoot) != nil {
		return ErrInvalidAdmission
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.GoVersion != "go1.26.8" {
		return ErrInvalidAdmission
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	goInfo, err := os.Lstat(goBinary)
	if err != nil || !goInfo.Mode().IsRegular() || goInfo.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidAdmission
	}
	environment, err := fixedBuildEnvironment()
	if err != nil {
		return ErrInvalidAdmission
	}
	buildContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	version := exec.CommandContext(buildContext, goBinary, "env", "GOVERSION", "GOROOT", "GOOS", "GOARCH")
	version.Env = environment
	version.Dir = sourceRoot
	versionOutput, err := version.Output()
	if err != nil || len(versionOutput) > 1024 ||
		string(versionOutput) != "go1.26.8\n"+runtime.GOROOT()+"\n"+runtime.GOOS+"\n"+runtime.GOARCH+"\n" {
		return ErrInvalidAdmission
	}
	temporary, err := os.MkdirTemp("", "sr-phase6-evidence-verifier-*")
	if err != nil {
		return ErrInvalidAdmission
	}
	defer func() {
		if os.RemoveAll(temporary) != nil {
			result = ErrInvalidAdmission
		}
	}()
	builtPath := filepath.Join(temporary, "verifier")
	build := exec.CommandContext(buildContext, goBinary, "build", "-mod=readonly", "-trimpath",
		"-buildvcs=false", "-ldflags=-buildid=", "-o", builtPath,
		"./cmd/verify-product-phase6-slice6-evidence")
	build.Env = environment
	build.Dir = sourceRoot
	if build.Run() != nil || buildContext.Err() != nil ||
		verifySource(buildContext, sourceRoot, revision, treeDigest) != nil ||
		verifyModuleLock(sourceRoot) != nil {
		return ErrInvalidAdmission
	}
	actual, err := stableExecutableDigest(actualPath)
	if err != nil {
		return ErrInvalidAdmission
	}
	built, err := stableExecutableDigest(builtPath)
	if err != nil || actual != built {
		return ErrInvalidAdmission
	}
	return nil
}

func verifyModuleLock(sourceRoot string) error {
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(sourceRoot, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			(name == "go.mod" && info.Size() < 1) || info.Size() > 8<<20 {
			return ErrInvalidAdmission
		}
	}
	module, err := os.ReadFile(filepath.Join(sourceRoot, "go.mod"))
	if err != nil || replaceDirective.Match(module) {
		return ErrInvalidAdmission
	}
	return nil
}

func fixedBuildEnvironment() ([]string, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" ||
		runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		return nil, ErrInvalidAdmission
	}
	home, err := os.UserHomeDir()
	if err != nil || !absolutePath(home) {
		return nil, ErrInvalidAdmission
	}
	cache, err := os.UserCacheDir()
	if err != nil || !absolutePath(cache) {
		return nil, ErrInvalidAdmission
	}
	environment := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "GOCACHE=" + filepath.Join(cache, "go-build"),
		"GOMODCACHE=" + filepath.Join(home, "go", "pkg", "mod"), "GOENV=off", "GOWORK=off",
		"GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off",
		"CGO_ENABLED=0", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}
	if runtime.GOARCH == "arm64" {
		environment = append(environment, "GOARM64=v8.0")
	} else {
		environment = append(environment, "GOAMD64=v1")
	}
	return environment, nil
}

func stableExecutableDigest(path string) (string, error) {
	if !absolutePath(path) {
		return "", ErrInvalidAdmission
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() < 1 || before.Size() > maxSlice6VerifierBytes {
		return "", ErrInvalidAdmission
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrInvalidAdmission
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", ErrInvalidAdmission
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxSlice6VerifierBytes+1))
	after, afterErr := file.Stat()
	if err != nil || afterErr != nil || n != before.Size() || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", ErrInvalidAdmission
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
