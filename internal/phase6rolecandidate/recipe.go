package phase6rolecandidate

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// A recipe is deliberately narrower than the FD-loader protocol: a loader
// specification alone does not establish a complete source/image recipe.
// Control still needs its independent public pin and probe, and Scanner its
// engine, dependencies and rules. Neither can inherit an ordinary role build.
type roleBuildRecipe struct {
	packagePath string
	stage       string
}

func recipeForTarget(target string) (roleBuildRecipe, error) {
	switch target {
	case "core":
		return roleBuildRecipe{".", "direct"}, nil
	case "browser-action-ingress":
		return roleBuildRecipe{"./cmd/browser-action-ingress", "direct"}, nil
	case "browser-executor-backend":
		return roleBuildRecipe{"./cmd/browser-executor-backend", "direct"}, nil
	case "desktop-executor-backend":
		return roleBuildRecipe{"./cmd/desktop-executor-backend", "direct"}, nil
	case "certificate-controller":
		return roleBuildRecipe{"./cmd/certificate-controller", "fd-loader"}, nil
	case "workload-tls-agent":
		return roleBuildRecipe{"./cmd/workload-tls-agent", "fd-loader"}, nil
	case "workload-material-agent":
		return roleBuildRecipe{"./cmd/workload-material-agent", "fd-loader"}, nil
	case "workload-credential-controller-v2":
		return roleBuildRecipe{"./cmd/workload-credential-controller-v2", "fd-loader"}, nil
	case "break-glass-controller":
		return roleBuildRecipe{"./cmd/break-glass-controller", "fd-loader"}, nil
	case "egress-policy-broker":
		return roleBuildRecipe{"./cmd/egress-policy-broker", "direct"}, nil
	case "egress-policy-state-authority":
		return roleBuildRecipe{"./cmd/egress-policy-state-authority", "fd-loader"}, nil
	case "phase6-ingress-relay":
		return roleBuildRecipe{"./cmd/phase6-ingress-relay", "direct"}, nil
	default:
		return roleBuildRecipe{}, ErrInvalidSourceInputs
	}
}

// Storage and tool-discovery paths remain explicit caller inputs. This fixes
// compilation semantics, not the provenance of PATH's executable or caches;
// the existing source/toolchain and original executable checks still apply.
const fixedGoEnvironment = "CGO_ENABLED=0 GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS= GOMAXPROCS=2 " +
	"GO111MODULE=on GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 GOPROXY=off GOSUMDB=off " +
	"GOPRIVATE= GONOPROXY=none GONOSUMDB=none GOINSECURE= GOAUTH=off GOVCS=*:off MISE_AUTO_INSTALL=0 LANG=C LC_ALL=C"

const goPathInputs = "PATH HOME TMPDIR GOTMPDIR GOCACHE GOMODCACHE XDG_CACHE_HOME SystemRoot SYSTEMROOT TEMP TMP"

func offlineGoEnvironment() []string {
	var env []string
	for _, key := range strings.Fields(goPathInputs) {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return append(env, strings.Fields(fixedGoEnvironment)...)
}

// packagePath comes only from the closed recipe or the fixed loader package.
func rebuildExecutable(ctx context.Context, sourceRoot, outputPath, platform, packagePath string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidBuildContext
	}
	var architecture string
	switch platform {
	case "linux/amd64":
		architecture = "amd64"
	case "linux/arm64/v8":
		architecture = "arm64"
	default:
		return nil, ErrInvalidBuildContext
	}
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", outputPath, packagePath)
	command.Dir = sourceRoot
	command.Env = append(offlineGoEnvironment(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture)
	if _, err := command.CombinedOutput(); err != nil {
		return nil, ErrInvalidBuildContext
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxPhase6RoleBinaryBytes {
		return nil, ErrInvalidBuildContext
	}
	rebuilt, err := os.ReadFile(outputPath)
	if err != nil || int64(len(rebuilt)) != info.Size() {
		return nil, ErrInvalidBuildContext
	}
	return rebuilt, nil
}
