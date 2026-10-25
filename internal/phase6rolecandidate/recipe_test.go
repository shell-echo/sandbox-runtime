package phase6rolecandidate

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestRecipesMatchReviewedTargetsAndBuildScript(t *testing.T) {
	wanted := map[string]roleBuildRecipe{
		"core":                              {".", "direct"},
		"browser-action-ingress":            {"./cmd/browser-action-ingress", "direct"},
		"browser-executor-backend":          {"./cmd/browser-executor-backend", "direct"},
		"desktop-executor-backend":          {"./cmd/desktop-executor-backend", "direct"},
		"certificate-controller":            {"./cmd/certificate-controller", "fd-loader"},
		"workload-tls-agent":                {"./cmd/workload-tls-agent", "fd-loader"},
		"workload-material-agent":           {"./cmd/workload-material-agent", "fd-loader"},
		"workload-credential-controller-v2": {"./cmd/workload-credential-controller-v2", "fd-loader"},
		"break-glass-controller":            {"./cmd/break-glass-controller", "fd-loader"},
		"egress-policy-broker":              {"./cmd/egress-policy-broker", "direct"},
		"egress-policy-state-authority":     {"./cmd/egress-policy-state-authority", "fd-loader"},
		"phase6-ingress-relay":              {"./cmd/phase6-ingress-relay", "direct"},
	}
	targets := phase6security.Slice6DesiredLocalRoleTargets()
	if len(targets) != len(wanted) {
		t.Fatal("reviewed target inventory changed without complete recipes")
	}
	// Execute only argument validation and package/stage selection. The boundary
	// is before any source, toolchain, build or Docker command in the script.
	selection := scriptSelection(t)
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			recipe, err := recipeForTarget(target)
			if err != nil || recipe != wanted[target] {
				t.Fatalf("recipe for %s = %#v, %v", target, recipe, err)
			}
			_, hasLoader := phase6fdloader.SpecificationFor(target)
			if hasLoader != (recipe.stage == "fd-loader") {
				t.Fatal("loader specification and recipe disagree")
			}
			command := exec.CommandContext(t.Context(), "sh", "-c",
				selection+"\nprintf '%s\\n' \"$package\" \"$stage\"\n", "role-selection", "linux/arm64/v8", target)
			output, err := command.CombinedOutput()
			if err != nil || string(output) != recipe.packagePath+"\n"+recipe.stage+"\n" {
				t.Fatalf("build script recipe differs: %s, %v", output, err)
			}
		})
	}
	for _, target := range []string{"", "unknown", "../core", "core/../../other", "-o=other",
		phase6security.Slice6BrowserPublishedImage, phase6security.Slice6DesktopCandidateImage,
		"provider-artifact-scanner", "provider-docker-control-bootstrap-v1",
		phase6fdloader.ControlDeliveryTarget, phase6fdloader.ControlSourceTarget, phase6fdloader.ControlTrustTarget} {
		if _, err := recipeForTarget(target); err == nil {
			t.Fatalf("incomplete or unknown recipe admitted: %q", target)
		}
	}
}

func poisonGoConfiguration(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"GOTOOLCHAIN": "not-a-toolchain", "GOFLAGS": "-not-a-go-flag",
		"GOENV":        filepath.Join(t.TempDir(), "missing-goenv"),
		"GOWORK":       filepath.Join(t.TempDir(), "missing-workspace"),
		"GOROOT":       filepath.Join(t.TempDir(), "missing-goroot"),
		"GOTOOLDIR":    filepath.Join(t.TempDir(), "missing-tools"),
		"GOCACHEPROG":  filepath.Join(t.TempDir(), "missing-cache-program"),
		"GOEXPERIMENT": "unknown-experiment", "GO111MODULE": "off",
		"GOAMD64": "invalid", "GOARM64": "invalid", "GOFIPS140": "invalid",
		"GOPRIVATE": "*", "GONOPROXY": "*", "GONOSUMDB": "*", "GOAUTH": "invalid",
	} {
		t.Setenv(name, value)
	}
}

func scriptSelection(t *testing.T) string {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "local-role", "build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	selection, _, ok := strings.Cut(string(script), "\nscript_dir=")
	if !ok {
		t.Fatal("build script selection boundary changed")
	}
	return selection
}

func TestNativeHelperGoEnvironmentMatchesBuildScript(t *testing.T) {
	poisonGoConfiguration(t)
	t.Setenv("GOOS", "invalid")
	t.Setenv("GOARCH", "invalid")
	t.Setenv("role_goos", "invalid")
	t.Setenv("role_goarch", "invalid")
	keys := []string{"GOVERSION", "GOROOT", "GOTOOLDIR", "GOOS", "GOARCH", "GO111MODULE", "GOEXPERIMENT",
		"CGO_ENABLED", "GOPROXY", "GOSUMDB", "GONOPROXY", "GONOSUMDB", "GOPRIVATE", "GOFLAGS", "GOWORK", "GOENV", "GOAUTH", "GOVCS"}
	command := exec.CommandContext(t.Context(), "go", append([]string{"env", "-json"}, keys...)...)
	command.Env = offlineGoEnvironment()
	passedEnvironment := map[string]string{}
	for _, entry := range command.Env {
		key, value, _ := strings.Cut(entry, "=")
		passedEnvironment[key] = value
	}
	for key, expected := range map[string]string{"GOENV": "off", "GOMAXPROCS": "2", "GOAMD64": "v1", "GOARM64": "v8.0"} {
		if passedEnvironment[key] != expected {
			t.Fatalf("child receives %s=%q, want %q", key, passedEnvironment[key], expected)
		}
	}
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GOOS", "GOARCH"} {
		if _, exists := passedEnvironment[key]; exists {
			t.Fatalf("native child inherits caller %s", key)
		}
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated native environment: %s, %v", output, err)
	}
	var observed map[string]string
	if err := json.Unmarshal(output, &observed); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{"GOVERSION": "go1.26.8", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH,
		"GO111MODULE": "on", "GOEXPERIMENT": "", "CGO_ENABLED": "0", "GOPROXY": "off", "GOSUMDB": "off",
		// Go1.26.8 EnvFile returns an empty path for raw GOENV=off. MkEnv
		// reports that path, so the observed value differs from the input above.
		"GONOPROXY": "none", "GONOSUMDB": "none", "GOPRIVATE": "", "GOFLAGS": "", "GOWORK": "off", "GOENV": "", "GOAUTH": "off", "GOVCS": "*:off"} {
		if observed[key] != expected {
			t.Fatalf("native helper %s = %q, want %q", key, observed[key], expected)
		}
	}
	if !filepath.IsAbs(observed["GOROOT"]) || observed["GOROOT"] == os.Getenv("GOROOT") || observed["GOTOOLDIR"] == os.Getenv("GOTOOLDIR") {
		t.Fatal("caller toolchain root or tool path accepted")
	}
	// Call only the extracted function, never the script's source checks, pin
	// reading, Docker commands, complete image build or publication.
	command = exec.CommandContext(t.Context(), "sh", "-c", scriptSelection(t)+"\nrole_go env -json "+strings.Join(keys, " "),
		"native-environment", "linux/arm64/v8", "core")
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("script native environment: %s, %v", output, err)
	}
	var shellObserved map[string]string
	if err := json.Unmarshal(output, &shellObserved); err != nil || !reflect.DeepEqual(observed, shellObserved) {
		t.Fatalf("script and verifier environments differ: %v, %v", shellObserved, err)
	}
}

func TestOfflineRebuildIgnoresCallerGoConfiguration(t *testing.T) {
	poisonGoConfiguration(t)
	t.Setenv("CGO_ENABLED", "invalid")
	t.Setenv("GOOS", "invalid")
	t.Setenv("GOARCH", "invalid")
	t.Setenv("GOPROXY", "https://invalid.test")
	t.Setenv("GOSUMDB", "invalid")
	root := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":                       "module example.test/recipe\n\ngo 1.26.8\n",
		"main.go":                      "package main\nfunc main() { println(\"role\") }\n",
		"cmd/phase6-fd-loader/main.go": "package main\nfunc main() { println(\"loader\") }\n",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recipe, err := recipeForTarget("core")
	if err != nil {
		t.Fatal(err)
	}
	var executables [][]byte
	selection := scriptSelection(t)
	for name, packagePath := range map[string]string{"role": recipe.packagePath, "loader": "./cmd/phase6-fd-loader"} {
		executable, err := rebuildExecutable(t.Context(), root, filepath.Join(t.TempDir(), name), "linux/arm64/v8", packagePath)
		if err != nil {
			t.Fatalf("isolated scratch %s build: %v", name, err)
		}
		image, err := elf.NewFile(bytes.NewReader(executable))
		if err != nil || image.Machine != elf.EM_AARCH64 {
			t.Fatalf("scratch %s is not the requested Linux arm64 executable: %v", name, err)
		}
		info, err := buildinfo.Read(bytes.NewReader(executable))
		if err != nil || info.GoVersion != "go1.26.8" {
			t.Fatalf("scratch toolchain: %#v, %v", info, err)
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["CGO_ENABLED"] != "0" || settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" ||
			settings["GOARM64"] != "v8.0" || settings["-trimpath"] != "true" || image.Section(".note.go.buildid") != nil {
			t.Fatalf("scratch build did not retain fixed build settings: %v", settings)
		}
		shellOutput := filepath.Join(t.TempDir(), name)
		command := exec.CommandContext(t.Context(), "sh", "-c", selection+
			"\nrole_go build -p=2 -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o \"$ROLE_TEST_OUTPUT\" \"$ROLE_TEST_PACKAGE\"",
			"scratch-build", "linux/arm64/v8", "core")
		command.Dir = root
		command.Env = append(os.Environ(), "ROLE_TEST_OUTPUT="+shellOutput, "ROLE_TEST_PACKAGE="+packagePath)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("script scratch build: %s, %v", output, err)
		}
		shellExecutable, err := os.ReadFile(shellOutput)
		if err != nil || !bytes.Equal(shellExecutable, executable) {
			t.Fatalf("script and verifier scratch %s bytes differ: %v", name, err)
		}
		executables = append(executables, executable)
	}
	if bytes.Equal(executables[0], executables[1]) {
		t.Fatal("role and loader package selection collapsed")
	}
	for _, ctx := range []context.Context{nil, canceledContext()} {
		if _, err := rebuildExecutable(ctx, root, filepath.Join(t.TempDir(), "rejected"), "linux/arm64/v8", recipe.packagePath); err == nil {
			t.Fatal("invalid context admitted a build")
		}
	}
	if _, err := rebuildExecutable(t.Context(), root, filepath.Join(t.TempDir(), "rejected"), "linux/386", recipe.packagePath); err == nil {
		t.Fatal("unsupported platform admitted a build")
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
