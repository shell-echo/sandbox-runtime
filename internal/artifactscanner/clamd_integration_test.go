//go:build integration

package artifactscanner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const clamdCandidateImage = "clamav/clamav@sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3"

// This opt-in local diagnostic builds the actual adapter into one Linux probe
// in the pinned ClamAV container. The image-embedded rules are old: even a
// passing benign/EICAR result is neither a freshness nor a release gate.
func TestClamdPinnedImageUnixIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_ARTIFACT_SCANNER_CLAMD_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_ARTIFACT_SCANNER_CLAMD_INTEGRATION=1 after review")
	}
	root, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		root = home
	}
	probeDirectory, err := os.MkdirTemp(root, "sr-clamd-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(probeDirectory); err != nil {
			t.Errorf("remove exact non-secret probe directory: %v", err)
		}
	})
	// The only host mount contains a test binary, no credentials or writable
	// socket. UID 1000 must be able to traverse it inside Docker Desktop.
	if err := os.Chmod(probeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	imageArchitecture := inspectCandidateArchitecture(t)
	probePath := filepath.Join(probeDirectory, "probe")
	build, stopBuild := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopBuild()
	buildCommand := exec.CommandContext(build, "go", "build", "-tags=integration", "-trimpath", "-buildvcs=true",
		"-o", probePath, "./internal/artifactscanner/testprobe")
	buildCommand.Dir = repositoryRoot
	buildCommand.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+imageArchitecture, "CGO_ENABLED=0")
	buildOutput, buildErr := buildCommand.CombinedOutput()
	if buildErr != nil {
		t.Fatalf("build source-bound Linux probe: %v (%s)", buildErr, boundedText(string(buildOutput), 2048))
	}
	if err := os.Chmod(probePath, 0o755); err != nil {
		t.Fatal(err)
	}
	probeDigest, err := fileDigest(probePath)
	if err != nil {
		t.Fatal(err)
	}
	buildInfo, err := buildinfo.ReadFile(probePath)
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := scannerSourceDigest(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	head, err := exec.Command("git", "-C", repositoryRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	status, err := exec.Command("git", "-C", repositoryRoot, "status", "--porcelain").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("probe build: go=%s binary_go=%s GOOS=linux GOARCH=%s CGO_ENABLED=0 tags=integration trimpath buildvcs=true head=%s dirty=%t source_subset=%s binary=%s image=%s",
		runtime.Version(), buildInfo.GoVersion, imageArchitecture, strings.TrimSpace(string(head)), len(status) != 0,
		sourceDigest, probeDigest, clamdCandidateImage)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	owner := hex.EncodeToString(nonce[:])
	name := "sr-clamd-it-" + owner
	containerID := ""
	t.Cleanup(func() { cleanupClamdContainer(t, name, owner, containerID) })
	startup, stopStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopStartup()
	startOutput, err := boundedDockerCommand(startup, 2048, "run", "--pull=never", "-d", "--name", name,
		"--label", "sandbox-runtime.test-owner="+owner,
		"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "4g", "--cpus", "2", "--pids-limit", "64", "--user", "1000:1000",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700",
		"--tmpfs", "/run/sandbox:rw,nosuid,nodev,noexec,size=32m,uid=1000,gid=1000,mode=0700",
		"-v", probeDirectory+":/run/probe:ro", "--entrypoint", "/run/probe/probe", clamdCandidateImage)
	if err != nil {
		t.Fatalf("start exact pinned single-container probe: %v (%s)", err, startOutput)
	}
	containerID = strings.TrimSpace(startOutput)
	if len(containerID) != 64 || !hexOnly(containerID) {
		t.Fatalf("Docker returned invalid container identity: %q", boundedText(containerID, 100))
	}
	wait, stopWait := context.WithTimeout(context.Background(), 80*time.Second)
	defer stopWait()
	waitOutput, waitErr := boundedDockerCommand(wait, 1024, "wait", containerID)
	state, stateErr := inspectClamdContainer(containerID)
	logs, logsErr := clamdContainerLogs(containerID)
	if waitErr != nil || stateErr != nil || logsErr != nil ||
		strings.TrimSpace(waitOutput) != "0" || state.Running || state.ExitCode != 0 || state.OOMKilled {
		t.Fatalf("single-container probe failed: wait=%q/%v state=%+v/%v logs=%q/%v",
			waitOutput, waitErr, state, stateErr, logs, logsErr)
	}
	var result struct {
		Protocol     string            `json:"protocol"`
		UID          int               `json:"uid"`
		GID          int               `json:"gid"`
		ConfigDigest string            `json:"config_digest"`
		RuleDigests  map[string]string `json:"rule_digests"`
		Benign       string            `json:"benign"`
		EICAR        string            `json:"eicar"`
	}
	if json.Unmarshal([]byte(logs), &result) != nil || result.Protocol != "sandbox-runtime.clamd-adapter-probe.v1" ||
		result.UID != 1000 || result.GID != 1000 || result.Benign != "clean" || result.EICAR != "infected" ||
		len(result.RuleDigests) != 3 || !scanDigestPattern.MatchString(result.ConfigDigest) {
		t.Fatalf("probe result is incomplete or invalid: %q", logs)
	}
	for _, digest := range result.RuleDigests {
		if !scanDigestPattern.MatchString(digest) {
			t.Fatalf("invalid rule digest in probe result")
		}
	}
	t.Logf("real adapter result: benign=%s EICAR=%s config=%s rules=%v (stale image rules; no readiness claim)",
		result.Benign, result.EICAR, result.ConfigDigest, result.RuleDigests)
}

func inspectCandidateArchitecture(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := boundedDockerCommand(ctx, 4096, "image", "inspect", "--format", "{{.Architecture}}|{{.Os}}|{{json .RepoDigests}}", clamdCandidateImage)
	fields := strings.Split(strings.TrimSpace(output), "|")
	if err != nil || len(fields) != 3 || fields[1] != "linux" ||
		(fields[0] != "arm64" && fields[0] != "amd64") || !strings.Contains(fields[2], clamdCandidateImage) {
		t.Fatalf("exact local scanner image/platform unavailable: %v (%s)", err, output)
	}
	return fields[0]
}

type clamdContainerState struct {
	Running   bool   `json:"Running"`
	ExitCode  int    `json:"ExitCode"`
	OOMKilled bool   `json:"OOMKilled"`
	Error     string `json:"Error"`
}

func inspectClamdContainer(identity string) (clamdContainerState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := boundedDockerCommand(ctx, 4096, "inspect", "--format", "{{json .State}}", identity)
	if err != nil {
		return clamdContainerState{}, err
	}
	var state clamdContainerState
	if json.Unmarshal([]byte(output), &state) != nil {
		return clamdContainerState{}, errors.New("invalid bounded Docker state")
	}
	return state, nil
}

func clamdContainerLogs(identity string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return boundedDockerCommand(ctx, 2048, "logs", "--tail", "20", identity)
}

func cleanupClamdContainer(t *testing.T, name, owner, expectedID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	identity, inspectErr := boundedDockerCommand(ctx, 512, "inspect", "--format",
		"{{.Id}}|{{index .Config.Labels \"sandbox-runtime.test-owner\"}}", name)
	if inspectErr == nil {
		parts := strings.Split(strings.TrimSpace(identity), "|")
		if len(parts) != 2 || parts[1] != owner || expectedID != "" && parts[0] != expectedID {
			t.Errorf("refuse cleanup of unowned scanner container: %q", boundedText(identity, 128))
			return
		}
		if output, err := boundedDockerCommand(ctx, 512, "rm", "-f", name); err != nil {
			t.Errorf("remove exact scanner container: %v (%s)", err, output)
			return
		}
	}
	// A successful Docker enumeration, rather than a failed inspect alone,
	// proves absence; a daemon outage is cleanup-unknown, never success.
	objects, err := boundedDockerCommand(ctx, 512, "ps", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil || strings.TrimSpace(objects) != "" {
		t.Errorf("scanner cleanup absence unproved: objects=%q err=%v prior_inspect=%v", objects, err, inspectErr)
	}
}

func boundedDockerCommand(ctx context.Context, limit int, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output := &boundedOutput{limit: limit}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if output.Overflow() {
		return output.String(), errors.New("Docker output exceeded bound")
	}
	return output.String(), err
}

type boundedOutput struct {
	mu       sync.Mutex
	limit    int
	content  []byte
	overflow bool
}

func (b *boundedOutput) Write(content []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := len(content)
	if len(b.content)+count > b.limit {
		b.overflow = true
	}
	if len(b.content) < b.limit {
		b.content = append(b.content, content[:min(count, b.limit-len(b.content))]...)
	}
	return count, nil
}

func (b *boundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.content))
}

func (b *boundedOutput) Overflow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

func scannerSourceDigest(root string) (string, error) {
	hash := sha256.New()
	for _, name := range []string{"go.mod", "go.sum", "internal/artifactscanner/clamd.go",
		"internal/artifactscanner/clamd_integration_test.go", "internal/artifactscanner/testprobe/main.go",
		"internal/restrictedunix/socket.go", "provider/artifact/model.go"} {
		file, err := os.Open(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, name+"\x00")
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return "", errors.Join(copyErr, closeErr)
		}
		_, _ = io.WriteString(hash, "\x00")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func hexOnly(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
