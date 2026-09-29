//go:build integration

package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// This is a diagnostic comparison, not a release or publication gate. B has
// different policy bytes from the locked Browser publication, so success here
// never silently authorizes a replacement runtime profile or image identity.
func TestBrowserChrootSeccompABDiagnostic(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BROWSER_CHROOT_AB_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_BROWSER_CHROOT_AB_INTEGRATION=1")
	}
	manifest, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	imageRef := LockedPublication().Image()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	inspectImagePolicy(t, ctx, imageRef, manifest)
	policyA, err := os.ReadFile("chromium-seccomp.json")
	if err != nil || digestBrowserPolicy(policyA) != SeccompDigest {
		t.Fatal("locked A policy bytes are unavailable")
	}
	needle := []byte("\n\t\t\t\t\"chroot\",\n")
	if bytes.Count(policyA, needle) != 1 {
		t.Fatal("cannot make a single-variable chroot policy comparison")
	}
	policyB := bytes.Replace(policyA, needle, []byte("\n"), 1)
	if bytes.Equal(policyA, policyB) || bytes.Contains(policyB, []byte("\"chroot\"")) {
		t.Fatal("B policy did not remove exactly the unconditional chroot name")
	}
	policyBPath := filepath.Join(t.TempDir(), "diagnostic-without-unconditional-chroot.json")
	if err := os.WriteFile(policyBPath, policyB, 0o600); err != nil {
		t.Fatal(err)
	}
	policyAPath, err := filepath.Abs("chromium-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("A locked policy %s; B diagnostic policy %s", SeccompDigest, digestBrowserPolicy(policyB))
	for _, variant := range []struct {
		name          string
		path          string
		policy        []byte
		expectFailure bool
	}{{"A-locked", policyAPath, policyA, false}, {"B-no-unconditional-chroot", policyBPath, policyB, true}} {
		t.Run(variant.name, func(t *testing.T) {
			runBrowserChrootVariant(t, ctx, imageRef, variant.path, variant.policy, variant.expectFailure)
		})
	}
}

func runBrowserChrootVariant(t *testing.T, ctx context.Context, imageRef, policyPath string, policy []byte, expectFailure bool) {
	t.Helper()
	name := fmt.Sprintf("sandbox-runtime-browser-chroot-ab-%d", time.Now().UnixNano())
	removed := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !removed {
			if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil &&
				!browserABContainerAbsent(output, err) {
				t.Errorf("A/B Browser cleanup failed: %v: %s", err, output)
			}
		}
		if output, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); !browserABContainerAbsent(output, err) {
			t.Errorf("A/B Browser container remained after cleanup: %v: %s", err, output)
		}
	})
	runDocker(t, ctx, nil, "run", "-d", "--pull=never", "--name", name,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace=browser-chroot-ab-diagnostic",
		"--user", "20000:30000", "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+policyPath,
		"--network", "none", "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"--tmpfs", "/workspace:rw,noexec,nosuid,size=1g", imageRef)
	securityOptions := runDocker(t, ctx, nil, "inspect", "--format", "{{json .HostConfig.SecurityOpt}}", name)
	var options []string
	if json.Unmarshal([]byte(securityOptions), &options) != nil || len(options) != 2 ||
		!strings.Contains(options[0], "no-new-privileges:true") ||
		!strings.HasPrefix(options[1], "seccomp=") {
		t.Fatal("Docker security options drifted")
	}
	var wantCompact, gotCompact bytes.Buffer
	if json.Compact(&wantCompact, policy) != nil ||
		json.Compact(&gotCompact, []byte(strings.TrimPrefix(options[1], "seccomp="))) != nil ||
		!bytes.Equal(wantCompact.Bytes(), gotCompact.Bytes()) ||
		!strings.Contains(runDocker(t, ctx, nil, "inspect", "--format", "{{json .HostConfig.CapDrop}}", name), "ALL") ||
		strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{.HostConfig.NetworkMode}}", name)) != "none" {
		t.Fatal("A/B container security settings drifted")
	}
	t.Logf("Docker-inspected compact seccomp JSON digest %s; source-file byte digest %s; cap-drop ALL; network none",
		digestBrowserPolicy(gotCompact.Bytes()), digestBrowserPolicy(policy))
	ready, state, logs := waitForBrowserAB(t, ctx, name)
	if expectFailure {
		if ready || state != "exited:133" || !strings.Contains(logs, `sys_chroot("/proc/self/fdinfo/") == 0`) {
			t.Fatalf("B did not isolate Chromium chroot dependency: ready=%v state=%s logs=%s", ready, state, logs)
		}
		t.Logf("B failed at Chromium zygote chroot with state %s: %s", state, strings.TrimSpace(logs))
		removeBrowserABContainer(t, ctx, name)
		removed = true
		return
	}
	if !ready {
		t.Fatalf("A Browser failed before CDP readiness: state=%s logs=%s", state, logs)
	}
	status := runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", "cat /proc/1/status")
	if !browserFourIDs(browserStatusField(status, "Uid"), "20000") ||
		!browserFourIDs(browserStatusField(status, "Gid"), "30000") ||
		browserStatusField(status, "CapEff") != "0000000000000000" ||
		browserStatusField(status, "CapBnd") != "0000000000000000" ||
		browserStatusField(status, "NoNewPrivs") != "1" ||
		browserStatusField(status, "Seccomp") != "2" {
		t.Fatalf("initial Browser process capability/seccomp state drifted:\n%s", status)
	}
	t.Logf("initial process security:\n%s", selectedBrowserStatus(status))
	initialUserNamespace := strings.TrimSpace(runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", "readlink /proc/1/ns/user"))
	initialMountNamespace := strings.TrimSpace(runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", "readlink /proc/1/ns/mnt"))
	if _, err := browserNamespaceID(initialUserNamespace, "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := browserNamespaceID(initialMountNamespace, "mnt"); err != nil {
		t.Fatal(err)
	}
	t.Logf("initial namespaces: user=%s mount=%s", initialUserNamespace, initialMountNamespace)
	for _, field := range []string{"{{.HostConfig.Privileged}}", "{{json .HostConfig.Binds}}", "{{json .HostConfig.Devices}}", "{{json .Mounts}}"} {
		t.Logf("Docker %s = %s", field, strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", field, name)))
	}
	if strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{.HostConfig.Privileged}}", name)) != "false" ||
		strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{json .HostConfig.Binds}}", name)) != "null" ||
		strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{json .HostConfig.Devices}}", name)) != "[]" ||
		strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{json .Mounts}}", name)) != "[]" {
		t.Fatal("A Browser gained privileged or host-mounted access")
	}
	for _, field := range []string{"PidMode", "IpcMode", "UsernsMode", "CgroupnsMode"} {
		mode := strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{.HostConfig."+field+"}}", name))
		if mode == "host" {
			t.Fatalf("A Browser shares host %s", field)
		}
		t.Logf("Docker %s = %q", field, mode)
	}
	if strings.TrimSpace(runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", "test ! -e /var/run/docker.sock && test ! -e /host && printf absent")) != "absent" {
		t.Fatal("A Browser can see a daemon socket or undeclared host mount")
	}
	chrootPath := strings.TrimSpace(runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", "command -v chroot"))
	probeOutput, probeErr := exec.CommandContext(ctx, "docker", "exec", "--user", "20000:30000", name, chrootPath, "/", "/bin/true").CombinedOutput()
	if probeErr == nil || !strings.Contains(string(probeOutput), "Operation not permitted") {
		t.Fatalf("initial non-root identity unexpectedly reached chroot: %v: %s", probeErr, probeOutput)
	}
	t.Logf("initial non-root chroot was denied: %s", strings.TrimSpace(string(probeOutput)))
	client := browserCDPClient(t, ctx, name)
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://127.0.0.1:9222/json/new?about:blank", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var pageTarget struct {
		Type                 string `json:"type"`
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&pageTarget) != nil {
		t.Fatalf("private CDP page creation unavailable: HTTP %d", response.StatusCode)
	}
	pageURL := pageTarget.WebSocketDebuggerURL
	if !strings.HasPrefix(pageURL, "ws://127.0.0.1:9222/devtools/page/") {
		t.Fatalf("private CDP page endpoint unavailable: %+v", pageTarget)
	}
	connection, _, err := websocket.Dial(ctx, pageURL, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	cdpBrowserCommand(t, ctx, connection, 1, "Page.enable", nil)
	page := "data:text/html," + url.PathEscape("<html><body><h1>phase6-sandbox</h1></body></html>")
	cdpBrowserCommand(t, ctx, connection, 2, "Page.navigate", map[string]any{"url": page})
	loaded := false
	for id := 3; id < 23; id++ {
		result := cdpBrowserCommand(t, ctx, connection, id, "Runtime.evaluate", map[string]any{
			"expression": "document.body && document.body.textContent.includes('phase6-sandbox')", "returnByValue": true})
		var value struct {
			Result struct {
				Value bool `json:"value"`
			} `json:"result"`
		}
		if json.Unmarshal(result, &value) == nil && value.Result.Value {
			loaded = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !loaded {
		t.Fatal("real CDP navigation did not render the data page")
	}
	screenshot := cdpBrowserCommand(t, ctx, connection, 23, "Page.captureScreenshot", map[string]any{"format": "png"})
	var capture struct {
		Data string `json:"data"`
	}
	if json.Unmarshal(screenshot, &capture) != nil {
		t.Fatal("CDP screenshot response invalid")
	}
	png, err := base64.StdEncoding.DecodeString(capture.Data)
	if err != nil || len(png) < 1024 || !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("real Browser render did not produce a PNG screenshot")
	}
	processes := runDocker(t, ctx, nil, "top", name, "-eo", "uid,gid,pid,args")
	if !strings.Contains(processes, "--type=zygote --headless") || strings.Contains(processes, "--no-sandbox") {
		t.Fatalf("Chromium sandbox process tree drifted:\n%s", processes)
	}
	for _, line := range strings.Split(strings.TrimSpace(processes), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "20000" || fields[1] != "30000" {
			t.Fatalf("Chromium process UID/GID drift: %q", line)
		}
	}
	zygote := runDocker(t, ctx, nil, "exec", name, "/bin/sh", "-c", `for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = headless-shell ] || continue; cmd=$(tr '\000' ' ' < "$p/cmdline" 2>/dev/null); case "$cmd" in *'--type=zygote --headless'*) printf 'PID=%s\n' "$p"; grep -E '^(Name|Uid|Gid|CapEff|CapBnd|NoNewPrivs|Seccomp|Seccomp_filters):' "$p/status"; printf 'USER_NS='; readlink "$p/ns/user"; printf 'MOUNT_NS='; readlink "$p/ns/mnt"; exit 0;; esac; done; exit 9`)
	zygoteUserNamespace := browserStatusField(zygote, "USER_NS")
	zygoteMountNamespace := browserStatusField(zygote, "MOUNT_NS")
	initialUserID, initialUserErr := browserNamespaceID(initialUserNamespace, "user")
	zygoteUserID, zygoteUserErr := browserNamespaceID(zygoteUserNamespace, "user")
	initialMountID, initialMountErr := browserNamespaceID(initialMountNamespace, "mnt")
	zygoteMountID, zygoteMountErr := browserNamespaceID(zygoteMountNamespace, "mnt")
	if !browserFourIDs(browserStatusField(zygote, "Uid"), "20000") ||
		!browserFourIDs(browserStatusField(zygote, "Gid"), "30000") ||
		browserStatusField(zygote, "CapEff") != "0000000000000000" ||
		browserStatusField(zygote, "NoNewPrivs") != "1" ||
		browserStatusField(zygote, "Seccomp") != "2" ||
		initialUserErr != nil || zygoteUserErr != nil || initialUserID == zygoteUserID ||
		initialMountErr != nil || zygoteMountErr != nil || initialMountID != zygoteMountID {
		t.Fatalf("Chromium zygote namespace/capability state unavailable: %s", zygote)
	}
	t.Logf("Chromium zygote state:\n%s", strings.TrimSpace(zygote))
	t.Logf("CDP navigation and %d-byte PNG screenshot passed with sandbox zygote", len(png))
	removeBrowserABContainer(t, ctx, name)
	removed = true
}

func removeBrowserABContainer(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	runDocker(t, ctx, nil, "rm", "-f", name)
	if output, err := exec.CommandContext(ctx, "docker", "container", "inspect", name).CombinedOutput(); !browserABContainerAbsent(output, err) {
		t.Fatalf("A/B Browser container absence unproved: %v: %s", err, output)
	}
}

func browserABContainerAbsent(output []byte, err error) bool {
	return err != nil && (strings.Contains(string(output), "No such object") ||
		strings.Contains(string(output), "No such container"))
}

func browserStatusField(document, field string) string {
	prefix := field + ":"
	if strings.HasSuffix(field, "_NS") {
		prefix = field + "="
	}
	value := ""
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, prefix) {
			if value != "" {
				return ""
			}
			value = strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return value
}

func browserFourIDs(value, wanted string) bool {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return false
	}
	for _, field := range fields {
		if field != wanted {
			return false
		}
	}
	return true
}

func browserNamespaceID(value, kind string) (uint64, error) {
	prefix := kind + ":["
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "]") {
		return 0, fmt.Errorf("invalid %s namespace observation", kind)
	}
	return strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(value, prefix), "]"), 10, 64)
}

func waitForBrowserAB(t *testing.T, ctx context.Context, name string) (bool, string, string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		logs := runDocker(t, ctx, nil, "logs", name)
		if strings.Contains(logs, "DevTools listening on ws://127.0.0.1:9222/") {
			return true, "running", logs
		}
		state := strings.TrimSpace(runDocker(t, ctx, nil, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name))
		if strings.HasPrefix(state, "exited:") {
			for retry := 0; retry < 8 && logs == ""; retry++ {
				time.Sleep(100 * time.Millisecond)
				logs = runDocker(t, ctx, nil, "logs", name)
			}
			return false, state, logs
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false, "timeout", runDocker(t, ctx, nil, "logs", name)
}

func browserCDPClient(t *testing.T, ctx context.Context, container string) *http.Client {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		command := exec.CommandContext(ctx, "docker", "exec", "-i", container, "/usr/bin/socat", "STDIO", "TCP:127.0.0.1:9222")
		stdin, err := command.StdinPipe()
		if err != nil {
			return nil, err
		}
		stdout, err := command.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := command.Start(); err != nil {
			return nil, err
		}
		client, bridge := net.Pipe()
		go func() { _, _ = io.Copy(stdin, bridge); _ = stdin.Close() }()
		go func() { _, _ = io.Copy(bridge, stdout); _ = bridge.Close() }()
		go func() { _ = command.Wait(); _ = bridge.Close() }()
		return client, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func cdpBrowserCommand(t *testing.T, ctx context.Context, connection *websocket.Conn, id int, method string, params map[string]any) json.RawMessage {
	t.Helper()
	document, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatalf("CDP %s write failed: %v", method, err)
	}
	for {
		_, payload, err := connection.Read(ctx)
		if err != nil {
			t.Fatalf("CDP %s read failed: %v", method, err)
		}
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(payload, &response) != nil {
			t.Fatalf("CDP %s malformed response: %s", method, payload)
		}
		if response.ID != id {
			continue
		}
		if len(response.Error) != 0 || len(response.Result) == 0 {
			t.Fatalf("CDP %s failed: %s", method, payload)
		}
		return response.Result
	}
}

func selectedBrowserStatus(status string) string {
	var lines []string
	for _, line := range strings.Split(status, "\n") {
		for _, field := range []string{"Name:", "Uid:", "Gid:", "CapEff:", "CapBnd:", "NoNewPrivs:", "Seccomp:", "Seccomp_filters:"} {
			if strings.HasPrefix(line, field) {
				lines = append(lines, line)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func digestBrowserPolicy(document []byte) string {
	sum := sha256.Sum256(document)
	return fmt.Sprintf("sha256:%x", sum)
}
