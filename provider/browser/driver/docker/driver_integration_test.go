//go:build integration

package docker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

// TestBrowserRelayTransportIntegration deliberately uses network=none. It
// proves the locked image controls and private Docker exec/CDP transport only;
// it is not restricted-egress or complete Browser runtime evidence.
func TestBrowserRelayTransportIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BROWSER_ADAPTER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_BROWSER_ADAPTER_INTEGRATION=1 to test the private Browser relay")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	manifest, err := browserimage.Load("../../../../profiles/browser/image/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	seccomp, err := os.ReadFile("../../../../profiles/browser/image/chromium-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := newMobyEngine(os.Getenv("DOCKER_HOST"))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.close()
	if err := backend.ping(ctx); err != nil {
		t.Fatal(err)
	}
	image := browserimage.LockedPublication().Image()
	if err := backend.ensureImage(ctx, image, PullIfNotPresent); err != nil {
		t.Fatal(err)
	}
	if inspected, err := backend.inspectImage(ctx, image); err != nil || validateImage(inspected, manifest, browserimage.LockedPublication()) != nil {
		t.Fatalf("locked image inspection failed: %v", err)
	}
	name := fmt.Sprintf("sandbox-runtime-browser-relay-%d", time.Now().UnixNano())
	id, err := backend.create(ctx, createRequest{
		name: name, image: image, labels: map[string]string{managedLabel: "true"},
		user: BrowserUser, workingDirectory: "/workspace",
		memoryBytes: 1 << 30, nanoCPUs: 1_000_000_000, pidsLimit: 256,
		inputsBytes: 16 << 20, tmpfsBytes: 256 << 20, workspaceBytes: 256 << 20, outputsBytes: 128 << 20, stopTimeout: 10,
		networkName: "none", seccompProfile: string(seccomp),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = backend.remove(cleanupCtx, id)
	})
	if err := backend.start(ctx, id); err != nil {
		t.Fatal(err)
	}
	inspection, err := backend.client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	host := inspection.Container.HostConfig
	if host == nil || host.NetworkMode != "none" || !host.ReadonlyRootfs || host.Privileged ||
		host.PublishAllPorts || len(host.PortBindings) != 0 || len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" {
		t.Fatalf("container isolation = %#v", host)
	}
	driver := &Driver{engine: backend}
	var path string
	for {
		path, err = driver.browserWebSocketPath(ctx, id)
		if err == nil {
			break
		}
		if waitErr := waitContext(ctx, browserReadyPoll); waitErr != nil {
			t.Fatalf("private CDP did not become ready: %v", err)
		}
	}
	connection, reader, err := driver.attachWebSocket(ctx, id, path)
	if err != nil {
		t.Fatal(err)
	}
	stream := &browserStream{connection: connection, reader: reader}
	defer stream.Close()
	payload := []byte(`{"id":1,"method":"Browser.getVersion"}`)
	if err := writeAll(ctx, stream, maskedWebSocketFrame(payload)); err != nil {
		t.Fatal(err)
	}
	response := readWebSocketFrame(t, ctx, stream)
	var message struct {
		ID     int `json:"id"`
		Result struct {
			Product string `json:"product"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response, &message); err != nil || message.ID != 1 || message.Result.Product != "Chrome/151.0.7922.109" {
		t.Fatalf("CDP response = %s, %v", response, err)
	}
}

func maskedWebSocketFrame(payload []byte) []byte {
	mask := [4]byte{0x19, 0x26, 0x08, 0x25}
	frame := []byte{0x81}
	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload))|0x80)
	case len(payload) <= 65_535:
		frame = append(frame, 126|0x80, byte(len(payload)>>8), byte(len(payload)))
	default:
		panic("test payload is too large")
	}
	frame = append(frame, mask[:]...)
	for index, value := range payload {
		frame = append(frame, value^mask[index%len(mask)])
	}
	return frame
}

func readWebSocketFrame(t *testing.T, ctx context.Context, stream *browserStream) []byte {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(contextStreamReader{ctx: ctx, stream: stream}, header); err != nil {
		t.Fatal(err)
	}
	if header[0]&0x80 == 0 || header[0]&0x0f != 1 || header[1]&0x80 != 0 {
		t.Fatalf("unexpected WebSocket header %x", header)
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(contextStreamReader{ctx: ctx, stream: stream}, extended); err != nil {
			t.Fatal(err)
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(contextStreamReader{ctx: ctx, stream: stream}, extended); err != nil {
			t.Fatal(err)
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if length == 0 || length > 64<<10 {
		t.Fatalf("WebSocket payload length = %d", length)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(contextStreamReader{ctx: ctx, stream: stream}, payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"id":1`) {
		t.Fatalf("unexpected CDP message = %s", payload)
	}
	return payload
}
