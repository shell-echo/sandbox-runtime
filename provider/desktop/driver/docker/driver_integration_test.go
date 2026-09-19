//go:build integration

package docker

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/moby/moby/client"

	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

// TestDesktopBrokerTransportIntegration proves the immutable image, container
// isolation, private broker attach/reconnect, and exact runtime cleanup against
// a real Docker engine. Network=none is deliberate here: restricted-egress
// provisioning remains an independent mandatory dependency of Driver.New and
// is not claimed by this transport-focused test.
func TestDesktopBrokerTransportIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DESKTOP_ADAPTER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DESKTOP_ADAPTER_INTEGRATION=1 to test the private Desktop broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	manifest, err := desktopimage.Load("../../../../profiles/desktop/image/manifest.json")
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
	image := desktopimage.LockedPublication().Image()
	if err := backend.ensureImage(ctx, image, PullIfNotPresent); err != nil {
		t.Fatal(err)
	}
	inspected, err := backend.inspectImage(ctx, image)
	if err != nil || validateImage(inspected, manifest, desktopimage.LockedPublication()) != nil {
		t.Fatalf("locked image inspection failed: %v", err)
	}
	name := fmt.Sprintf("sandbox-runtime-desktop-broker-%d", time.Now().UnixNano())
	id, err := backend.create(ctx, createRequest{
		name: name, image: image, labels: map[string]string{managedLabel: "true"},
		user: DesktopUser, workingDirectory: "/workspace",
		memoryBytes: 1 << 30, nanoCPUs: 1_000_000_000, pidsLimit: 256,
		inputsBytes: 16 << 20, tmpfsBytes: 256 << 20, workspaceBytes: 256 << 20,
		outputsBytes: 128 << 20, stopTimeout: 10, networkName: "none", dnsResolver: "10.88.0.2",
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
		host.PublishAllPorts || len(host.PortBindings) != 0 || len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" ||
		len(host.SecurityOpt) != 1 || host.SecurityOpt[0] != "no-new-privileges:true" ||
		host.IpcMode != "private" || host.CgroupnsMode != "private" || len(host.Devices) != 0 ||
		len(host.DeviceRequests) != 0 || host.Memory <= 0 || host.NanoCPUs <= 0 || host.PidsLimit == nil {
		t.Fatalf("container isolation = %#v", host)
	}
	driver := &Driver{engine: backend}
	for {
		descriptor, describeErr := driver.brokerDescriptor(ctx, id)
		if describeErr == nil {
			if descriptor.Validate() != nil {
				t.Fatalf("invalid broker descriptor = %#v", descriptor)
			}
			break
		}
		if waitErr := waitContext(ctx, desktopReadyPoll); waitErr != nil {
			t.Fatalf("private Desktop broker did not become ready: %v", describeErr)
		}
	}
	first, err := driver.brokerDescriptor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	second, err := driver.brokerDescriptor(ctx, id)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("fresh reconnect descriptor = %#v, %v", second, err)
	}
	if err := backend.remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.inspect(ctx, id); err == nil {
		t.Fatal("Desktop runtime remained after cleanup")
	}
}
