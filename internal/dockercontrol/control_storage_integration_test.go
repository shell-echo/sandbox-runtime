//go:build integration && (darwin || linux)

package dockercontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// Uses only fresh ordinary volumes, restricted containers and exact owned
// cleanup. It proves daemon mount/consumer rejection, not a quota backend.
func TestControlStorageRealStoppedConsumerAndOrdinaryVolumeRefusal(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CONTROL_STORAGE_INTEGRATION") != "1" {
		t.Skip("explicit Docker fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	api, err := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f := newControlStorageFixture(t)
	b := f.b
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	b.Storage.Namespace = hex.EncodeToString(nonce)
	b.Storage.StorageID = "control-execution-" + b.Storage.Namespace
	b.ControlName = b.Storage.StorageID
	const image = "sha256:ae959799024a09da597284763c417a6e820e020fad0634c5267cf4f125e682bf"
	i, err := api.ImageInspect(ctx, image)
	if err != nil || i.ID != image || i.Architecture != "arm64" || i.Os != "linux" {
		t.Fatal("pinned local fixture image unavailable", err)
	}
	b.ControlImageID = image
	info, err := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	b.Daemon = info
	ids := []string{}
	vols := []string{}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for n := len(ids) - 1; n >= 0; n-- {
			r, e := api.ContainerInspect(cleanup, ids[n], client.ContainerInspectOptions{})
			if e != nil || r.Container.Config == nil || r.Container.Config.Labels["sandbox-runtime.control-storage.namespace"] != b.Storage.Namespace {
				t.Error("owned container identity lost", e)
				continue
			}
			_, e = api.ContainerRemove(cleanup, ids[n], client.ContainerRemoveOptions{Force: true})
			if e != nil {
				t.Error(e)
			}
		}
		for n := len(vols) - 1; n >= 0; n-- {
			r, e := api.VolumeInspect(cleanup, vols[n], client.VolumeInspectOptions{})
			if e != nil || r.Volume.Labels["sandbox-runtime.control-storage.namespace"] != b.Storage.Namespace {
				t.Error("owned volume identity lost", e)
				continue
			}
			_, e = api.VolumeRemove(cleanup, vols[n], client.VolumeRemoveOptions{})
			if e != nil {
				t.Error(e)
			}
		}
		filters := make(client.Filters).Add("label", "sandbox-runtime.control-storage.namespace="+b.Storage.Namespace)
		cs, e := api.ContainerList(cleanup, client.ContainerListOptions{All: true, Filters: filters})
		if e != nil || len(cs.Items) != 0 {
			t.Error("container cleanup incomplete", e)
		}
		vs, e := api.VolumeList(cleanup, client.VolumeListOptions{Filters: filters})
		if e != nil || len(vs.Items) != 0 {
			t.Error("volume cleanup incomplete", e)
		}
	})
	// First discover the fresh backing mountpoint; then bind final labels to it.
	// A single ordinary data volume is sufficient for this negative gate.
	v, err := api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: b.Storage.StorageID, Labels: b.labels("filesystem")})
	if err != nil {
		t.Fatal(err)
	}
	vols = append(vols, v.Volume.Name)
	pids := int64(32)
	h := &container.HostConfig{ReadonlyRootfs: true, NetworkMode: "none", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, LogConfig: container.LogConfig{Type: "none"}, Resources: container.Resources{Memory: 64 << 20, MemorySwap: 64 << 20, NanoCPUs: 500_000_000, PidsLimit: &pids}, Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: v.Volume.Name, Target: controlStorageTarget, VolumeOptions: &mount.VolumeOptions{NoCopy: true}}}}
	c, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: b.ControlName, Config: &container.Config{Image: image, User: "57010:57011", Cmd: []string{"/bin/sleep", "60"}, Labels: b.labels("control")}, HostConfig: h})
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, c.ID)
	b.ControlID = c.ID
	if _, err := api.ContainerStart(ctx, c.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := api.ContainerInspect(ctx, c.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !safeStorageContainer(r.Container, b, v.Volume, f.volumes[1]) {
		t.Logf("fixture runtime: name=%s image=%s user=%s caps=%v/%v security=%v mounts=%+v configured=%+v labels=%v volumes=%+v", r.Container.Name, r.Container.Image, r.Container.Config.User, r.Container.HostConfig.CapAdd, r.Container.HostConfig.CapDrop, r.Container.HostConfig.SecurityOpt, r.Container.Mounts, r.Container.HostConfig.Mounts, r.Container.Config.Labels, v.Volume)
		t.Fatal("real sole-consumer mount projection rejected")
	}
	if validControlStorageVolume(v.Volume, b, false) {
		t.Fatal("ordinary volume became dedicated backend")
	}
	second, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: b.ControlName + "-stopped", Config: &container.Config{Image: image, User: "57010:57011", Cmd: []string{"/bin/true"}, Labels: b.labels("fixture-extra")}, HostConfig: h})
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, second.ID)
	other, err := api.ContainerInspect(ctx, second.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if other.Container.State.Running || safeStorageContainer(other.Container, b, v.Volume, f.volumes[1]) {
		t.Fatal("stopped second consumer was accepted")
	}
	all, err := api.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range all.Items {
		if c.ID == second.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("all-consumer observation omitted stopped container")
	}
	if _, err := readControlStorageInventory(ctx, api, b); err == nil {
		t.Fatal("real ordinary backend accepted")
	}
	t.Log("actual Docker sole-mount projection, stopped second-consumer refusal, ordinary-volume refusal; no dedicated physical admission")
}
