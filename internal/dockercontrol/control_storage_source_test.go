//go:build darwin || linux

package dockercontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

func newSourceControlFixture(t *testing.T) *controlStorageFixture {
	f := newControlStorageFixture(t)
	b := &f.b
	b.Backend.Device = "/dev/loop7"
	b.SourceSealDigest = executionTestDigest("9")
	b.SourceSocket = "/var/run/docker.sock"
	for i := range f.volumes {
		role := "filesystem"
		if i == 1 {
			role = "backing"
		}
		f.volumes[i].Labels = b.labels(role)
	}
	f.volumes[0].Options["device"] = b.Backend.Device
	c := &f.containers[0]
	c.Config.Labels = b.labels("control")
	c.HostConfig.GroupAdd = []string{"0"}
	c.HostConfig.NetworkMode = "none"
	for i := 0; i < 8; i++ {
		p := fmt.Sprintf("/dev/loop%d", i)
		c.HostConfig.Devices = append(c.HostConfig.Devices, container.DeviceMapping{PathOnHost: p, PathInContainer: p, CgroupPermissions: "r"})
	}
	c.HostConfig.Mounts = append(c.HostConfig.Mounts, mount.Mount{Type: mount.TypeVolume, Source: b.backingVolume(), Target: controlstorage.SourceMountPath, ReadOnly: true, VolumeOptions: &mount.VolumeOptions{NoCopy: true}}, mount.Mount{Type: mount.TypeBind, Source: b.SourceSocket, Target: controlStorageSocketTarget, ReadOnly: true})
	c.Mounts = append(c.Mounts, container.MountPoint{Type: mount.TypeVolume, Name: b.backingVolume(), Source: f.volumes[1].Mountpoint, Destination: controlstorage.SourceMountPath, Driver: "local"}, container.MountPoint{Type: mount.TypeBind, Source: b.SourceSocket, Destination: controlStorageSocketTarget, Propagation: "rprivate"})
	f.transport.binding = *b
	return f
}
func TestSourceControlExactAuthority(t *testing.T) {
	f := newSourceControlFixture(t)
	if _, e := readControlStorageInventory(t.Context(), f.api, f.b); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*controlStorageFixture){
		"rw device":    func(f *controlStorageFixture) { f.containers[0].HostConfig.Devices[7].CgroupPermissions = "rw" },
		"device alias": func(f *controlStorageFixture) { f.containers[0].HostConfig.Devices[7].PathInContainer = "/dev/other" },
		"duplicate device": func(f *controlStorageFixture) {
			f.containers[0].HostConfig.Devices[7] = f.containers[0].HostConfig.Devices[6]
		},
		"extra group": func(f *controlStorageFixture) {
			f.containers[0].HostConfig.GroupAdd = append(f.containers[0].HostConfig.GroupAdd, "6")
		},
		"missing group":         func(f *controlStorageFixture) { f.containers[0].HostConfig.GroupAdd = nil },
		"wrong user":            func(f *controlStorageFixture) { f.containers[0].Config.User = "57012:57011" },
		"rw backing":            func(f *controlStorageFixture) { f.containers[0].Mounts[1].RW = true },
		"configured rw backing": func(f *controlStorageFixture) { f.containers[0].HostConfig.Mounts[1].ReadOnly = false },
		"backing subpath":       func(f *controlStorageFixture) { f.containers[0].HostConfig.Mounts[1].VolumeOptions.Subpath = "sub" },
		"socket alias":          func(f *controlStorageFixture) { f.containers[0].Mounts[2].Source = "/run/other.sock" },
		"rw socket":             func(f *controlStorageFixture) { f.containers[0].Mounts[2].RW = true },
		"second stopped consumer": func(f *controlStorageFixture) {
			c := f.containers[0]
			c.ID = fmt.Sprintf("%064x", 12)
			c.Name = "/extra"
			c.State = &container.State{Status: "created"}
			f.containers = append(f.containers, c)
		},
		"legacy cannot acquire": func(f *controlStorageFixture) { f.b.SourceSealDigest = ""; f.b.SourceSocket = "" },
		"socket directory via named volume": func(f *controlStorageFixture) {
			v := f.volumes[1]
			v.Name = "socket-alias"
			v.Mountpoint = "/var/lib/docker/volumes/socket-alias/_data"
			v.Options = map[string]string{"type": "none", "o": "bind", "device": "/run"}
			f.volumes = append(f.volumes, v)
		},
		"stopped socket consumer": func(f *controlStorageFixture) {
			c := container.InspectResponse{ID: fmt.Sprintf("%064x", 42), Name: "/socket-extra", Config: &container.Config{}, State: &container.State{Status: "created"}, HostConfig: &container.HostConfig{}}
			c.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeBind, Source: "/run/docker.sock", Target: "/socket", ReadOnly: true}}
			c.Mounts = []container.MountPoint{{Type: mount.TypeBind, Source: "/run/docker.sock", Destination: "/socket"}}
			f.containers = append(f.containers, c)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSourceControlFixture(t)
			change(f)
			if _, e := readControlStorageInventory(t.Context(), f.api, f.b); e == nil {
				t.Fatal("unsafe authority accepted")
			}
		})
	}
	before, e := readSourceVolumeBinding(t.Context(), f.api, f.b)
	if e != nil {
		t.Fatal(e)
	}
	f.volumes[0].CreatedAt = "2026-10-12T00:00:00Z"
	after, e := readSourceVolumeBinding(t.Context(), f.api, f.b)
	if e != nil || before == after {
		t.Fatal("volume recreation lost from persistent binding")
	}
}

func TestSourceDesktopListMappingIsExactAndUnowned(t *testing.T) {
	f := newSourceControlFixture(t)
	b := f.b
	b.SourceSocket = "/run/host-services/docker.proxy.sock"
	base := container.MountPoint{Type: mount.TypeBind, Source: "/Users/example/data", Destination: "/data", RW: true, Propagation: "rprivate"}
	listed := base
	listed.Source = "/host_mnt" + base.Source
	if !sameControlStorageMounts([]container.MountPoint{listed}, []container.MountPoint{base}, b, false) {
		t.Fatal("observed exact mapping rejected")
	}
	if sameControlStorageMounts([]container.MountPoint{listed}, []container.MountPoint{base}, b, true) {
		t.Fatal("owned path mapping accepted")
	}
	for _, change := range []func(*container.MountPoint){func(m *container.MountPoint) { m.RW = false }, func(m *container.MountPoint) { m.Source = "/host_mnt/Users/another/data" }, func(m *container.MountPoint) { m.Destination = "/other" }, func(m *container.MountPoint) { m.Type = mount.TypeVolume }} {
		x := listed
		change(&x)
		if sameControlStorageMounts([]container.MountPoint{x}, []container.MountPoint{base}, b, false) {
			t.Fatal("drift accepted")
		}
	}
	b.SourceSealDigest = ""
	if sameControlStorageMounts([]container.MountPoint{listed}, []container.MountPoint{base}, b, false) {
		t.Fatal("legacy mapping weakened")
	}
}

func TestSourceDesktopInventoryRetainsRawSafetyChecks(t *testing.T) {
	for _, kind := range []string{"exact", "rw drift", "socket alias", "volume alias"} {
		t.Run(kind, func(t *testing.T) {
			f := newSourceControlFixture(t)
			f.b.SourceSocket = "/run/host-services/docker.proxy.sock"
			f.containers[0].HostConfig.Mounts[2].Source = f.b.SourceSocket
			f.containers[0].Mounts[2].Source = f.b.SourceSocket
			f.transport.binding = f.b
			peer := container.InspectResponse{ID: fmt.Sprintf("%064x", 43), Name: "/unrelated", Config: &container.Config{}, State: &container.State{Status: "created"}, HostConfig: &container.HostConfig{}}
			peer.Mounts = []container.MountPoint{{Type: mount.TypeBind, Source: "/Users/example/data", Destination: "/data", RW: true, Propagation: "rprivate"}}
			f.containers = append(f.containers, peer)
			f.transport.base = codingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := f.respond(r)
				if err != nil || r.URL.Path != "/v1.55/containers/json" {
					return response, err
				}
				data, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				var list []container.Summary
				if err := json.Unmarshal(data, &list); err != nil {
					t.Fatal(err)
				}
				m := &list[1].Mounts[0]
				m.Source = "/host_mnt" + m.Source
				switch kind {
				case "rw drift":
					m.RW = false
				case "socket alias":
					m.Source = f.b.SourceSocket
				case "volume alias":
					m.Source = f.volumes[0].Mountpoint
				}
				data, _ = json.Marshal(list)
				return codingTransportResponse(200, string(data), int64(len(data))), nil
			})
			_, err := readControlStorageInventory(t.Context(), f.api, f.b)
			if (err == nil) != (kind == "exact") {
				t.Fatal("unexpected inventory admission", err)
			}
		})
	}
}

func TestSourceFirstExternalReadHasSharedDeadline(t *testing.T) {
	for _, operation := range []bool{false, true} {
		f := newSourceControlFixture(t)
		called := false
		f.before = func(r *http.Request) {
			called = true
			deadline, ok := r.Context().Deadline()
			if !ok || time.Until(deadline) > maxCodingInventoryDuration {
				t.Fatal("unbounded first external source read")
			}
		}
		store := &controlstorage.Store{}
		var err error
		if operation {
			gate := make(chan struct{}, 1)
			gate <- struct{}{}
			s := &sourceBoundControlStorage{observer: &controlStorageUnixObserver{gate: gate, api: f.api, binding: f.b, store: store}}
			err = s.Check(t.Context())
		} else {
			_, err = observeControlStorage(t.Context(), f.api, store, f.b)
		}
		if !called || err == nil {
			t.Fatal("unbound Store should reject after bounded source read")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := &sourceBoundControlStorage{observer: &controlStorageUnixObserver{gate: make(chan struct{}, 1)}}
	done := make(chan error, 1)
	go func() { done <- s.Check(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled admission accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled admission remained queued")
	}
}
