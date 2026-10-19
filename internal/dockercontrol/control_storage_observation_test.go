//go:build darwin || linux

package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

type controlStorageFixture struct {
	b          controlStorageBinding
	volumes    []volume.Volume
	containers []container.InspectResponse
	before     func(*http.Request)
	api        *client.Client
	transport  *controlStorageTransport
}

func newControlStorageFixture(t *testing.T) *controlStorageFixture {
	t.Helper()
	x := executionTestBinding(t)
	b := controlStorageBinding{Storage: x.Storage, EndpointScopeDigest: x.EndpointScopeDigest,
		Daemon:    CodingDaemonObservation{IdentityDigest: x.DaemonDigest, EnvironmentDigest: x.DaemonEnvironmentDigest, Platform: x.Template.Image.Platform},
		ControlID: strings.Repeat("e", 64), ControlName: "control-execution-" + x.Storage.Namespace, ControlImageID: executionTestDigest("f")}
	b.Storage.UID, b.Storage.GID = 57010, 57011
	back := "/var/lib/docker/volumes/" + b.backingVolume() + "/_data"
	b.Backend = controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: "/dev/loop17", BackingFile: back + "/receipt.ext4", Bytes: 1 << 30}
	v := volume.Volume{Name: b.Storage.StorageID, Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/" + b.Storage.StorageID + "/_data", Labels: b.labels("filesystem"), Options: map[string]string{"type": "ext4", "device": b.Backend.Device, "o": "rw,nosuid,nodev,noexec,private"}}
	c := container.InspectResponse{ID: b.ControlID, Name: "/" + b.ControlName, Image: b.ControlImageID, Config: &container.Config{User: "57010:57011", Labels: b.labels("control")}, State: &container.State{Status: "running", Running: true, Pid: 123}, HostConfig: &container.HostConfig{ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}}}
	c.Mounts = []container.MountPoint{{Type: mount.TypeVolume, Name: v.Name, Driver: "local", Source: v.Mountpoint, Destination: controlStorageTarget, RW: true}}
	c.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeVolume, Source: v.Name, Target: controlStorageTarget, VolumeOptions: &mount.VolumeOptions{NoCopy: true}}}
	f := &controlStorageFixture{b: b, volumes: []volume.Volume{v, {Name: b.backingVolume(), Driver: "local", Scope: "local", Mountpoint: back, Labels: b.labels("backing")}}, containers: []container.InspectResponse{c}}
	f.transport = &controlStorageTransport{host: "/run/docker.sock", binding: b, base: codingRoundTripFunc(f.respond)}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{Transport: f.transport}))
	if err != nil {
		t.Fatal(err)
	}
	f.api = api
	t.Cleanup(func() { _ = api.Close() })
	return f
}
func (f *controlStorageFixture) respond(r *http.Request) (*http.Response, error) {
	if f.before != nil {
		f.before(r)
	}
	var value any
	switch r.URL.Path {
	case "/v1.55/info":
		value = codingInfoFixture()
	case "/v1.55/volumes":
		value = struct {
			Volumes  []volume.Volume
			Warnings []string
		}{f.volumes, nil}
	case "/v1.55/containers/json":
		list := []container.Summary{}
		for _, c := range f.containers {
			list = append(list, container.Summary{ID: c.ID, Names: []string{c.Name}, Mounts: c.Mounts, State: c.State.Status})
		}
		value = list
	default:
		for _, v := range f.volumes {
			if r.URL.Path == "/v1.55/volumes/"+v.Name {
				value = v
			}
		}
		for _, c := range f.containers {
			if r.URL.Path == "/v1.55/containers/"+c.ID+"/json" {
				value = c
			}
		}
	}
	if value == nil {
		return nil, fmt.Errorf("unexpected fixture request")
	}
	d, _ := json.Marshal(value)
	return codingTransportResponse(200, string(d), int64(len(d))), nil
}

func TestControlStorageSyntheticWholeDaemonObservation(t *testing.T) {
	f := newControlStorageFixture(t)
	a, err := readControlStorageInventory(t.Context(), f.api, f.b)
	if err != nil || !controlDigest.MatchString(a) {
		t.Fatal("synthetic inventory", err)
	}
	b, err := readControlStorageInventory(t.Context(), f.api, f.b)
	if err != nil || a != b {
		t.Fatal("stable synthetic inventory", err)
	}
	if _, err := observeControlStorage(t.Context(), f.api, nil, f.b); err == nil {
		t.Fatal("synthetic Docker data bypassed live Store fd")
	}
}

func TestControlStorageRejectsAdditionalConsumersAndUnsafeBackend(t *testing.T) {
	cases := map[string]func(*controlStorageFixture){
		"second stopped consumer": func(f *controlStorageFixture) {
			c := f.containers[0]
			c.ID = strings.Repeat("c", 64)
			c.Name = "/stopped"
			c.State = &container.State{Status: "exited"}
			f.containers = append(f.containers, c)
		},
		"read-only second consumer": func(f *controlStorageFixture) {
			c := f.containers[0]
			c.ID = strings.Repeat("c", 64)
			c.Name = "/readonly"
			c.Mounts = append([]container.MountPoint{}, c.Mounts...)
			c.Mounts[0].RW = false
			f.containers = append(f.containers, c)
		},
		"backing accessible": func(f *controlStorageFixture) {
			f.containers[0].Mounts = append(f.containers[0].Mounts, container.MountPoint{Type: mount.TypeBind, Source: f.volumes[1].Mountpoint, Destination: "/backing"})
		},
		"parent bind": func(f *controlStorageFixture) {
			f.containers[0].Mounts = append(f.containers[0].Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/var/lib/docker", Destination: "/alias"})
		},
		"hidden target": func(f *controlStorageFixture) {
			f.containers[0].Mounts = append(f.containers[0].Mounts, container.MountPoint{Type: mount.TypeTmpfs, Destination: controlStorageTarget + "/state"})
		},
		"same device alias volume": func(f *controlStorageFixture) {
			v := f.volumes[0]
			v.Name = "alias"
			v.Mountpoint = "/var/lib/docker/volumes/alias/_data"
			f.volumes = append(f.volumes, v)
		},
		"bind backend alias": func(f *controlStorageFixture) {
			f.volumes = append(f.volumes, volume.Volume{Name: "alias", Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/alias/_data", Options: map[string]string{"type": "none", "device": f.volumes[1].Mountpoint, "o": "bind"}})
		},
		"shared ordinary volume":       func(f *controlStorageFixture) { f.volumes[0].Options = nil },
		"missing private mount option": func(f *controlStorageFixture) { f.volumes[0].Options["o"] = "rw,nosuid,nodev,noexec" },
		"upstream propagation option":  func(f *controlStorageFixture) { f.volumes[0].Options["o"] = "rw,nosuid,nodev,noexec,slave" },
		"unknown driver":               func(f *controlStorageFixture) { f.volumes[1].Driver = "plugin" },
		"changed owner":                func(f *controlStorageFixture) { f.containers[0].Config.User = "0:0" },
		"changed source":               func(f *controlStorageFixture) { f.containers[0].Mounts[0].Source += "/child" },
		"changed principal": func(f *controlStorageFixture) {
			f.containers[0].Config.Labels["sandbox-runtime.control-storage.principal"] = executionTestDigest("1")
		},
		"tmpfs hidden target": func(f *controlStorageFixture) {
			f.containers[0].HostConfig.Tmpfs = map[string]string{controlStorageTarget: "size=1m"}
		},
		"volume subpath": func(f *controlStorageFixture) { f.containers[0].HostConfig.Mounts[0].VolumeOptions.Subpath = "sub" },
		"shared Control PID namespace": func(f *controlStorageFixture) {
			f.containers[0].HostConfig.PidMode = container.PidMode("container:" + f.b.ControlID)
		},
		"privileged":       func(f *controlStorageFixture) { f.containers[0].HostConfig.Privileged = true },
		"device authority": func(f *controlStorageFixture) { f.containers[0].HostConfig.DeviceCgroupRules = []string{"b 7:* rwm"} },
		"over volume bound": func(f *controlStorageFixture) {
			for i := len(f.volumes); i <= maxControlStorageVolumes; i++ {
				v := f.volumes[0]
				v.Name = fmt.Sprint(i)
				f.volumes = append(f.volumes, v)
			}
		},
		"duplicate container": func(f *controlStorageFixture) { f.containers = append(f.containers, f.containers[0]) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newControlStorageFixture(t)
			change(f)
			if _, err := readControlStorageInventory(t.Context(), f.api, f.b); err == nil {
				t.Fatal("unsafe daemon view accepted")
			}
		})
	}
}

func TestControlStorageRejectsListInspectRaceAndCancellation(t *testing.T) {
	f := newControlStorageFixture(t)
	calls := 0
	f.before = func(r *http.Request) {
		if r.URL.Path == "/v1.55/containers/json" {
			calls++
			if calls == 2 {
				f.containers = nil
			}
		}
	}
	if _, err := readControlStorageInventory(t.Context(), f.api, f.b); err == nil {
		t.Fatal("disappearing consumer accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readControlStorageInventory(ctx, f.api, f.b); err == nil {
		t.Fatal("cancelled collection accepted")
	}
}

func TestControlStorageTransportRejectsBroaderReadsAndAmbiguousJSON(t *testing.T) {
	f := newControlStorageFixture(t)
	for _, uri := range []string{"/v1.55/containers/json", "/v1.55/containers/json?all=1&filters={}", "/v1.55/volumes/unlisted", "/v1.55/containers/" + f.b.ControlID + "/json", "/v1.55/events", "/v1.55/info?x=1"} {
		r, _ := http.NewRequest("GET", "http://"+client.DummyHost+uri, nil)
		r.URL.Host = f.transport.host
		r.Host = client.DummyHost
		if f.transport.allowed(r) {
			t.Fatal("broader read accepted", uri)
		}
	}
	f.transport.base = codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return codingTransportResponse(200, `{"ID":"first","id":"alias"}`, -1), nil
	})
	if _, err := f.api.Info(t.Context(), client.InfoOptions{}); err == nil {
		t.Fatal("case alias accepted")
	}
}

type storageChangingBody struct {
	io.Reader
	read  func()
	close func() error
}

func (b storageChangingBody) Read(p []byte) (int, error) {
	if b.read != nil {
		b.read()
	}
	return b.Reader.Read(p)
}
func (b storageChangingBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}
func TestControlStorageSocketAndCloseRecheckedAfterBody(t *testing.T) {
	for _, when := range []string{"read", "close", "close-error"} {
		t.Run(when, func(t *testing.T) {
			f := newControlStorageFixture(t)
			same := true
			f.transport.checkSocket = func() bool { return same }
			f.transport.base = codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				r := codingTransportResponse(200, `{}`, -1)
				r.Body = storageChangingBody{Reader: strings.NewReader(`{}`), read: func() {
					if when == "read" {
						same = false
					}
				}, close: func() error {
					if when == "close" {
						same = false
					}
					if when == "close-error" {
						return errors.New("close failed")
					}
					return nil
				}}
				return r, nil
			})
			if _, err := f.api.Info(t.Context(), client.InfoOptions{}); err == nil {
				t.Fatal("changed source/body close failure accepted")
			}
		})
	}
}
