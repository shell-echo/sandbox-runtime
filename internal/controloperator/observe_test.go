package controloperator

import (
	"encoding/json"
	"errors"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"os"
	"testing"
)

// Uses a retained real create observation and original OCI inputs. No Docker
// writes happen in this negative projection test.
func TestDeliveryDaemonIdentityFixture(t *testing.T) {
	path := os.Getenv("CONTROL_DELIVERY_INPUT")
	inspectPath := os.Getenv("CONTROL_DELIVERY_INSPECT")
	if path == "" || inspectPath == "" {
		t.Skip("explicit real observation fixture")
	}
	a, e := load(t.Context(), path)
	if e != nil {
		t.Fatal("inputs", e)
	}
	defer clear(a.key)
	raw, e := os.ReadFile(inspectPath)
	if e != nil {
		t.Fatal(e)
	}
	var all []container.InspectResponse
	if json.Unmarshal(raw, &all) != nil || len(all) != 1 {
		t.Fatal("inspect fixture")
	}
	c := all[0]
	if check(c, a, false) != nil {
		t.Fatal("exact real create config")
	}
	for name, mutate := range map[string]func(*container.InspectResponse){
		"selected manifest":   func(c *container.InspectResponse) { c.ImageManifestDescriptor.Digest = "sha256:wrong" },
		"descriptor size":     func(c *container.InspectResponse) { c.ImageManifestDescriptor.Size++ },
		"descriptor platform": func(c *container.InspectResponse) { c.ImageManifestDescriptor.Platform.Architecture = "amd64" },
		"config image":        func(c *container.InspectResponse) { c.Config.Image = "different" },
		"index":               func(c *container.InspectResponse) { c.Image = "different" },
		"entrypoint":          func(c *container.InspectResponse) { c.Config.Entrypoint = []string{"/bin/sleep"} },
		"env":                 func(c *container.InspectResponse) { c.Config.Env = append(c.Config.Env, "ENV=/tmp/hook") },
		"duplicate env":       func(c *container.InspectResponse) { c.Config.Env = append(c.Config.Env, c.Config.Env[0]) },
		"probe mount":         func(c *container.InspectResponse) { c.Mounts[0].Destination = "/usr/local/bin" },
		"rw config":           func(c *container.InspectResponse) { c.Mounts[0].RW = true },
		"device": func(c *container.InspectResponse) {
			c.HostConfig.Devices = append(c.HostConfig.Devices, container.DeviceMapping{PathOnHost: "/dev/loop0"})
		},
		"group":        func(c *container.InspectResponse) { c.HostConfig.GroupAdd = append(c.HostConfig.GroupAdd, "999") },
		"uid":          func(c *container.InspectResponse) { c.Config.User = "0:0" },
		"network":      func(c *container.InspectResponse) { c.HostConfig.NetworkMode = "host" },
		"restart":      func(c *container.InspectResponse) { c.RestartCount = 1 },
		"disabled OOM": func(c *container.InspectResponse) { yes := true; c.HostConfig.OomKillDisable = &yes },
		"multi attach": func(c *container.InspectResponse) { c.Config.StdinOnce = false },
	} {
		t.Run(name, func(t *testing.T) {
			var q []container.InspectResponse
			json.Unmarshal(raw, &q)
			mutate(&q[0])
			if check(q[0], a, false) == nil {
				t.Fatal("unsafe create accepted")
			}
		})
	}
}
func TestDeliveryImageReadOnlyFixture(t *testing.T) {
	path := os.Getenv("CONTROL_DELIVERY_INPUT")
	if path == "" {
		t.Skip("explicit daemon fixture")
	}
	a, e := load(t.Context(), path)
	if e != nil {
		t.Fatal("input", e)
	}
	defer clear(a.key)
	cli, e := client.New(client.WithHost(a.input.Host), client.WithAPIVersionNegotiation())
	if e != nil {
		t.Fatal(e)
	}
	defer cli.Close()
	if _, e = inspect(t.Context(), cli, a, false); e != nil {
		t.Fatal("created daemon/image chain", e)
	}
}
func TestOperatorRejectsNoContext(t *testing.T) {
	if _, e := Run(nil, "unread"); !errors.Is(e, controldelivery.ErrUnavailable) {
		t.Fatal(e)
	}
}

func TestSourceDaemonIdentityFixture(t *testing.T) {
	input, inspectPath, backPath := os.Getenv("CONTROL_SOURCE_OPERATOR_INPUT"), os.Getenv("CONTROL_SOURCE_OPERATOR_INSPECT"), os.Getenv("CONTROL_SOURCE_BACK_INSPECT")
	if input == "" || inspectPath == "" || backPath == "" {
		t.Skip("explicit real source observation")
	}
	a, e := load(t.Context(), input)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(a.key)
	raw, e := os.ReadFile(inspectPath)
	if e != nil {
		t.Fatal(e)
	}
	backRaw, e := os.ReadFile(backPath)
	if e != nil {
		t.Fatal(e)
	}
	var all []container.InspectResponse
	var back []volume.Volume
	if json.Unmarshal(raw, &all) != nil || len(all) != 1 || json.Unmarshal(backRaw, &back) != nil || len(back) != 1 {
		t.Fatal("fixture shape")
	}
	if check(all[0], a, false, back[0]) != nil {
		t.Fatal("source baseline")
	}
	for name, mutate := range map[string]func(*container.InspectResponse){
		"log exporter": func(c *container.InspectResponse) {
			c.HostConfig.LogConfig = container.LogConfig{Type: "syslog", Config: map[string]string{"syslog-address": "tcp://192.0.2.1:514"}}
		},
		"log params":      func(c *container.InspectResponse) { c.HostConfig.LogConfig.Config = map[string]string{"tag": "extra"} },
		"cpu override":    func(c *container.InspectResponse) { c.HostConfig.CPUQuota = 1000 },
		"cpuset override": func(c *container.InspectResponse) { c.HostConfig.CpusetCpus = "0" },
		"memory override": func(c *container.InspectResponse) { c.HostConfig.MemoryReservation = 1 },
		"shm override":    func(c *container.InspectResponse) { c.HostConfig.ShmSize++ },
		"oom priority":    func(c *container.InspectResponse) { c.HostConfig.OomScoreAdj = -1 },
		"unmasked proc":   func(c *container.InspectResponse) { c.HostConfig.MaskedPaths = nil },
		"writable proc":   func(c *container.InspectResponse) { c.HostConfig.ReadonlyPaths = nil },
		"device write":    func(c *container.InspectResponse) { c.HostConfig.Devices[7].CgroupPermissions = "rw" },
		"extra group":     func(c *container.InspectResponse) { c.HostConfig.GroupAdd = append(c.HostConfig.GroupAdd, "1") },
		"old process":     func(c *container.InspectResponse) { c.Config.Entrypoint = []string{"/bin/sleep"} },
		"source volume":   func(c *container.InspectResponse) { c.Mounts[0].Source += "-replacement" },
		"source identity": func(c *container.InspectResponse) {
			c.Config.Labels["sandbox-runtime.control-storage.namespace"] = "replacement"
		},
		"restart": func(c *container.InspectResponse) { c.RestartCount = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var q []container.InspectResponse
			json.Unmarshal(raw, &q)
			mutate(&q[0])
			if check(q[0], a, false, back[0]) == nil {
				t.Fatal("unsafe source config")
			}
		})
	}
	v := back[0]
	v.Options = map[string]string{"device": "/dev/loop0"}
	if check(all[0], a, false, v) == nil {
		t.Fatal("wrong backing")
	}
}
