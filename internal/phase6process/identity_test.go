package phase6process

import (
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"testing"
)

func TestIdentityRequiresBytesCredentialsAndLoaderSeparation(t *testing.T) {
	s := phase6security.ControlServiceIdentityV1{Principal: phase6security.Principal{UID: 501, GID: 502}, Launch: phase6security.ControlServiceLaunchV1{ExecutableDigest: "sha256:role", LoaderDigest: "sha256:loader"}, ProcessArgs: []string{phase6fdloader.RolePath}, Groups: []uint32{502}}
	o := Observation{Executable: phase6fdloader.RolePath, Digest: s.Launch.ExecutableDigest, Inode: 3, StartTicks: 8, Args: s.ProcessArgs, UIDs: []uint32{501, 501, 501, 501}, GIDs: []uint32{502, 502, 502, 502}, Groups: s.Groups, NamespacePIDs: []uint32{1}, Capabilities: []uint64{0, 0, 0, 0, 0}, NoNewPrivileges: 1, Seccomp: 2}
	if Verify(o, s, "role") != nil {
		t.Fatal("matching role")
	}
	raw, _ := json.Marshal(o)
	for name, change := range map[string]func(*Observation){"same argv different bytes": func(v *Observation) { v.Digest = "sha256:other" }, "saved root": func(v *Observation) { v.UIDs[2] = 0 }, "extra group": func(v *Observation) { v.Groups = append(v.Groups, 0) }, "PID reuse": func(v *Observation) { v.StartTicks = 0 }, "child": func(v *Observation) { v.NamespacePIDs = []uint32{2} }, "capability": func(v *Observation) { v.Capabilities[3] = 1 }, "wrong args": func(v *Observation) { v.Args = append(v.Args, "extra") }, "seccomp absent": func(v *Observation) { v.Seccomp = 0 }} {
		t.Run(name, func(t *testing.T) {
			var q Observation
			_ = json.Unmarshal(raw, &q)
			change(&q)
			if Verify(q, s, "role") == nil {
				t.Fatal("identity drift accepted")
			}
		})
	}
	o.Executable = phase6fdloader.LoaderPath
	o.Args = []string{o.Executable}
	o.Digest = s.Launch.LoaderDigest
	if Verify(o, s, "loader") != nil {
		t.Fatal("loader identity")
	}
	if Verify(o, s, "role") == nil {
		t.Fatal("loader counted as role")
	}
}
