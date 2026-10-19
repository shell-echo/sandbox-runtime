package phase6security

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

func testControlBootstrap(t *testing.T) ProfileV2 {
	t.Helper()
	p := testControlSourceProfile(t, strings.Repeat("a", 32), "", "", testDigest("seal"))
	b := &ControlOperatorBootstrapV1{Protocol: ControlBootstrapProtocol, Target: ControlBootstrapTarget, KeyID: "operator-v1", KeyDigest: testDigest("public-key"), PublicKeyFD: 3, PinSource: "independently-provisioned-executable", ObservationProtocol: ControlOperatorObservationProtocol, MaxObservationSeconds: 120}
	for n, target := range p.controlServiceTargets() {
		l := ControlServiceLaunchV1{Deployment: n, Target: target, SourceRevision: strings.Repeat("a", 40), SourceTreeDigest: testDigest("tree"), ExecutableDigest: testDigest(target)}
		if target != "core" {
			l.LoaderDigest = testDigest("loader")
		}
		b.Launches = append(b.Launches, l)
	}
	sort.Slice(b.Launches, func(i, j int) bool { return b.Launches[i].Deployment < b.Launches[j].Deployment })
	p.DockerControl.OperatorBootstrap = b
	p.ProfileDigest = p.Digest()
	return p
}
func TestControlBootstrapDeclarationPreservesHolds(t *testing.T) {
	p := testControlBootstrap(t)
	data, _ := json.Marshal(p)
	r, e := ReviewControlBootstrap(data)
	if e != nil || r.Admission != "held-not-a-permit" || len(r.Services) != 8 {
		t.Fatal("complete declaration", e)
	}
	for _, s := range r.Services {
		if s.Launch.Target == "core" {
			if len(s.Args) != 4 || len(s.ProcessArgs) != 5 {
				t.Fatal("core argv")
			}
		} else if len(s.Entrypoint) != 3 || len(s.Args) != 0 || len(s.ProcessArgs) != 1 {
			t.Fatal("fixed loader")
		}
	}
	if p.Validate() == nil {
		t.Fatal("public hold removed")
	}
	if _, e := DecodeV2(data); e == nil {
		t.Fatal("decoder hold removed")
	}
	old := testControlSourceProfile(t, strings.Repeat("a", 32), "", "", testDigest("seal"))
	b, _ := json.Marshal(old)
	if bytes.Contains(b, []byte("operator_bootstrap")) {
		t.Fatal("legacy bytes changed")
	}
	if _, e := ReviewControlBootstrap(b); e == nil {
		t.Fatal("undeclared bootstrap")
	}
	for name, mutate := range map[string]func(*ProfileV2){
		"same envelope root": func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.PinSource = "loader-envelope" },
		"different fd":       func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.PublicKeyFD = 4 },
		"legacy target":      func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.Target = "workload-tls-agent" },
		"missing service": func(v *ProfileV2) {
			v.DockerControl.OperatorBootstrap.Launches = v.DockerControl.OperatorBootstrap.Launches[1:]
		},
		"duplicate service": func(v *ProfileV2) {
			v.DockerControl.OperatorBootstrap.Launches[1] = v.DockerControl.OperatorBootstrap.Launches[0]
		},
		"unknown target":           func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.Launches[0].Target = "arbitrary" },
		"missing bytes":            func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.Launches[0].ExecutableDigest = "" },
		"missing source":           func(v *ProfileV2) { v.DockerControl.OperatorBootstrap.Launches[0].SourceTreeDigest = "" },
		"unrelated boundary drift": func(v *ProfileV2) { v.ProviderDatabases = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			_ = json.Unmarshal(data, &q)
			mutate(&q)
			q.ProfileDigest = q.Digest()
			b, _ := json.Marshal(q)
			if _, e := ReviewControlBootstrap(b); e == nil {
				t.Fatal("accepted invalid declaration")
			}
		})
	}
	if _, e := ReviewControlBootstrap(append(data, '\n')); e == nil {
		t.Fatal("noncanonical")
	}
}

// Private operator fixture only; emitted claims remain held and synthetic.
func TestControlBootstrapFixture(t *testing.T) {
	if os.Getenv("CONTROL_BOOTSTRAP_FIXTURE") != "1" {
		t.Skip("explicit private fixture")
	}
	p := testControlBootstrap(t)
	if path := os.Getenv("CONTROL_BOOTSTRAP_BASE_PROFILE"); path != "" {
		raw, e := os.ReadFile(path)
		if e != nil || json.Unmarshal(raw, &p) != nil {
			t.Fatal("base profile", e)
		}
		p.DockerControl.OperatorBootstrap = &ControlOperatorBootstrapV1{}
	}
	b, e := os.ReadFile(os.Getenv("CONTROL_BOOTSTRAP_DECLARATION"))
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(b, p.DockerControl.OperatorBootstrap) != nil {
		t.Fatal("declaration")
	}
	if path := os.Getenv("CONTROL_BOOTSTRAP_IMAGES"); path != "" {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var images map[string]struct{ Index, Manifest, Config string }
		if json.Unmarshal(raw, &images) != nil {
			t.Fatal("image map")
		}
		for i := range p.Principals {
			c := &p.Principals[i]
			target := p.controlServiceTargets()[c.Name]
			if target == "" {
				continue
			}
			v, ok := images[target]
			if !ok {
				t.Fatal("missing image")
			}
			c.ImageLocation = "local"
			c.ImageIdentityKind = ImageIdentityOCIIndex
			c.ImageDigest = v.Index
			c.ImageReference = v.Index
			c.ImageSelectedManifestDigest = v.Manifest
			c.ImageConfigDigest = v.Config
			if c.Name == p.DockerControl.Deployment {
				a := p.DockerControl.SourceAccess
				a.Intent, e = NewControlSourceIntentV1(a.Intent.Namespace, *c, a.Intent.SocketSource)
				if e != nil {
					t.Fatal(e)
				}
				a.IntentDigest, e = a.Intent.Digest()
				if e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	if p.controlTrustDirectories() {
		testControlTrustDirectories(&p, os.Getenv("CONTROL_TRUST_BUNDLE_DIGEST"))
	}
	p.ProfileDigest = p.Digest()
	b, _ = json.Marshal(p)
	r, e := ReviewControlBootstrap(b)
	if e != nil {
		t.Fatal(e)
	}
	for path, data := range map[string][]byte{os.Getenv("CONTROL_BOOTSTRAP_PROFILE"): b, os.Getenv("CONTROL_BOOTSTRAP_REVIEW"): mustBootstrapJSON(t, r)} {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write(data)
		ce := f.Close()
		if e != nil || ce != nil {
			t.Fatal("write fixture")
		}
	}
}
func mustBootstrapJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
