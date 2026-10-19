package phase6security

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testControlSourceProfile(t *testing.T, ns, image, seccomp, seal string) ProfileV2 {
	t.Helper()
	p := testCodingExecutionProfile(t)
	old := p.CodingExecution.Receipt.StorageID
	p.CodingExecution.Receipt, _ = NewCodingReceiptNamespaceV3(ns)
	p.DockerControl.ReceiptStorageID = p.CodingExecution.Receipt.StorageID
	p.DockerControl.DaemonSocketPath = ControlSourceSocketTarget
	for i := range p.Principals {
		c := &p.Principals[i]
		for j := range c.Mounts {
			if c.Mounts[j].StorageID == old {
				c.Mounts[j].StorageID = p.DockerControl.ReceiptStorageID
			}
		}
		if c.Name != "provider-docker-control" {
			continue
		}
		c.UID, c.GID, c.HostDevices = 57010, 57011, true
		if image != "" {
			c.ImageLocation = "local"
			c.ImageIdentityKind = ImageIdentityOCIIndex
			c.ImageDigest = image
			c.ImageReference = image
			c.ImageConfigDigest = os.Getenv("CONTROL_SOURCE_CONFIG")
			c.ImageSelectedManifestDigest = os.Getenv("CONTROL_SOURCE_MANIFEST")
		}
		if seccomp != "" {
			c.SeccompDigest = seccomp
		}
		for j := range c.Mounts {
			if c.Mounts[j].Kind == "daemon_socket" {
				c.Mounts[j].Target = ControlSourceSocketTarget
			}
		}
		intent, e := NewControlSourceIntentV1(ns, *c, "/run/host-services/docker.proxy.sock")
		if e != nil {
			t.Fatal(e)
		}
		d, _ := intent.Digest()
		p.DockerControl.SourceAccess = &ControlSourceAccessV1{ControlSourceAccessProtocol, intent, d, seal}
		c.Mounts = append(c.Mounts, Mount{Target: intent.BackingTarget, StorageID: intent.BackingStorageID, ReadOnly: true, Kind: "control_source"})
	}
	for i := range p.TLSAgentBindings {
		if p.TLSAgentBindings[i].SubjectDeployment == "provider-docker-control" {
			p.TLSAgentBindings[i].SubjectUID = 57010
			p.TLSAgentBindings[i].SubjectGID = 57011
		}
	}
	p.ProfileDigest = p.Digest()
	return p
}

func TestControlSourceProfileCompleteReviewAndHold(t *testing.T) {
	p := testControlSourceProfile(t, strings.Repeat("a", 32), "", "", testDigest("seal"))
	data, _ := json.Marshal(p)
	if p.validateFields() != nil {
		t.Fatal("complete source fields")
	}
	r, e := ReviewControlSourceProfile(data)
	if e != nil || r.ProfileDigest != p.Digest() || len(r.Networks) != 3 || len(r.Control.Mounts) != 7 || r.Admission != "held-not-a-permit" {
		t.Fatal("review", e, len(r.Control.Mounts))
	}
	if p.Validate() == nil {
		t.Fatal("public hold")
	}
	if _, e := DecodeV2(data); e == nil {
		t.Fatal("decoder hold")
	}
	if _, e := p.CodingExecutionStorageBinding(); e == nil {
		t.Fatal("Store admission hold")
	}
	original := testCodingExecutionProfile(t)
	old, _ := json.Marshal(original)
	if bytes.Contains(old, []byte("source_access")) {
		t.Fatal("legacy encoding changed")
	}
	cases := map[string]func(*ProfileV2){
		"device write": func(v *ProfileV2) { v.DockerControl.SourceAccess.Intent.Devices[7].Permissions = "rw" },
		"device alias": func(v *ProfileV2) { v.DockerControl.SourceAccess.Intent.Devices[0].Target = "/dev/other" },
		"extra group": func(v *ProfileV2) {
			v.DockerControl.SourceAccess.Intent.Groups = append(v.DockerControl.SourceAccess.Intent.Groups, 1)
		},
		"wrong source":    func(v *ProfileV2) { v.DockerControl.SourceAccess.Intent.SocketSource = "/tmp/socket" },
		"wrong seal":      func(v *ProfileV2) { v.DockerControl.SourceAccess.SealDigest = "" },
		"stale intent":    func(v *ProfileV2) { v.DockerControl.SourceAccess.IntentDigest = testDigest("other") },
		"unrelated PG":    func(v *ProfileV2) { v.ProviderDatabases = nil },
		"unrelated graph": func(v *ProfileV2) { v.Networks = v.Networks[1:] },
		"wrong TLS UID": func(v *ProfileV2) {
			for i := range v.TLSAgentBindings {
				if v.TLSAgentBindings[i].SubjectDeployment == "provider-docker-control" {
					v.TLSAgentBindings[i].SubjectUID++
				}
			}
		},
		"source alias other role": func(v *ProfileV2) {
			v.Principals[0].Mounts = append(v.Principals[0].Mounts, Mount{Target: "/var/lib/sandbox-runtime/control-source/child", Kind: "trust_anchor", ReadOnly: true, StorageID: "alias"})
		},
		"overlap": func(v *ProfileV2) {
			for i := range v.Principals {
				if v.Principals[i].Name == "provider-docker-control" {
					v.Principals[i].Mounts = append(v.Principals[i].Mounts, Mount{Kind: "trust_anchor", ReadOnly: true, StorageID: "alias", Target: "/run"})
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			_ = json.Unmarshal(data, &q)
			mutate(&q)
			q.ProfileDigest = q.Digest()
			b, _ := json.Marshal(q)
			if _, e := ReviewControlSourceProfile(b); e == nil {
				t.Fatal("accepted drift")
			}
		})
	}
	if _, e := ReviewControlSourceProfile(append(data, '\n')); e == nil {
		t.Fatal("noncanonical")
	}
	a := p.DockerControl.SourceAccess.IntentDigest
	p.DockerControl.SourceAccess.SealDigest = testDigest("fresh seal")
	if p.Digest() == r.ProfileDigest || p.DockerControl.SourceAccess.IntentDigest != a {
		t.Fatal("digest domains")
	}
}

// Explicit operator fixture generator; synthetic role supply identities remain
// synthetic. This creates a complete declaration, not admission or release data.
func TestControlSourceProfileFixture(t *testing.T) {
	if os.Getenv("CONTROL_PROFILE_FIXTURE") != "1" {
		t.Skip("operator fixture opt-in")
	}
	p := testControlSourceProfile(t, os.Getenv("CONTROL_SOURCE_NAMESPACE"), os.Getenv("CONTROL_SOURCE_IMAGE"), os.Getenv("CONTROL_SOURCE_SECCOMP"), os.Getenv("CONTROL_SOURCE_SEAL"))
	if os.Getenv("CONTROL_BOUNDARY_FIXTURE") == "1" {
		original, _ := json.Marshal(p)
		boundary, e := ReviewControlConsumerBoundary(original)
		if e != nil {
			t.Fatal(e)
		}
		for i := range p.Principals {
			c := &p.Principals[i]
			for _, want := range boundary.Consumers {
				if c.Name == want.Name && c.Name != "provider-docker-control" {
					c.ImageLocation = "local"
					c.ImageIdentityKind = ImageIdentityOCIIndex
					c.ImageDigest = os.Getenv("CONTROL_SOURCE_IMAGE")
					c.ImageReference = c.ImageDigest
					c.ImageConfigDigest = os.Getenv("CONTROL_SOURCE_CONFIG")
					c.ImageSelectedManifestDigest = os.Getenv("CONTROL_SOURCE_MANIFEST")
					c.SeccompDigest = os.Getenv("CONTROL_SOURCE_SECCOMP")
				}
			}
		}
		p.ProfileDigest = p.Digest()
	}
	b, _ := json.Marshal(p)
	if os.Getenv("CONTROL_PROFILE_PRESEAL") == "1" {
		if _, e := p.DockerControl.SourceAccess.Intent.Digest(); e != nil {
			t.Fatal(e)
		}
		b, _ = json.Marshal(p.DockerControl.SourceAccess.Intent)
	} else if _, e := ReviewControlSourceProfile(b); e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(os.Getenv("CONTROL_PROFILE_OUTPUT"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if _, e = file.Write(b); e != nil {
		t.Fatal(e)
	}
}
