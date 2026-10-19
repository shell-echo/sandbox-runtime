package phase6security

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControlConsumerBoundaryProjectionAndHold(t *testing.T) {
	p := testControlSourceProfile(t, strings.Repeat("b", 32), "", "", testDigest("seal"))
	data, _ := json.Marshal(p)
	b, e := ReviewControlConsumerBoundary(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Consumers) != 19 || len(b.Anchors) != 2 || len(b.ExcludedAnchors) != 3 || len(b.Endpoints) != 3 || b.TLSAgent.AgentDeployment != "provider-docker-control-tls-agent" {
		t.Fatal("derived boundary", len(b.Consumers), b.ExcludedAnchors)
	}
	for _, c := range b.Consumers {
		mounts := b.Mounts(c)
		switch c.Name {
		case "provider-docker-control":
			if len(mounts) != 7 {
				t.Fatal(c.Name)
			}
		case b.TLSAgent.AgentDeployment:
			if len(mounts) != 1 || mounts[0].ReadOnly {
				t.Fatal("single socket writer")
			}
		default:
			if len(mounts) != 2 || !mounts[0].ReadOnly || !mounts[1].ReadOnly {
				t.Fatal("exact CA readers", c.Name)
			}
		}
	}
	if p.Validate() == nil {
		t.Fatal("public hold")
	}
	for _, a := range p.TrustAnchors {
		if a.ID == "internal-client-ca" && len(a.Consumers) < 2 {
			t.Fatal("missing cross role consumers")
		}
	}
	p.TrustAnchors[0].Consumers = append(p.TrustAnchors[0].Consumers, "undeclared")
	p.ProfileDigest = p.Digest()
	data, _ = json.Marshal(p)
	if _, e := ReviewControlConsumerBoundary(data); e == nil {
		t.Fatal("unbound consumer")
	}
}
