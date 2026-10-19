package controldelivery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/controlbootstrap"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"testing"
)

func TestSignatureDomainChallengeAndHostObservation(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Challenge{Protocol: Protocol, Scope: Scope, Challenge: "fresh", Startup: phase6fdloader.StartupBinding{Target: phase6fdloader.ControlDeliveryTarget}}
	raw, _ := json.Marshal(c)
	r := Reply{Protocol: Protocol, Scope: Scope, ChallengeDigest: Digest(raw), OperatorObservationDigest: Digest([]byte("independent"))}
	b, e := SigningBytes(c, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Signature = ed25519.Sign(key, b)
	if !ed25519.Verify(pub, b, r.Signature) {
		t.Fatal("signature")
	}
	r.OperatorObservationDigest = Digest([]byte("replacement"))
	changed, e := SigningBytes(c, r)
	if e != nil || ed25519.Verify(pub, changed, r.Signature) {
		t.Fatal("host observation not bound")
	}
	c.Challenge = "replay in another session"
	if _, e := SigningBytes(c, r); e == nil {
		t.Fatal("challenge not bound")
	}
	r.Scope = "store-admission"
	if _, e := SigningBytes(c, r); e == nil {
		t.Fatal("domain")
	}
	var zero controlbootstrap.Credential
	if zero.VerifySignature(b, r.Signature) {
		t.Fatal("fabricated credential")
	}
	if _, e := zero.Review(); e == nil {
		t.Fatal("fabricated review")
	}
}

func TestSourceSignatureBindsEveryPhysicalObservationAndSeparatesScopes(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := Digest([]byte("source"))
	c := Challenge{Protocol: SourceProtocol, Scope: SourceScope, ProfileBytesDigest: d, Startup: phase6fdloader.StartupBinding{Target: phase6fdloader.ControlSourceTarget}, Source: &phase6process.SourceObservation{Protocol: SourceProtocol, ProfileBytesDigest: d, Namespace: "local", Intent: d, Seal: d, Root: d, Volumes: d, Inventory: d, ProcessSession: d}}
	reply := func(c Challenge) Reply {
		raw, _ := json.Marshal(c)
		return Reply{Protocol: c.Protocol, Scope: c.Scope, ChallengeDigest: Digest(raw), OperatorObservationDigest: Digest([]byte("host"))}
	}
	r := reply(c)
	b, e := SigningBytes(c, r)
	if e != nil {
		t.Fatal(e)
	}
	signature := ed25519.Sign(key, b)
	for name, mutate := range map[string]func(*Challenge){
		"root":      func(q *Challenge) { q.Source.Root = Digest([]byte("new")) },
		"volumes":   func(q *Challenge) { q.Source.Volumes = Digest([]byte("new")) },
		"inventory": func(q *Challenge) { q.Source.Inventory = Digest([]byte("new")) },
		"session":   func(q *Challenge) { q.Source.ProcessSession = Digest([]byte("new")) },
		"seal":      func(q *Challenge) { q.Source.Seal = Digest([]byte("new")) },
		"namespace": func(q *Challenge) { q.Source.Namespace = "replacement" },
		"run":       func(q *Challenge) { q.Startup.RunID = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			q := c
			s := *c.Source
			q.Source = &s
			mutate(&q)
			b, e := SigningBytes(q, reply(q))
			if e != nil || ed25519.Verify(pub, b, signature) {
				t.Fatal("unbound source", e)
			}
		})
	}
	q := c
	q.Source = nil
	if _, e := SigningBytes(q, reply(q)); e == nil {
		t.Fatal("missing source")
	}
	q = c
	q.Protocol = Protocol
	q.Scope = Scope
	q.Startup.Target = phase6fdloader.ControlDeliveryTarget
	if _, e := SigningBytes(q, reply(q)); e == nil {
		t.Fatal("source in old domain")
	}
	q.Source = nil
	b, e = SigningBytes(q, reply(q))
	if e != nil || ed25519.Verify(pub, b, signature) {
		t.Fatal("scope crossed")
	}
	r.Protocol = Protocol
	r.Scope = Scope
	if _, e := SigningBytes(c, r); e == nil {
		t.Fatal("old reply")
	}
}
