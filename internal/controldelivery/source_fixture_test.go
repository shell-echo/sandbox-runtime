package controldelivery

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"os"
	"testing"
	"time"
)

// Explicit negative fixture signer only. It does not perform operator observation
// and its signature must never be counted as a successful operator ceremony.
func TestSourceNegativeFixtureSignature(t *testing.T) {
	if os.Getenv("CONTROL_SOURCE_NEGATIVE_SIGN") != "1" {
		t.Skip("explicit private negative fixture")
	}
	raw, e := secretfile.Read(os.Getenv("CONTROL_SOURCE_CHALLENGE"), MaxFrame)
	if e != nil {
		t.Fatal(e)
	}
	var c Challenge
	if phase6fdloader.DecodeCanonical(raw, &c) != nil || (c.Protocol != SourceProtocol && c.Protocol != TrustProtocol) {
		t.Fatal("source challenge")
	}
	doc, e := secretfile.Read(os.Getenv("CONTROL_SOURCE_PROFILE"), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	review, e := phase6security.ReviewControlBootstrap(doc)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateChallenge(c, review, time.Now()); e != nil {
		t.Fatal(e)
	}
	key, e := secretfile.Read(os.Getenv("CONTROL_SOURCE_TEST_KEY"), 64)
	if e != nil || len(key) != 64 || Digest(key[32:]) != review.Bootstrap.KeyDigest {
		t.Fatal("test key")
	}
	defer clear(key)
	r := Reply{Protocol: c.Protocol, Scope: c.Scope, ChallengeDigest: Digest(raw), OperatorObservationDigest: Digest([]byte("NEGATIVE TEST ONLY: no operator observation"))}
	msg, e := SigningBytes(c, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Signature = ed25519.Sign(key, msg)
	out, e := os.OpenFile(os.Getenv("CONTROL_SOURCE_TEST_REPLY"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	b, _ := json.Marshal(r)
	if _, e := out.Write(b); e != nil {
		t.Fatal(e)
	}
}
