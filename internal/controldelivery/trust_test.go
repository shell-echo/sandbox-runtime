package controldelivery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
)

func trustChallenge() Challenge {
	d := "sha256:" + strings.Repeat("a", 64)
	v := &phase6process.TrustObservation{}
	for i, id := range []string{"internal-client-ca", "internal-server-ca"} {
		v.Anchors = append(v.Anchors, phase6process.AnchorObservation{ID: id, StorageID: id + "-storage", VolumeDigest: d, Artifact: trustanchor.DirectoryObservation{BundleDigest: d, Directory: trustanchor.FileIdentity{Device: 1, Inode: uint64(i + 1), Mode: 0555, Size: 4096}, File: trustanchor.FileIdentity{Device: 1, Inode: uint64(i + 11), Mode: 0444, Size: 512}, MountID: uint64(i + 101)}})
	}
	return Challenge{Protocol: TrustProtocol, Scope: TrustScope, ProfileBytesDigest: d, Startup: phase6fdloader.StartupBinding{Target: phase6fdloader.ControlTrustTarget}, Source: &phase6process.SourceObservation{Protocol: TrustProtocol, ProfileBytesDigest: d, Namespace: "local", Intent: d, Seal: d, Root: d, Volumes: d, Inventory: d, ProcessSession: d, Trust: v}}
}

func TestTrustSigningBindsBothArtifactsAndRejectsOlderScope(t *testing.T) {
	c := trustChallenge()
	raw, _ := json.Marshal(c)
	r := Reply{Protocol: TrustProtocol, Scope: TrustScope, ChallengeDigest: Digest(raw), OperatorObservationDigest: Digest([]byte("host"))}
	wire, err := SigningBytes(c, r)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, wire)
	for name, mutate := range map[string]func(*Challenge){
		"file inode":      func(c *Challenge) { c.Source.Trust.Anchors[0].Artifact.File.Inode++ },
		"directory inode": func(c *Challenge) { c.Source.Trust.Anchors[1].Artifact.Directory.Inode++ },
		"mount":           func(c *Challenge) { c.Source.Trust.Anchors[0].Artifact.MountID++ },
		"volume":          func(c *Challenge) { c.Source.Trust.Anchors[1].VolumeDigest = Digest([]byte("other")) },
		"bytes":           func(c *Challenge) { c.Source.Trust.Anchors[0].Artifact.BundleDigest = Digest([]byte("other")) },
		"missing":         func(c *Challenge) { c.Source.Trust = nil },
		"duplicate":       func(c *Challenge) { c.Source.Trust.Anchors[1] = c.Source.Trust.Anchors[0] },
		"writable":        func(c *Challenge) { c.Source.Trust.Anchors[0].Artifact.File.Mode = 0644 },
		"old source domain": func(c *Challenge) {
			c.Protocol = SourceProtocol
			c.Scope = SourceScope
			c.Startup.Target = phase6fdloader.ControlSourceTarget
			c.Source.Protocol = SourceProtocol
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed Challenge
			_ = json.Unmarshal(raw, &changed)
			mutate(&changed)
			b, _ := json.Marshal(changed)
			reply := r
			reply.Protocol = changed.Protocol
			reply.Scope = changed.Scope
			reply.ChallengeDigest = Digest(b)
			actual, e := SigningBytes(changed, reply)
			if e == nil && ed25519.Verify(pub, actual, sig) {
				t.Fatal("altered physical evidence retained signature")
			}
		})
	}
	old := c
	old.Protocol = SourceProtocol
	old.Scope = SourceScope
	old.Startup.Target = phase6fdloader.ControlSourceTarget
	old.Source.Protocol = SourceProtocol
	if sourceShape(old) {
		t.Fatal("source-only accepted trust proof")
	}
}
