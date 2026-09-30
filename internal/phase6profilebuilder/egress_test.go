package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6EgressKeys(t *testing.T) (EgressKeySupply, map[string]string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]string)
	for _, name := range phase6security.Slice6DesiredEgressAuthorityNames() {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name+".key")
		if err := os.WriteFile(path, private, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(private)
		paths[name] = path
	}
	supply, err := LoadSlice6EgressKeySupply(paths)
	if err != nil {
		t.Fatal(err)
	}
	return supply, paths
}

func TestSlice6EgressKeySupplyReopensPrivateSources(t *testing.T) {
	supply, paths := testSlice6EgressKeys(t)
	if err := supply.VerifySources(); err != nil {
		t.Fatal(err)
	}
	for _, key := range supply.keys {
		if len(key) != ed25519.PublicKeySize {
			t.Fatal("private bytes retained as public key")
		}
	}
	name := phase6security.Slice6DesiredEgressAuthorityNames()[0]
	path := paths[name]
	wrong := make(map[string]string, len(paths))
	for key, value := range paths {
		wrong[key] = value
	}
	wrong[name] = paths[phase6security.Slice6DesiredEgressAuthorityNames()[1]]
	if _, err := LoadSlice6EgressKeySupply(wrong); err == nil {
		t.Fatal("duplicate source path admitted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if supply.VerifySources() == nil {
		t.Fatal("relaxed private key mode admitted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := supply.VerifySources(); err != nil {
		t.Fatal(err)
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secret[ed25519.SeedSize] ^= 1
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if supply.VerifySources() == nil {
		t.Fatal("inconsistent private key admitted")
	}
	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(replacement)
	if supply.VerifySources() == nil {
		t.Fatal("changed private key admitted")
	}
	link := filepath.Join(filepath.Dir(path), "alias.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	wrong[name] = link
	if _, err := LoadSlice6EgressKeySupply(wrong); err == nil {
		t.Fatal("symlink key admitted")
	}
}

func TestSlice6EgressDraftBindsFiveRealKeyDigestsAndMounts(t *testing.T) {
	before, err := bindSlice6FinalTopologyDraft(testSlice6TrustDraft(t), testSlice6ExternalSupply())
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := testSlice6EgressKeys(t)
	bound, err := bindSlice6EgressDraft(before, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.EgressPolicies) != 5 || !slices.EqualFunc(bound.Principals, before.Principals,
		func(a, b phase6security.Principal) bool { return a.Name == b.Name }) {
		t.Fatal("reviewed egress inventory changed")
	}
	for _, policy := range bound.EgressPolicies {
		key := keys.keys[policy.Authority.DeploymentName]
		if policy.Authority.PublicKeyDigest != phase6security.OperatorPublicKeyDigest(key) ||
			bytes.Contains([]byte(policy.Authority.PublicKeyDigest), key) {
			t.Fatal("policy did not bind the real public key digest")
		}
		var broker, authority phase6security.Principal
		for _, principal := range bound.Principals {
			if principal.Name == policy.Broker {
				broker = principal
			}
			if principal.Name == policy.Authority.DeploymentName {
				authority = principal
			}
		}
		if len(broker.Listeners) != 1 || broker.Listeners[0].Port != 8443 ||
			!slice6MountFound(broker, "private_socket", policy.Authority.SocketDirectory,
				policy.Authority.SocketStorageID, true) ||
			!slice6MountFound(authority, "private_socket", policy.Authority.SocketDirectory,
				policy.Authority.SocketStorageID, false) ||
			!slice6MountFound(authority, "persistent_ledger", policy.Authority.LedgerMountTarget,
				policy.Authority.LedgerStorageID, false) {
			t.Fatal("egress policy mounts or listener missing")
		}
	}
	if len(before.Principals[0].Listeners) != 0 ||
		bound.VerifySources(context.Background(), time.Now()) == nil ||
		func() bool {
			_, err := BindSlice6EgressDraft(context.Background(), before, keys, time.Now())
			return err == nil
		}() {
		t.Fatal("synthetic upstream draft admitted for final freeze")
	}
	changed := before
	changed.TrustEdges = slices.Clone(before.TrustEdges)
	for index := range changed.TrustEdges {
		if changed.TrustEdges[index].From == "egress-broker-product" &&
			changed.TrustEdges[index].To == "egress-policy-authority-product" {
			changed.TrustEdges[index].Authentication = "none"
		}
	}
	if _, err := bindSlice6EgressDraft(changed, keys); err == nil {
		t.Fatal("weakened broker authority edge admitted")
	}
	changed = before
	changed.Principals = slices.Clone(before.Principals)
	for index := range changed.Principals {
		if changed.Principals[index].Name == "product-runtime" {
			changed.Principals[index].Mounts = append(slices.Clone(changed.Principals[index].Mounts),
				phase6security.Mount{Target: "/run/egress-authority", Kind: "private_socket", StorageID: "stolen"})
		}
	}
	if _, err := bindSlice6EgressDraft(changed, keys); err == nil {
		t.Fatal("unreviewed shared authority mount admitted")
	}
	changedBound := bound
	changedBound.EgressPolicies = slices.Clone(bound.EgressPolicies)
	changedBound.EgressPolicies[0].Targets = slices.Clone(bound.EgressPolicies[0].Targets)
	changedBound.EgressPolicies[0].Targets[0].Host = "alternate.example.test"
	wanted, err := phase6security.BuildSlice6DesiredEgressPolicies(changedBound.Principals, keys.publicKeys())
	if err != nil || slices.EqualFunc(changedBound.EgressPolicies, wanted,
		func(a, b phase6security.EgressPolicy) bool { return a.Digest() == b.Digest() }) {
		t.Fatal("policy target drift not detected")
	}
	changedBound = bound
	changedBound.Principals = slices.Clone(bound.Principals)
	for index := range changedBound.Principals {
		if changedBound.Principals[index].Name == "product-runtime" {
			changedBound.Principals[index].Mounts = append(slices.Clone(changedBound.Principals[index].Mounts),
				phase6security.Mount{Target: "/run/egress-authority", Kind: "private_socket", StorageID: "stolen"})
		}
	}
	if slice6BoundEgressMatches(changedBound.Principals, changedBound.TrustEdges, bound.EgressPolicies) {
		t.Fatal("post-binding authority mount drift admitted")
	}
}

func slice6MountFound(principal phase6security.Principal, kind, target, storageID string, readOnly bool) bool {
	for _, mount := range principal.Mounts {
		if mount.Kind == kind && mount.Target == target && mount.StorageID == storageID && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}
