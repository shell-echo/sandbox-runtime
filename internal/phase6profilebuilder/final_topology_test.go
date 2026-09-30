package phase6profilebuilder

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6ExternalSupply() ExternalImageSupply {
	const platform = "linux/arm64/v8"
	supply := ExternalImageSupply{platform: platform,
		bindings: make(map[string]ImageBinding), descriptorProofs: make(map[string]string)}
	for name, reference := range map[string]string{
		"action-history-postgres": slice6PostgresImage,
		"capacity-valkey":         slice6ValkeyImage, "dns": slice6DNSImage,
		"postgres": slice6PostgresImage, "vault": slice6VaultImage,
	} {
		supply.bindings[name] = ImageBinding{Reference: reference,
			Digest: reference[strings.LastIndexByte(reference, '@')+1:], Location: "registry",
			Kind: phase6security.ImageIdentityOCIIndex, Platform: platform,
			SelectedManifestDigest: "sha256:" + strings.Repeat("a", 64),
			ConfigDigest:           "sha256:" + strings.Repeat("b", 64)}
		supply.descriptorProofs[name] = "sha256:" + strings.Repeat("c", 64)
	}
	return supply
}

func testSlice6TrustDraft(t *testing.T) TrustDraft {
	t.Helper()
	now := time.Now().UTC()
	anchors, err := LoadSlice6TrustAnchorSupply(testSlice6TrustFiles(t, now), now)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSlice6TrustAnchorDraft(testSlice6ResourceDraft(t), anchors, now)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestSlice6FinalTopologyDraftBindsReviewed32PathsAnd37Edges(t *testing.T) {
	before := testSlice6TrustDraft(t)
	supply := testSlice6ExternalSupply()
	bound, err := bindSlice6FinalTopologyDraft(before, supply)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.External) != 5 || len(bound.TrustEdges) != 152 ||
		phase6security.VerifySlice6DesiredFinalNetworks(bound.Networks) != nil {
		t.Fatalf("final desired topology incomplete: %d services, %d edges", len(bound.External), len(bound.TrustEdges))
	}
	if bound.VerifySources(context.Background(), time.Now().UTC()) == nil {
		t.Fatal("synthetic image/resource or unverified OCI sources admitted at final freeze")
	}
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		serviceFound, dialerFound := false, false
		for _, service := range bound.External {
			if service.Name == path.Service {
				serviceFound = slices.Contains(service.Networks, path.Network)
				for _, edgeID := range path.EdgeIDs {
					serviceFound = serviceFound && slices.Contains(service.IngressEdges, edgeID)
				}
			}
		}
		for _, principal := range bound.Principals {
			if principal.Name == path.Dialer {
				dialerFound = slices.Contains(principal.Networks, path.Network)
			}
		}
		if !serviceFound || !dialerFound {
			t.Fatalf("unbound physical path %s", path.Network)
		}
	}
	if !slices.EqualFunc(before.Networks, phase6security.Slice6DesiredNetworks(),
		func(a, b phase6security.Network) bool { return a.Name == b.Name && a.IPv4Subnet == b.IPv4Subnet }) {
		t.Fatal("builder mutated source draft networks")
	}
	changed := before
	changed.Principals = append([]phase6security.Principal(nil), before.Principals...)
	changed.Principals[0].TLS = nil
	if _, err := bindSlice6FinalTopologyDraft(changed, supply); err == nil {
		t.Fatal("TLS identity drift admitted")
	}
	changed = before
	changed.Principals = append([]phase6security.Principal(nil), before.Principals...)
	changed.Principals[0].Mounts = append(slices.Clone(changed.Principals[0].Mounts),
		phase6security.Mount{Kind: "trust_anchor", Target: "/run/trust/unreviewed.pem",
			StorageID: "unreviewed", ReadOnly: true})
	if _, err := bindSlice6FinalTopologyDraft(changed, supply); err == nil {
		t.Fatal("unreviewed CA mount admitted")
	}
	changed = before
	changed.Networks = slices.Clone(before.Networks)
	changed.Networks[0].IPv4Subnet = "172.31.250.0/24"
	if _, err := bindSlice6FinalTopologyDraft(changed, supply); err == nil {
		t.Fatal("IPAM drift admitted")
	}
	if _, err := BindSlice6FinalTopologyDraft(context.Background(), before, supply, time.Now()); err == nil {
		t.Fatal("unverified OCI source admitted by public binder")
	}
}
