package phase6security

import (
	"slices"
	"sort"
)

type slice6AnchorSpec struct {
	id, purpose, artifactID, storageID, targetPath string
	consumers                                      []string
}

var slice6DesiredAnchors = []slice6AnchorSpec{
	{"external-server-ca", "server_verification", "external-server-ca-artifact", "external-server-ca-storage", "/run/trust/external-server-ca.pem",
		[]string{"browser-action-ingress-runtime", "certificate-controller", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime"}},
	{"internal-client-ca", "client_verification", "internal-client-ca-artifact", "internal-client-ca-storage", "/run/trust/internal-client-ca.pem",
		[]string{"browser-action-ingress-runtime", "browser-executor-backend", "browser-runtime-role", "desktop-executor-backend", "desktop-runtime-role", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "guest-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime", "provider-runtime"}},
	{"internal-server-ca", "server_verification", "internal-server-ca-artifact", "internal-server-ca-storage", "/run/trust/internal-server-ca.pem",
		[]string{"browser-action-ingress-runtime", "browser-executor-backend", "browser-runtime-role", "desktop-executor-backend", "desktop-runtime-role", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "guest-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime", "provider-runtime"}},
	{"postgres-client-ca", "client_verification", "postgres-client-ca-artifact", "postgres-client-ca-storage", "/run/trust/postgres-client-ca.pem",
		[]string{"gateway-runtime", "product-migration-job", "product-runtime", "provider-browser-migration-job", "provider-browser-runtime", "provider-desktop-migration-job", "provider-desktop-runtime", "provider-migration-job", "provider-runtime"}},
	{"vault-client-ca", "client_verification", "vault-client-ca-artifact", "vault-client-ca-storage", "/run/trust/vault-client-ca.pem",
		[]string{"certificate-controller"}},
}

// VerifySlice6DesiredTrustAnchors freezes the reviewed bundle ownership and
// consumer boundary. Bundle digests must instead be bound to observed CA bytes
// during controlled bootstrap; this function cannot attest those bytes.
func VerifySlice6DesiredTrustAnchors(profile Profile) error {
	return verifySlice6TrustAnchors(profile, slice6DesiredAnchors)
}

// VerifySlice6DesiredFinalTrustAnchors also freezes the Vault and external
// server roots needed by every direct dialer in the final 30-path graph.
func VerifySlice6DesiredFinalTrustAnchors(profile Profile) error {
	return verifySlice6TrustAnchors(profile, slice6FinalAnchorSpecs())
}

// Slice6DesiredFinalTrustAnchorTemplates returns the reviewed anchor and
// consumer inventory without inventing CA bytes or bundle digests. A
// bootstrap builder must bind each digest to checked operator-owned bytes
// before the resulting profile can be verified or launched.
func Slice6DesiredFinalTrustAnchorTemplates() []TrustAnchor {
	specs := slice6FinalAnchorSpecs()
	result := make([]TrustAnchor, 0, len(specs))
	for _, spec := range specs {
		result = append(result, TrustAnchor{ID: spec.id, Purpose: spec.purpose,
			TrustDomain: "sandbox-runtime.test", ArtifactID: spec.artifactID,
			StorageID: spec.storageID, TargetPath: spec.targetPath,
			WriterAuthority: "operator", Consumers: append([]string(nil), spec.consumers...)})
	}
	return result
}

func slice6FinalAnchorSpecs() []slice6AnchorSpec {
	expected := make([]slice6AnchorSpec, len(slice6DesiredAnchors))
	copy(expected, slice6DesiredAnchors)
	for i := range expected {
		expected[i].consumers = append([]string(nil), expected[i].consumers...)
		for _, dependency := range append(Slice6RequiredDirectExternalDependencies(), Slice6ProviderMigrationExternalDependencies()...) {
			if expected[i].id != "external-server-ca" &&
				(expected[i].id != "vault-client-ca" || dependency.Service != "vault") {
				continue
			}
			if !slices.Contains(expected[i].consumers, dependency.Dialer) {
				expected[i].consumers = append(expected[i].consumers, dependency.Dialer)
			}
		}
		sort.Strings(expected[i].consumers)
	}
	return expected
}

func verifySlice6TrustAnchors(profile Profile, expected []slice6AnchorSpec) error {
	if profile.Validate() != nil || len(profile.TrustAnchors) != len(expected) {
		return errSlice6DesiredInventory
	}
	for index, anchor := range profile.TrustAnchors {
		want := expected[index]
		if anchor.ID != want.id || anchor.Purpose != want.purpose ||
			anchor.TrustDomain != "sandbox-runtime.test" || anchor.ArtifactID != want.artifactID ||
			anchor.StorageID != want.storageID || anchor.TargetPath != want.targetPath ||
			anchor.WriterAuthority != "operator" || anchor.OwnerUID != 0 || anchor.OwnerGID != 0 ||
			!slices.Equal(anchor.Consumers, want.consumers) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
