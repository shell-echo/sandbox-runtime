package phase6security

import "slices"

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
		[]string{"provider-browser-runtime", "provider-desktop-runtime"}},
	{"vault-client-ca", "client_verification", "vault-client-ca-artifact", "vault-client-ca-storage", "/run/trust/vault-client-ca.pem",
		[]string{"certificate-controller"}},
}

// VerifySlice6DesiredTrustAnchors freezes the reviewed bundle ownership and
// consumer boundary. Bundle digests must instead be bound to observed CA bytes
// during controlled bootstrap; this function cannot attest those bytes.
func VerifySlice6DesiredTrustAnchors(profile Profile) error {
	if profile.Validate() != nil || len(profile.TrustAnchors) != len(slice6DesiredAnchors) {
		return errSlice6DesiredInventory
	}
	for index, anchor := range profile.TrustAnchors {
		expected := slice6DesiredAnchors[index]
		if anchor.ID != expected.id || anchor.Purpose != expected.purpose ||
			anchor.TrustDomain != "sandbox-runtime.test" || anchor.ArtifactID != expected.artifactID ||
			anchor.StorageID != expected.storageID || anchor.TargetPath != expected.targetPath ||
			anchor.WriterAuthority != "operator" || anchor.OwnerUID != 0 || anchor.OwnerGID != 0 ||
			!slices.Equal(anchor.Consumers, expected.consumers) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
