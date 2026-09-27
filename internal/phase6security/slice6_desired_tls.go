package phase6security

import "slices"

// These are the only deployments that may present a network server leaf in
// the reviewed local candidate. The other non-template deployments have
// client-only identities; the relay and sandbox templates have no TLS key.
var slice6DesiredServerDNSNames = map[string]string{
	"product-runtime":                      "product.sandbox-runtime.test",
	"gateway-runtime":                      "gateway.sandbox-runtime.test",
	"browser-action-ingress-runtime":       "browser-action-ingress.sandbox-runtime.test",
	"provider-runtime":                     "provider-runtime.sandbox-runtime.test",
	"provider-browser-runtime":             "provider-browser-runtime.sandbox-runtime.test",
	"provider-desktop-runtime":             "provider-desktop-runtime.sandbox-runtime.test",
	"browser-runtime-role":                 "browser-runtime-role.sandbox-runtime.test",
	"desktop-runtime-role":                 "desktop-runtime-role.sandbox-runtime.test",
	"browser-executor-backend":             "browser-executor-backend.sandbox-runtime.test",
	"desktop-executor-backend":             "desktop-executor-backend.sandbox-runtime.test",
	"egress-broker-product":                "egress-broker-product.sandbox-runtime.test",
	"egress-broker-gateway":                "egress-broker-gateway.sandbox-runtime.test",
	"egress-broker-browser-action-ingress": "egress-broker-browser-action-ingress.sandbox-runtime.test",
	"egress-broker-provider-browser":       "egress-broker-provider-browser.sandbox-runtime.test",
	"egress-broker-provider-desktop":       "egress-broker-provider-desktop.sandbox-runtime.test",
}

// Slice6DesiredTLSIdentity constructs only expected leaf policy. It does not
// issue a certificate or establish possession of the corresponding key.
func Slice6DesiredTLSIdentity(deployment, principalDigest string) (*TLSIdentity, error) {
	kind, err := Slice6DesiredDeploymentKind(deployment)
	if err != nil {
		return nil, errSlice6DesiredInventory
	}
	if kind == "sandbox" || kind == "ingress_relay" {
		if kind == "sandbox" && principalDigest != "" ||
			kind == "ingress_relay" && !digestPattern.MatchString(principalDigest) {
			return nil, errSlice6DesiredInventory
		}
		return nil, nil
	}
	if !digestPattern.MatchString(principalDigest) {
		return nil, errSlice6DesiredInventory
	}
	identity := &TLSIdentity{PrincipalDigest: principalDigest, TrustDomain: "sandbox-runtime.test",
		URI: "spiffe://sandbox-runtime.test/" + deployment, Usages: []string{"client_auth"},
		TTLSeconds: 900, RotateAfterSeconds: 500, OverlapSeconds: 30,
		RevocationMaxStalenessSeconds: 30, ConnectionDrainSeconds: 10}
	if name, server := slice6DesiredServerDNSNames[deployment]; server {
		identity.DNSNames = []string{name}
		identity.Usages = []string{"client_auth", "server_auth"}
		if kind == "executor" {
			identity.Usages = []string{"server_auth"}
		}
	}
	return identity, nil
}

// VerifySlice6DesiredTLSIdentities freezes the desired SPIFFE names, SAN/EKU
// allocation and rotation/drain bounds. It does not issue or observe a leaf,
// prove its private-key owner, or replace live peer/CRL handshake checks.
func VerifySlice6DesiredTLSIdentities(profile Profile) error {
	if VerifySlice6DesiredNetworkGraph(profile) != nil {
		return errSlice6DesiredInventory
	}
	for _, principal := range profile.Principals {
		if principal.Kind == "sandbox" || principal.Kind == "ingress_relay" {
			if principal.TLS != nil {
				return errSlice6DesiredInventory
			}
			continue
		}
		identity := principal.TLS
		if identity == nil || identity.PrincipalDigest != principal.PrincipalDigest ||
			identity.TrustDomain != "sandbox-runtime.test" ||
			identity.URI != "spiffe://sandbox-runtime.test/"+principal.Name ||
			identity.TTLSeconds != 900 || identity.RotateAfterSeconds != 500 ||
			identity.OverlapSeconds != 30 || identity.RevocationMaxStalenessSeconds != 30 ||
			identity.ConnectionDrainSeconds != 10 {
			return errSlice6DesiredInventory
		}
		name, server := slice6DesiredServerDNSNames[principal.Name]
		if !server {
			if len(identity.DNSNames) != 0 || !slices.Equal(identity.Usages, []string{"client_auth"}) {
				return errSlice6DesiredInventory
			}
			continue
		}
		usages := []string{"client_auth", "server_auth"}
		if principal.Kind == "executor" {
			usages = []string{"server_auth"}
		}
		if !slices.Equal(identity.DNSNames, []string{name}) || !slices.Equal(identity.Usages, usages) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
