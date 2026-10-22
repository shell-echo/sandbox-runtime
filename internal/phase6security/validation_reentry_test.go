package phase6security

import (
	"slices"
	"testing"
)

// Each public entry must revalidate the current input, even after a successful
// call with that profile. The private composition helpers are not a cache or an
// admission token that a later mutation can reuse.
func TestSlice6PublicProfileVerifiersRevalidateEveryCall(t *testing.T) {
	draft := reviewedSlice6ImageFixture(t)
	planned, err := BindSlice6DesiredNetworkPlan(draft)
	if err != nil {
		t.Fatal(err)
	}
	final := validSlice6EvidenceFixture(t).Profile
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		profile Profile
		verify  func(Profile) error
	}{
		{"final gate", final, VerifySlice6FinalGateProfile},
		{"final external", final, VerifySlice6DesiredFinalExternalProfile},
		{"intermediate external", intermediate, VerifySlice6DesiredExecutableExternalProfile},
		{"external closure", final, VerifySlice6FinalExternalDependencyClosure},
		{"final anchors", final, VerifySlice6DesiredFinalTrustAnchors},
		{"draft anchors", draft, VerifySlice6DesiredTrustAnchors},
		{"egress", final, VerifySlice6DesiredEgressPolicies},
		{"TLS", final, VerifySlice6DesiredTLSIdentities},
		{"principal IDs", final, VerifySlice6DesiredPrincipalIDs},
		{"ingress", final, VerifySlice6DesiredIngress},
		{"ingress policy", final, VerifySlice6DesiredIngressPolicy},
		{"planned networks", planned, VerifySlice6DesiredNetworks},
		{"trust edges", draft, VerifySlice6DesiredTrustEdges},
		{"external services", draft, VerifySlice6DesiredExternalServices},
		{"edge addresses", planned, VerifySlice6DesiredEdgeAddresses},
		{"network binder", draft, func(p Profile) error {
			_, err := BindSlice6DesiredNetworkPlan(p)
			return err
		}},
		{"draft network graph", draft, VerifySlice6DesiredNetworkGraph},
		{"DNS CA", final, VerifySlice6DNSClientCA},
		{"DNS runtime", final, VerifySlice6DNSRuntimePolicy},
		{"images", final, VerifySlice6DesiredImageLocations},
		{"broker boundary", final, func(p Profile) error {
			_, _, _, _, err := p.BrokerBoundaryForPolicy("gateway-egress")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := test.profile
			if err := test.verify(profile); err != nil {
				t.Fatalf("valid profile rejected: %v", err)
			}
			profile.ProfileDigest = testDigest("different-profile")
			if err := test.verify(profile); err == nil {
				t.Fatal("substituted digest accepted after a successful call")
			}
			profile = test.profile
			profile.Principals = slices.Clone(profile.Principals)
			profile.Principals[0].ReadOnlyRootFilesystem = false
			profile.ProfileDigest = profile.Digest()
			if err := test.verify(profile); err == nil {
				t.Fatal("rehashed unsafe profile accepted after a successful call")
			}
			if err := test.verify(test.profile); err != nil {
				t.Fatalf("invalid call poisoned later validation: %v", err)
			}
		})
	}
}

func TestObservationValidationRechecksProfileAfterSuccessfulCall(t *testing.T) {
	profile := validProfile()
	observations := validObservations(profile)
	if err := ValidateObservations(profile, observations); err != nil {
		t.Fatal(err)
	}
	profile.Principals[0].ReadOnlyRootFilesystem = false
	profile.ProfileDigest = profile.Digest()
	observations.ProfileDigest = profile.ProfileDigest
	if err := ValidateObservations(profile, observations); err == nil {
		t.Fatal("matching observation digest authorized an unsafe profile")
	}
}
