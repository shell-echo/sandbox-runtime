package phase6security

import (
	"slices"
	"strings"
	"testing"
)

func TestCanonicalRuntimeEdgesAreCompleteAndExact(t *testing.T) {
	for _, spec := range requiredRuntimeEdges {
		t.Run(spec.id+"/missing", func(t *testing.T) {
			profile := validProfile()
			profile.TrustEdges = slices.DeleteFunc(profile.TrustEdges, func(edge TrustEdge) bool {
				return edge.ID == spec.id
			})
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("missing approved runtime edge accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Profile){
		"undeclared Browser bypass network": func(profile *Profile) {
			const bypass = "gateway-provider-browser-bypass"
			for index := range profile.Principals {
				if profile.Principals[index].Name == "gateway-runtime" || profile.Principals[index].Name == "provider-browser-runtime" {
					profile.Principals[index].Networks = append(profile.Principals[index].Networks, bypass)
					slices.Sort(profile.Principals[index].Networks)
				}
			}
			profile.Networks = append(profile.Networks, Network{Name: bypass, Kind: "trust_edge", Internal: true,
				GatewayModeIPv4: "isolated", IPv4Subnet: "10.26.0.0/24", Principals: []string{"gateway-runtime", "provider-browser-runtime"}})
			slices.SortFunc(profile.Networks, func(a, b Network) int { return strings.Compare(a.Name, b.Name) })
		},
		"legacy direct Gateway Browser bypass": func(profile *Profile) {
			for _, edge := range profile.TrustEdges {
				if edge.ID != BrowserActionIngressProviderPrivateEdgeID {
					continue
				}
				edge.ID = "gateway-provider-browser-private"
				edge.From = "gateway-runtime"
				for _, principal := range profile.Principals {
					if principal.Name == "gateway-runtime" {
						edge.FromURI = principal.TLS.URI
						edge.FromPrincipalDigest = principal.PrincipalDigest
					}
				}
				profile.TrustEdges = append(profile.TrustEdges, edge)
				return
			}
		},
		"coding provider steals browser attach": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID != "provider-browser-attach" {
					continue
				}
				for _, principal := range profile.Principals {
					if principal.Name == "provider-runtime" {
						profile.TrustEdges[index].From = principal.Name
						profile.TrustEdges[index].FromURI = principal.TLS.URI
						profile.TrustEdges[index].FromPrincipalDigest = principal.PrincipalDigest
						return
					}
				}
			}
		},
		"browser provider steals desktop attach": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID != "provider-desktop-attach" {
					continue
				}
				for _, principal := range profile.Principals {
					if principal.Name == "provider-browser-runtime" {
						profile.TrustEdges[index].From = principal.Name
						profile.TrustEdges[index].FromURI = principal.TLS.URI
						profile.TrustEdges[index].FromPrincipalDigest = principal.PrincipalDigest
						return
					}
				}
			}
		},
		"guest wrong route": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == "guest-product" {
					profile.TrustEdges[index].RoutePath = "/executor"
				}
			}
		},
		"browser attach wrong target network": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == "provider-browser-attach" {
					profile.TrustEdges[index].TargetAddress = "10.18.0.3:8450"
				}
			}
		},
		"desktop attach wrong listener port": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == "provider-desktop-attach" {
					profile.TrustEdges[index].Port = 8452
					profile.TrustEdges[index].TargetAddress = "10.18.0.3:8452"
				}
			}
		},
		"guest wrong tenant scope": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == "guest-product" {
					profile.TrustEdges[index].TenantScope = "system"
				}
			}
		},
		"provider private route conflation": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == "gateway-provider-desktop-private" {
					profile.TrustEdges[index].RoutePath = "/private/terminal"
				}
			}
		},
		"browser private route conflation": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == BrowserActionIngressProviderPrivateEdgeID {
					profile.TrustEdges[index].RoutePath = "/private/terminal"
				}
			}
		},
		"action ingress private peer drift": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == BrowserActionIngressProviderPrivateEdgeID {
					profile.TrustEdges[index].FromURI = "spiffe://sandbox-runtime.test/gateway-runtime"
				}
			}
		},
		"action ingress public route drift": func(profile *Profile) {
			for index := range profile.TrustEdges {
				if profile.TrustEdges[index].ID == GatewayBrowserActionIngressEdgeID {
					profile.TrustEdges[index].RoutePath = "/private/browser"
				}
			}
		},
		"duplicate browser attach alias": func(profile *Profile) {
			for _, edge := range profile.TrustEdges {
				if edge.ID == "provider-browser-attach" {
					edge.ID = "provider-browser-attach-alias"
					profile.TrustEdges = append(profile.TrustEdges, edge)
					slices.SortFunc(profile.TrustEdges, func(a, b TrustEdge) int {
						if a.ID < b.ID {
							return -1
						}
						if a.ID > b.ID {
							return 1
						}
						return 0
					})
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("runtime edge drift accepted")
			}
		})
	}
}

func TestGuestAndAttachEdgesDeriveBothPeerCRLDirections(t *testing.T) {
	profile := validProfile()
	sources := completePeerCRLSources(t, profile)
	for _, edgeID := range []string{"guest-product", "provider-browser-attach", "provider-desktop-attach"} {
		directions := map[string]bool{}
		for _, edge := range sources.Edges {
			if edge.EdgeID == edgeID {
				directions[edge.Direction] = true
			}
		}
		if !directions["inbound"] || !directions["outbound"] || len(directions) != 2 {
			t.Fatalf("%s did not derive both peer-CRL directions: %v", edgeID, directions)
		}
	}
}

func TestProviderProfilesHaveSeparateIdentityAndSignerAuthority(t *testing.T) {
	profile := validProfile()
	seenIdentity := map[string]bool{}
	seenSocket := map[string]bool{}
	for _, name := range []string{"provider-runtime", "provider-browser-runtime", "provider-desktop-runtime"} {
		binding, agent, subject, err := profile.TLSAgentForSubject(name)
		if err != nil || subject.TLS == nil || agent.UID == subject.UID || agent.GID == subject.GID {
			t.Fatalf("%s lacks its separate TLS agent: %v", name, err)
		}
		if seenIdentity[subject.PrincipalDigest] || seenIdentity[subject.TLS.URI] ||
			seenSocket[binding.SocketPath] || seenSocket[binding.ControllerSocketPath] {
			t.Fatalf("%s reused a Provider identity or signer socket", name)
		}
		seenIdentity[subject.PrincipalDigest], seenIdentity[subject.TLS.URI] = true, true
		seenSocket[binding.SocketPath], seenSocket[binding.ControllerSocketPath] = true, true
	}
}
