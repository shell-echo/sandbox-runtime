package phase6security

import "testing"

func TestPublicTLSBoundaryIsExactServerOnlyException(t *testing.T) {
	profile := validProfile()
	for _, candidate := range []struct {
		id, subject string
		port        int
	}{
		{"gateway-public", "gateway-runtime", 8445},
		{"product-public", "product-runtime", 8444},
	} {
		binding, agent, subject, anchor, err := profile.PublicTLSBoundary(candidate.id, candidate.port)
		if err != nil || binding.SubjectDeployment != candidate.subject || agent.Name != binding.AgentDeployment ||
			subject.Name != candidate.subject || anchor.ID != "internal-server-ca" || anchor.Purpose != "server_verification" {
			t.Fatalf("public boundary %s: binding=%+v agent=%s subject=%s anchor=%+v err=%v",
				candidate.id, binding, agent.Name, subject.Name, anchor, err)
		}
	}
	for _, candidate := range []struct {
		id   string
		port int
	}{{"gateway-public", 8444}, {"product-public", 8445}, {"browser-public", 8443}} {
		if _, _, _, _, err := profile.PublicTLSBoundary(candidate.id, candidate.port); err == nil {
			t.Fatalf("unbound public listener accepted: %+v", candidate)
		}
	}
}

func TestPublicListenerBindingRejectsScopeAndAnchorDrift(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing":   func(p *Profile) { p.PublicListeners = p.PublicListeners[:1] },
		"duplicate": func(p *Profile) { p.PublicListeners[1] = p.PublicListeners[0] },
		"swapped deployment": func(p *Profile) {
			p.PublicListeners[0].DeploymentName = "product-runtime"
		},
		"principal digest": func(p *Profile) { p.PublicListeners[0].PrincipalDigest = testDigest("other") },
		"wrong listener":   func(p *Profile) { p.PublicListeners[0].ListenerName = "other" },
		"wrong port":       func(p *Profile) { p.PublicListeners[0].Port++ },
		"optional mTLS": func(p *Profile) {
			p.PublicListeners[0].ClientAuthentication = "verify_if_given"
		},
		"internal edge anchor": func(p *Profile) { p.PublicListeners[0].IssuerAnchorID = "internal-client-ca" },
		"undeclared public listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-runtime" {
					p.Principals[index].Listeners = append(p.Principals[index].Listeners,
						Listener{Name: "unbound", Protocol: "tcp", Port: 9443, Exposure: "public"})
				}
			}
		},
		"public UDP alias": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					p.Principals[index].Listeners = append(p.Principals[index].Listeners,
						Listener{Name: "signaling", Protocol: "udp", Port: 8445, Exposure: "public"})
				}
			}
		},
		"no server EKU": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					p.Principals[index].TLS.Usages = []string{"client_auth"}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("public TLS drift accepted")
			}
		})
	}
}
