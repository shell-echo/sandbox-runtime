package phase6security

import "testing"

func TestTrustAnchorRegistryRejectsDriftAndWrongDirection(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing anchor":   func(p *Profile) { p.TrustAnchors = p.TrustAnchors[1:] },
		"duplicate anchor": func(p *Profile) { p.TrustAnchors = append(p.TrustAnchors, p.TrustAnchors[len(p.TrustAnchors)-1]) },
		"bundle drift":     func(p *Profile) { p.TrustAnchors[0].BundleDigest = "sha256:wrong" },
		"purpose swap":     func(p *Profile) { p.TrustAnchors[1].Purpose = "server_verification" },
		"domain swap":      func(p *Profile) { p.TrustAnchors[0].TrustDomain = "other.example.test" },
		"writable source": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "product-runtime" {
					for j := range p.Principals[i].Mounts {
						if p.Principals[i].Mounts[j].Kind == "trust_anchor" {
							p.Principals[i].Mounts[j].ReadOnly = false
						}
					}
				}
			}
		},
		"extra consumer": func(p *Profile) {
			p.TrustAnchors[0].Consumers = append(p.TrustAnchors[0].Consumers, "provider-runtime")
		},
		"wrong client anchor": func(p *Profile) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == "executor-browser" {
					p.TrustEdges[i].ClientAnchorID = "internal-server-ca"
				}
			}
		},
		"missing bootstrap anchor": func(p *Profile) { p.CertificateController.BootstrapClientAnchorID = "" },
		"server CA as bootstrap":   func(p *Profile) { p.CertificateController.BootstrapClientAnchorID = "external-server-ca" },
		"unix CA injection": func(p *Profile) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].Protocol == "unix" {
					p.TrustEdges[i].ServerAnchorID = "external-server-ca"
					break
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("trust-anchor drift accepted")
			}
		})
	}
}
