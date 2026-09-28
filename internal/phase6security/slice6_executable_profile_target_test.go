package phase6security

import "testing"

func TestSlice6ExecutableProfileTargetBindsAllPhysicalDependencies(t *testing.T) {
	draft := validProfile()
	if err := draft.Validate(); err != nil {
		t.Fatalf("base fixture invalid: %v", err)
	}
	if VerifySlice6DesiredExecutableExternalProfile(draft) == nil {
		t.Fatal("partial 17/12 graph admitted as the executable target")
	}
	target, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatalf("complete external target could not be built: %v", err)
	}
	if err := VerifySlice6DesiredExecutableExternalProfile(target); err != nil {
		t.Fatalf("complete target rejected: %v", err)
	}
	if len(target.Networks) != len(Slice6DesiredNetworks())+27 ||
		len(target.TrustEdges) != len(slice6DesiredTrustEdges())+16 {
		t.Fatalf("incomplete target: %d networks, %d trust edges", len(target.Networks), len(target.TrustEdges))
	}
	if len(draft.Networks) == len(target.Networks) || len(draft.TrustEdges) == len(target.TrustEdges) {
		t.Fatal("construction mutated the input draft")
	}
	for _, mutation := range []struct {
		name   string
		change func(*Profile)
	}{
		{"remove bridge", func(p *Profile) { p.Networks = p.Networks[1:] }},
		{"share Vault material bridge", func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "service-browser-agent-vault" {
					p.Networks[index].Principals = []string{"browser-agent", "desktop-agent"}
				}
			}
		}},
		{"swap agent Vault edge", func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == "browser-agent-vault" {
					p.TrustEdges[index].From = "desktop-agent"
				}
			}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := target
			changed.Networks = append([]Network(nil), target.Networks...)
			changed.TrustEdges = append([]TrustEdge(nil), target.TrustEdges...)
			mutation.change(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6DesiredExecutableExternalProfile(changed) == nil {
				t.Fatal("unsafe complete target mutation admitted")
			}
		})
	}
}
