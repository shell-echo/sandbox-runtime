package phase6security

import (
	"slices"
	"strconv"
	"testing"
)

func TestSlice6MaterialAgentSignerInventoryHasElevenDistinctKeyOwners(t *testing.T) {
	wanted := map[string]string{
		"browser-action-ingress-agent-tls-agent":   "browser-action-ingress-agent",
		"browser-agent-tls-agent":                  "browser-agent",
		"desktop-agent-tls-agent":                  "desktop-agent",
		"gateway-agent-tls-agent":                  "gateway-agent",
		"guest-agent-tls-agent":                    "guest-agent",
		"product-migration-agent-tls-agent":        "product-migration-agent",
		"product-runtime-agent-tls-agent":          "product-runtime-agent",
		"provider-browser-runtime-agent-tls-agent": "provider-browser-runtime-agent",
		"provider-desktop-runtime-agent-tls-agent": "provider-desktop-runtime-agent",
		"provider-migration-agent-tls-agent":       "provider-migration-agent",
		"provider-runtime-agent-tls-agent":         "provider-runtime-agent",
	}
	profile := validProfile()
	if profile.Validate() != nil || len(wanted) != 11 {
		t.Fatal("material signer fixture is not a valid closed profile")
	}
	byName := make(map[string]Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		byName[principal.Name] = principal
	}
	bound := make(map[string]bool, len(wanted))
	for _, binding := range profile.TLSAgentBindings {
		subject, newSigner := wanted[binding.AgentDeployment]
		if !newSigner {
			continue
		}
		agent := byName[binding.AgentDeployment]
		material := byName[subject]
		if bound[binding.AgentDeployment] || binding.SubjectDeployment != subject ||
			agent.Kind != "tls_agent" || material.Kind != "material_agent" ||
			agent.PrincipalDigest == material.PrincipalDigest ||
			agent.UID == material.UID || agent.GID == material.GID ||
			binding.AgentPrincipalDigest != agent.PrincipalDigest ||
			binding.SubjectPrincipalDigest != material.PrincipalDigest ||
			slice6ApprovedTLSAgentSubjects[binding.AgentDeployment] != subject ||
			slice6DesiredImageTargets[binding.AgentDeployment] != "workload-tls-agent" {
			t.Fatalf("material-agent signer %s is not an exact independent key owner", binding.AgentDeployment)
		}
		bound[binding.AgentDeployment] = true
	}
	if len(bound) != len(wanted) {
		t.Fatalf("only %d of %d material-agent signers were bound", len(bound), len(wanted))
	}
	for agent, subject := range wanted {
		if requiredTLSAgentSubjects[agent] != subject || requiredPrincipals[agent] != "tls_agent" ||
			slice6ApprovedDeploymentKinds[agent] != "tls_agent" ||
			!slices.Contains(byName[agent].TLS.Usages, "client_auth") ||
			slices.Contains(byName[agent].TLS.Usages, "server_auth") {
			t.Fatalf("material signer %s gained a different subject or server identity", agent)
		}
	}

	changed := profile
	changed.TLSAgentBindings = append([]TLSAgentBinding(nil), profile.TLSAgentBindings...)
	for index := range changed.TLSAgentBindings {
		if changed.TLSAgentBindings[index].AgentDeployment == "gateway-agent-tls-agent" {
			changed.TLSAgentBindings[index].SubjectDeployment = "guest-agent"
			break
		}
	}
	changed.ProfileDigest = changed.Digest()
	if changed.Validate() == nil {
		t.Fatal("cross-material-agent signer substitution was admitted")
	}
}

func TestSlice6MaterialSignerIDsAndNetworksDoNotShiftOldAllocations(t *testing.T) {
	pairs := Slice6DesiredUIDGID()
	networks := Slice6DesiredNetworks()
	newCount, oldCount, addedCount := 0, 0, 0
	usedSubnets := make(map[string]bool, len(networks))
	baseNetworks := make([]string, 0, len(networks))
	materialNetworks := make([]string, 0, 11)
	for _, network := range networks {
		if usedSubnets[network.IPv4Subnet] {
			t.Fatalf("duplicate local subnet %s", network.IPv4Subnet)
		}
		usedSubnets[network.IPv4Subnet] = true
		name := ""
		if len(network.Principals) == 1 {
			name = network.Principals[0]
		}
		if ordinal, added := slice6AdditionalDeploymentOrdinals[name]; added {
			addedCount++
			if network.Name != "network-"+name || network.IPv4Subnet != "172.31."+strconv.Itoa(91+ordinal)+".0/24" ||
				pairs[name] != [2]uint32{uint32(56000 + ordinal), uint32(58000 + ordinal)} {
				t.Fatalf("additional deployment %s lost its reserved identity/network", name)
			}
			continue
		}
		if requiredPrincipals[requiredTLSAgentSubjects[name]] != "material_agent" {
			baseNetworks = append(baseNetworks, network.Name)
			continue
		}
		materialNetworks = append(materialNetworks, network.Name)
		newCount++
		if network.Name != "network-"+name || network.GatewayModeIPv4 != "isolated" || !network.Internal ||
			!slices.Contains(network.Principals, name) || pairs[name][0] < 55000 || pairs[name][0] > 55010 ||
			pairs[name][1] < 57000 || pairs[name][1] > 57010 {
			t.Fatalf("material-agent signer lost reserved isolation: %s", name)
		}
	}
	for name, pair := range pairs {
		if _, added := slice6AdditionalDeploymentOrdinals[name]; added {
			continue
		}
		if requiredPrincipals[requiredTLSAgentSubjects[name]] == "material_agent" {
			continue
		}
		oldCount++
		if pair[0] < 20000 || pair[0] > 20057 || pair[1] < 30000 || pair[1] > 30057 {
			t.Fatalf("old deployment %s moved out of its reviewed UID/GID partition", name)
		}
	}
	if newCount != 11 || oldCount != 58 || addedCount != 13 {
		t.Fatalf("identity inventory = %d material signers, %d old, %d added", newCount, oldCount, addedCount)
	}
	if len(baseNetworks) >= 80 {
		t.Fatal("reviewed base networks overlap the material signer reservation")
	}
	for index, name := range baseNetworks {
		for _, network := range networks {
			if network.Name == name && network.IPv4Subnet != "172.31."+strconv.Itoa(index+1)+".0/24" {
				t.Fatalf("old network %s changed its reviewed CIDR", name)
			}
		}
	}
	for index, name := range materialNetworks {
		for _, network := range networks {
			if network.Name == name && network.IPv4Subnet != "172.31."+strconv.Itoa(80+index)+".0/24" {
				t.Fatalf("material signer %s changed its reserved CIDR", name)
			}
		}
	}
}
