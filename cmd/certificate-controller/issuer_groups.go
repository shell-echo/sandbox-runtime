package main

import (
	"errors"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

var errInvalidIssuerGroups = errors.New("invalid finite certificate issuer groups")

// validateFiniteIssuerPolicyGroups enforces the reviewed two-issuer local
// profile: only five named egress brokers may obtain a broker-issuer leaf.
// The existing signed policy and peer-edge mapping remain the authorization
// boundary; this helper neither creates an issuer nor grants a Vault role.
func validateFiniteIssuerPolicyGroups(profile phase6security.Profile,
	sources phase6security.PeerCRLSources, policies []workloadpki.Policy) error {
	if sources.Validate(profile) != nil {
		return errInvalidIssuerGroups
	}
	return validateFiniteIssuerPolicyGroupsBound(profile, sources, policies)
}

// The bound core is split from source-document validation so the exact finite
// policy/edge partition can be tested without a fabricated complete Profile.
func validateFiniteIssuerPolicyGroupsBound(profile phase6security.Profile,
	sources phase6security.PeerCRLSources, policies []workloadpki.Policy) error {
	if len(sources.Sources) != 2 || len(policies) == 0 {
		return errInvalidIssuerGroups
	}
	brokerNames := map[string]bool{
		"egress-broker-product": true, "egress-broker-gateway": true,
		"egress-broker-browser-action-ingress": true, "egress-broker-provider-browser": true,
		"egress-broker-provider-desktop": true,
	}
	brokerPolicies := make(map[string]bool, len(brokerNames))
	for _, binding := range profile.TLSAgentBindings {
		if brokerNames[binding.SubjectDeployment] {
			if brokerPolicies[binding.IssuerPolicyID] || binding.IssuerPolicyID == "" {
				return errInvalidIssuerGroups
			}
			brokerPolicies[binding.IssuerPolicyID] = true
		}
	}
	if len(brokerPolicies) != len(brokerNames) {
		return errInvalidIssuerGroups
	}
	sourceByID := make(map[string]phase6security.PeerCRLSource, 2)
	for _, source := range sources.Sources {
		sourceByID[source.ID] = source
	}
	brokerSource, generalSource := "", ""
	seenPolicies := make(map[string]bool, len(policies))
	brokerCount := 0
	for _, policy := range policies {
		if policy.ID == "" || seenPolicies[policy.ID] || sourceByID[policy.IssuerSourceID].ID == "" {
			return errInvalidIssuerGroups
		}
		seenPolicies[policy.ID] = true
		if brokerPolicies[policy.ID] {
			brokerCount++
			if brokerSource != "" && brokerSource != policy.IssuerSourceID {
				return errInvalidIssuerGroups
			}
			brokerSource = policy.IssuerSourceID
		} else {
			if generalSource != "" && generalSource != policy.IssuerSourceID {
				return errInvalidIssuerGroups
			}
			generalSource = policy.IssuerSourceID
		}
	}
	if brokerCount != len(brokerPolicies) || brokerSource == "" || generalSource == "" ||
		brokerSource == generalSource || sourceByID[brokerSource].IssuerID == sourceByID[generalSource].IssuerID ||
		sourceByID[brokerSource].IssuerDigest == sourceByID[generalSource].IssuerDigest {
		return errInvalidIssuerGroups
	}
	for _, service := range profile.External {
		if service.Name == "dns" {
			if service.DNSClientCA == nil ||
				service.DNSClientCA.IssuerID != sourceByID[brokerSource].IssuerID ||
				service.DNSClientCA.IssuerDigest != sourceByID[brokerSource].IssuerDigest {
				return errInvalidIssuerGroups
			}
		}
	}
	edges := make(map[string]phase6security.TrustEdge, len(profile.TrustEdges))
	for _, edge := range profile.TrustEdges {
		edges[edge.ID] = edge
	}
	for _, binding := range sources.Edges {
		edge, found := edges[binding.EdgeID]
		if !found {
			return errInvalidIssuerGroups
		}
		peer := edge.To
		if binding.Direction == "inbound" {
			peer = edge.From
		}
		want := generalSource
		if brokerNames[peer] {
			want = brokerSource
		}
		if binding.SourceID != want {
			return errInvalidIssuerGroups
		}
	}
	return nil
}
