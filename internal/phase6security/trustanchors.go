package phase6security

import (
	"net/url"
	"path"
	"slices"
	"strings"
)

func validateTrustAnchors(anchors []TrustAnchor, edges []TrustEdge, public []PublicListenerBinding, controller CertificateControllerAuthority, principals map[string]Principal,
	external map[string]ExternalService) error {
	return validateTrustAnchorsWithPostgres(anchors, edges, public, controller, nil, principals, external)
}

func validateTrustAnchorsWithPostgres(anchors []TrustAnchor, edges []TrustEdge, public []PublicListenerBinding,
	controller CertificateControllerAuthority, postgres []PostgresClientAgentBinding,
	principals map[string]Principal, external map[string]ExternalService) error {
	byID := make(map[string]TrustAnchor, len(anchors))
	storage, artifact, targets := map[string]bool{}, map[string]bool{}, map[string]TrustAnchor{}
	previous := ""
	for _, anchor := range anchors {
		if anchor.ID <= previous || !namePattern.MatchString(anchor.ID) || !digestPattern.MatchString(anchor.BundleDigest) ||
			(anchor.Purpose != "server_verification" && anchor.Purpose != "client_verification") ||
			!validDNSName(anchor.TrustDomain) || !namePattern.MatchString(anchor.ArtifactID) ||
			!namePattern.MatchString(anchor.StorageID) || !strings.HasPrefix(anchor.TargetPath, "/") ||
			path.Clean(anchor.TargetPath) != anchor.TargetPath || anchor.TargetPath == "/" ||
			!strings.HasSuffix(anchor.TargetPath, ".pem") || anchor.WriterAuthority != "operator" ||
			anchor.OwnerUID > 60000 || anchor.OwnerGID > 60000 || len(anchor.Consumers) < 1 ||
			len(anchor.Consumers) > 128 || !sortedUniqueNames(anchor.Consumers) ||
			storage[anchor.StorageID] || artifact[anchor.ArtifactID] || targets[anchor.TargetPath].ID != "" {
			return ErrInvalidProfile
		}
		previous = anchor.ID
		storage[anchor.StorageID], artifact[anchor.ArtifactID], targets[anchor.TargetPath] = true, true, anchor
		for _, consumer := range anchor.Consumers {
			principal, ok := principals[consumer]
			if !ok || !hasTrustAnchorMount(principal, anchor) {
				return ErrInvalidProfile
			}
		}
		byID[anchor.ID] = anchor
	}
	references := make(map[string]int, len(anchors))
	requiredConsumers := make(map[string]map[string]bool, len(anchors))
	markConsumer := func(anchorID, consumer string) {
		if requiredConsumers[anchorID] == nil {
			requiredConsumers[anchorID] = make(map[string]bool)
		}
		requiredConsumers[anchorID][consumer] = true
	}
	for _, edge := range edges {
		if edge.Authentication != "mtls" {
			if edge.ServerAnchorID != "" || edge.ClientAnchorID != "" {
				return ErrInvalidProfile
			}
			continue
		}
		to, local := principals[edge.To]
		server, ok := byID[edge.ServerAnchorID]
		if !ok || server.Purpose != "server_verification" || !slices.Contains(server.Consumers, edge.From) {
			return ErrInvalidProfile
		}
		serverURI, err := url.Parse(edge.ToURI)
		if err != nil || server.TrustDomain != serverURI.Host {
			return ErrInvalidProfile
		}
		references[server.ID]++
		markConsumer(server.ID, edge.From)
		if !local {
			if _, ok := external[edge.To]; !ok || edge.ClientAnchorID != "" {
				return ErrInvalidProfile
			}
			continue
		}
		if to.TLS == nil {
			return ErrInvalidProfile
		}
		// The caller verifies the remote server with this root. The local
		// server also verifies its own agent-issued server leaf against it.
		if !slices.Contains(server.Consumers, edge.To) {
			return ErrInvalidProfile
		}
		markConsumer(server.ID, edge.To)
		client, ok := byID[edge.ClientAnchorID]
		clientURI, err := url.Parse(edge.FromURI)
		if !ok || err != nil || client.Purpose != "client_verification" ||
			client.TrustDomain != clientURI.Host || !slices.Contains(client.Consumers, edge.To) ||
			!slices.Contains(client.Consumers, edge.From) {
			return ErrInvalidProfile
		}
		references[client.ID]++
		markConsumer(client.ID, edge.To)
		// The server verifies peers with this root. The caller uses the
		// same exact root only to verify its own agent-issued client leaf.
		markConsumer(client.ID, edge.From)
	}
	for _, listener := range public {
		anchor, ok := byID[listener.IssuerAnchorID]
		principal := principals[listener.DeploymentName]
		if !ok || principal.TLS == nil || anchor.Purpose != "server_verification" ||
			anchor.TrustDomain != principal.TLS.TrustDomain || !slices.Contains(anchor.Consumers, listener.DeploymentName) {
			return ErrInvalidProfile
		}
		references[anchor.ID]++
		markConsumer(anchor.ID, listener.DeploymentName)
	}
	bootstrap, ok := byID[controller.BootstrapClientAnchorID]
	controllerPrincipal := principals[controller.DeploymentName]
	if !ok || controllerPrincipal.TLS == nil || bootstrap.Purpose != "client_verification" ||
		bootstrap.TrustDomain != controllerPrincipal.TLS.TrustDomain ||
		!slices.Contains(bootstrap.Consumers, controller.DeploymentName) {
		return ErrInvalidProfile
	}
	references[bootstrap.ID]++
	markConsumer(bootstrap.ID, controller.DeploymentName)
	for _, binding := range postgres {
		anchor, ok := byID[binding.IssuerAnchorID]
		if !ok || anchor.Purpose != "client_verification" || !slices.Contains(anchor.Consumers, binding.SubjectDeployment) {
			return ErrInvalidProfile
		}
		references[anchor.ID]++
		markConsumer(anchor.ID, binding.SubjectDeployment)
	}
	for id, anchor := range byID {
		if references[id] < 1 || len(requiredConsumers[id]) != len(anchor.Consumers) {
			return ErrInvalidProfile
		}
		for _, consumer := range anchor.Consumers {
			if !requiredConsumers[id][consumer] {
				return ErrInvalidProfile
			}
		}
		for name, principal := range principals {
			if hasTrustAnchorMount(principal, anchor) != slices.Contains(anchor.Consumers, name) {
				return ErrInvalidProfile
			}
		}
	}
	for _, principal := range principals {
		for _, mount := range principal.Mounts {
			if mount.Kind == "trust_anchor" {
				anchor, ok := targets[mount.Target]
				if !ok || !slices.Contains(anchor.Consumers, principal.Name) ||
					mount.StorageID != anchor.StorageID || !mount.ReadOnly || mount.MaxBytes != 0 {
					return ErrInvalidProfile
				}
			}
		}
	}
	return nil
}

func hasTrustAnchorMount(principal Principal, anchor TrustAnchor) bool {
	for _, mount := range principal.Mounts {
		if mount.Target == anchor.TargetPath && mount.Kind == "trust_anchor" && mount.ReadOnly &&
			mount.StorageID == anchor.StorageID && mount.MaxBytes == 0 {
			return true
		}
	}
	return false
}

// EdgeTrustAnchors returns direction-specific bundle artifacts for one exact
// profile edge. External services have no repository-owned client verifier.
func (p Profile) EdgeTrustAnchors(edgeID string) (TrustAnchor, TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
	}
	for _, edge := range p.TrustEdges {
		if edge.ID != edgeID || edge.Authentication != "mtls" {
			continue
		}
		var server, client TrustAnchor
		for _, anchor := range p.TrustAnchors {
			if anchor.ID == edge.ServerAnchorID {
				server = anchor
			}
			if anchor.ID == edge.ClientAnchorID {
				client = anchor
			}
		}
		if server.ID != "" && (edge.ClientAnchorID == "" || client.ID != "") {
			return server, client, nil
		}
	}
	return TrustAnchor{}, TrustAnchor{}, ErrInvalidProfile
}

func (p Profile) ConsumerTrustAnchor(anchorID, consumer, purpose string) (TrustAnchor, error) {
	if p.Validate() != nil {
		return TrustAnchor{}, ErrInvalidProfile
	}
	for _, anchor := range p.TrustAnchors {
		if anchor.ID == anchorID && anchor.Purpose == purpose && slices.Contains(anchor.Consumers, consumer) {
			return anchor, nil
		}
	}
	return TrustAnchor{}, ErrInvalidProfile
}
