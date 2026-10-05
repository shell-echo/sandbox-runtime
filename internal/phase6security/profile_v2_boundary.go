package phase6security

import (
	"net/netip"
	"path"
	"slices"
	"strings"
)

const (
	v2DaemonSocketPath    = "/var/run/docker.sock"
	v2DaemonSocketStorage = "provider-docker-daemon-socket"
	v2ReceiptTarget       = "/var/lib/sandbox-runtime/control-receipts"
	v2ReceiptMaxBytes     = 1 << 30
	v2ScannerRuleTarget   = "/var/lib/clamav"
	v2ScannerRuleMaxBytes = 1 << 30
)

var v2ControlScopes = []ControlEndpointV2{
	{Scope: "browser", ProviderDeployment: "provider-browser-runtime", Network: "provider-browser-control",
		EdgeID: "provider-browser-control", RoutePath: "/control/browser"},
	{Scope: "coding", ProviderDeployment: "provider-runtime", Network: "provider-coding-control",
		EdgeID: "provider-coding-control", RoutePath: "/control/coding"},
	{Scope: "desktop", ProviderDeployment: "provider-desktop-runtime", Network: "provider-desktop-control",
		EdgeID: "provider-desktop-control", RoutePath: "/control/desktop"},
}

func validateV2NewPrincipal(value Principal, control DockerControlAuthorityV2, scanner ArtifactScannerAuthorityV2) error {
	if !namePattern.MatchString(value.Name) || !validImageIdentity(value.ImageLocation, value.ImageIdentityKind,
		value.ImageReference, value.ImageDigest, value.ImagePlatform, value.ImageSelectedManifestDigest,
		value.ImageConfigDigest) || value.UID < 10000 || value.UID > 60000 ||
		value.GID < 10000 || value.GID > 60000 || !value.ReadOnlyRootFilesystem ||
		!value.NoNewPrivileges || !exactStrings(value.DroppedCapabilities, []string{"ALL"}) ||
		!digestPattern.MatchString(value.SeccompDigest) || !validSlice6CapacityLimit(value.Resources) ||
		value.HostNetwork || value.HostDevices || value.ExternalUplink || !value.DirectEgressBlocked ||
		(value.Kind == "tls_agent" && len(value.Networks) != 0) ||
		(value.Kind != "tls_agent" && (len(value.Networks) == 0 || len(value.Networks) > 8)) ||
		!sortedUniqueNames(value.Networks) ||
		len(value.Mounts) > 16 || len(value.Listeners) > 4 ||
		(value.Kind == "tls_agent" && len(value.Listeners) != 0) ||
		value.DockerSocket != (value.Name == control.Deployment) {
		return ErrInvalidProfile
	}
	seenTargets := map[string]bool{}
	for _, mount := range value.Mounts {
		if !strings.HasPrefix(mount.Target, "/") || path.Clean(mount.Target) != mount.Target ||
			mount.Target == "/" || seenTargets[mount.Target] {
			return ErrInvalidProfile
		}
		seenTargets[mount.Target] = true
		switch mount.Kind {
		case "private_socket":
			if mount.MaxBytes != 0 || !namePattern.MatchString(mount.StorageID) {
				return ErrInvalidProfile
			}
		case "trust_anchor":
			if !mount.ReadOnly || mount.MaxBytes != 0 || !namePattern.MatchString(mount.StorageID) {
				return ErrInvalidProfile
			}
		case "private_config":
			if !mount.ReadOnly || mount.MaxBytes != Slice6PrivateConfigMaxBytes ||
				!namePattern.MatchString(mount.StorageID) || mount.PrivateFiles == "" {
				return ErrInvalidProfile
			}
		case "tmpfs":
			if mount.ReadOnly || mount.MaxBytes < 4096 || mount.MaxBytes > 1<<30 || mount.StorageID != "" {
				return ErrInvalidProfile
			}
		case "daemon_socket":
			if value.Name != control.Deployment || mount.Target != v2DaemonSocketPath ||
				mount.StorageID != v2DaemonSocketStorage || !mount.ReadOnly || mount.MaxBytes != 0 {
				return ErrInvalidProfile
			}
		case "persistent_ledger":
			if value.Name != control.Deployment || mount.Target != control.ReceiptTarget ||
				mount.StorageID != control.ReceiptStorageID || mount.ReadOnly ||
				mount.MaxBytes != control.ReceiptMaxBytes {
				return ErrInvalidProfile
			}
		case "scanner_rules":
			if value.Name != scanner.Deployment || mount.Target != scanner.RuleTarget ||
				mount.StorageID != scanner.RuleStorageID || !mount.ReadOnly ||
				mount.MaxBytes != v2ScannerRuleMaxBytes {
				return ErrInvalidProfile
			}
		default:
			return ErrInvalidProfile
		}
		if mount.Kind != "private_config" && mount.PrivateFiles != "" {
			return ErrInvalidProfile
		}
	}
	for _, listener := range value.Listeners {
		if !namePattern.MatchString(listener.Name) || listener.Protocol != "tcp" ||
			listener.Exposure != "trust_edge" || listener.Port < 1 || listener.Port > 65535 {
			return ErrInvalidProfile
		}
	}
	return nil
}

func validateV2ControlAuthority(p ProfileV2, principals map[string]Principal, edges map[string]TrustEdge) error {
	a := p.DockerControl
	control := principals[a.Deployment]
	if a.Deployment != "provider-docker-control" || control.Kind != "docker_control" ||
		a.DaemonSocketPath != v2DaemonSocketPath || a.DaemonSocketGID != 0 ||
		a.DaemonSocketMode != 0o660 || !slices.Equal(a.SupplementaryGIDs, []uint32{0}) ||
		a.ReceiptTarget != v2ReceiptTarget ||
		a.ReceiptMaxBytes != v2ReceiptMaxBytes || !namePattern.MatchString(a.ReceiptStorageID) ||
		len(a.Endpoints) != len(v2ControlScopes) || !slices.Equal(a.Endpoints, v2ControlScopes) ||
		!slices.Equal(control.Networks, []string{
			"provider-browser-control", "provider-coding-control", "provider-desktop-control"}) ||
		!exactPolicyMount(control, "daemon_socket", v2DaemonSocketPath, v2DaemonSocketStorage, true) ||
		!exactPolicyMount(control, "persistent_ledger", a.ReceiptTarget, a.ReceiptStorageID, false) ||
		len(control.Listeners) != 3 {
		return ErrInvalidProfile
	}
	for _, principal := range principals {
		if principal.Name == control.Name {
			continue
		}
		if principal.DockerSocket {
			return ErrInvalidProfile
		}
		for _, mount := range principal.Mounts {
			if mount.Kind == "daemon_socket" || mount.StorageID == v2DaemonSocketStorage ||
				mount.StorageID == a.ReceiptStorageID || mount.Target == v2DaemonSocketPath ||
				mount.Target == a.ReceiptTarget {
				return ErrInvalidProfile
			}
		}
	}
	for _, expected := range v2ControlScopes {
		if validateV2PrivateEdge(p, principals, edges, expected.ProviderDeployment,
			control.Name, expected.Network, expected.EdgeID, expected.RoutePath, expected.Scope) != nil {
			return ErrInvalidProfile
		}
	}
	for _, edge := range p.TrustEdges {
		if edge.Authentication != "mtls" || edge.To != control.Name {
			continue
		}
		if !slices.ContainsFunc(v2ControlScopes, func(scope ControlEndpointV2) bool { return scope.EdgeID == edge.ID }) {
			return ErrInvalidProfile
		}
	}
	return nil
}

func validateV2ScannerAuthority(p ProfileV2, principals map[string]Principal, edges map[string]TrustEdge) error {
	a := p.ArtifactScanner
	scanner := principals[a.Deployment]
	if a.Deployment != "provider-artifact-scanner" || scanner.Kind != "artifact_scanner" ||
		a.ProviderDeployment != "provider-runtime" || a.Network != "provider-coding-scanner" ||
		a.EdgeID != "provider-coding-scanner" || a.RoutePath != "/scan" ||
		a.RuleTarget != v2ScannerRuleTarget || !namePattern.MatchString(a.RuleStorageID) ||
		!digestPattern.MatchString(a.RuleManifestDigest) || a.MaxRuleAgeSeconds != 72*60*60 ||
		a.MaxArtifactBytes != 64<<20 || a.MaxConcurrentScans != 1 ||
		!slices.Equal(scanner.Networks, []string{a.Network}) || len(scanner.Listeners) != 1 ||
		!exactPolicyMount(scanner, "scanner_rules", a.RuleTarget, a.RuleStorageID, true) ||
		validateV2PrivateEdge(p, principals, edges, a.ProviderDeployment, scanner.Name,
			a.Network, a.EdgeID, a.RoutePath, "scanner") != nil {
		return ErrInvalidProfile
	}
	for _, principal := range principals {
		if principal.Name == scanner.Name {
			continue
		}
		for _, mount := range principal.Mounts {
			if mount.Kind == "scanner_rules" || mount.StorageID == a.RuleStorageID || mount.Target == a.RuleTarget {
				return ErrInvalidProfile
			}
		}
	}
	for _, edge := range p.TrustEdges {
		if edge.Authentication == "mtls" && edge.To == scanner.Name && edge.ID != a.EdgeID {
			return ErrInvalidProfile
		}
	}
	return nil
}

func validateV2PrivateEdge(p ProfileV2, principals map[string]Principal, edges map[string]TrustEdge,
	providerName, targetName, networkName, edgeID, route, listenerName string) error {
	provider, target := principals[providerName], principals[targetName]
	edge, ok := edges[edgeID]
	if !ok || provider.TLS == nil || target.TLS == nil || edge.From != providerName ||
		edge.To != targetName || edge.Protocol != "https" || edge.Authentication != "mtls" ||
		edge.RoutePath != route || edge.TenantScope != "bound" || edge.MaxConnectionSeconds > 300 ||
		edge.ServerAnchorID == "" || edge.ClientAnchorID == "" ||
		edge.ServerAnchorID == edge.ClientAnchorID || edge.FromURI != provider.TLS.URI ||
		edge.ToURI != target.TLS.URI || edge.FromPrincipalDigest != provider.PrincipalDigest ||
		edge.ToPrincipalDigest != target.PrincipalDigest || edge.TargetAddress == "" {
		return ErrInvalidProfile
	}
	var network Network
	for _, candidate := range p.Networks {
		if candidate.Name == networkName {
			network = candidate
		}
	}
	if network.Kind != "trust_edge" || !network.Internal || network.IPv6Enabled ||
		network.GatewayModeIPv4 != "isolated" || len(network.Principals) != 2 ||
		!slices.Contains(network.Principals, providerName) || !slices.Contains(network.Principals, targetName) ||
		!slices.Contains(provider.Networks, networkName) || !slices.Contains(target.Networks, networkName) {
		return ErrInvalidProfile
	}
	shared := 0
	for _, name := range provider.Networks {
		if slices.Contains(target.Networks, name) {
			shared++
		}
	}
	if shared != 1 {
		return ErrInvalidProfile
	}
	address, addressErr := netip.ParseAddrPort(edge.TargetAddress)
	prefix, prefixErr := netip.ParsePrefix(network.IPv4Subnet)
	if addressErr != nil || prefixErr != nil || int(address.Port()) != edge.Port ||
		!prefix.Contains(address.Addr()) || address.Addr() == prefix.Addr() {
		return ErrInvalidProfile
	}
	found := false
	for _, listener := range target.Listeners {
		if listener.Name == listenerName && listener.Protocol == "tcp" &&
			listener.Exposure == "trust_edge" && listener.Port == edge.Port {
			found = true
		}
	}
	if !found {
		return ErrInvalidProfile
	}
	return nil
}
