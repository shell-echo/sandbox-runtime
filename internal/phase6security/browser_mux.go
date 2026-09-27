package phase6security

import "slices"

const (
	BrowserMuxSocketDirectory = "/run/browser-mux"
	BrowserMuxSocketStorageID = "browser-provider-mux-socket"
	BrowserMuxUnixEdgeID      = "browser-executor-provider-mux"
)

// validateBrowserMux binds the Provider-owned allocation socket to exactly
// the Browser backend. It is a Unix peer edge, not an alternate TCP route or
// permission for the backend to read Provider PostgreSQL or Docker.
func validateBrowserMux(principals map[string]Principal, edges map[string]TrustEdge) error {
	provider, providerOK := principals["provider-browser-runtime"]
	backend, backendOK := principals["browser-executor-backend"]
	edge, edgeOK := edges[BrowserMuxUnixEdgeID]
	if !providerOK || !backendOK || !edgeOK || provider.TLS == nil || backend.TLS == nil ||
		provider.UID == backend.UID || provider.GID == backend.GID ||
		!exactPolicyMount(provider, "private_socket", BrowserMuxSocketDirectory, BrowserMuxSocketStorageID, false) ||
		!exactPolicyMount(backend, "private_socket", BrowserMuxSocketDirectory, BrowserMuxSocketStorageID, true) ||
		edge.From != backend.Name || edge.To != provider.Name || edge.Protocol != "unix" ||
		edge.Authentication != "unix_peer_credentials" || edge.TenantScope != "system" ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 30 ||
		edge.FromURI != backend.TLS.URI || edge.ToURI != provider.TLS.URI ||
		edge.FromPrincipalDigest != backend.PrincipalDigest || edge.ToPrincipalDigest != provider.PrincipalDigest ||
		!slices.ContainsFunc(provider.Listeners, func(listener Listener) bool {
			return listener == (Listener{Name: "browser-mux", Protocol: "unix", Exposure: "private_socket"})
		}) {
		return ErrInvalidProfile
	}
	for name, principal := range principals {
		if name == provider.Name || name == backend.Name {
			continue
		}
		for _, mount := range principal.Mounts {
			if mount.StorageID == BrowserMuxSocketStorageID || mount.Target == BrowserMuxSocketDirectory {
				return ErrInvalidProfile
			}
		}
	}
	for id, candidate := range edges {
		if candidate.From == backend.Name && candidate.To == provider.Name && id != BrowserMuxUnixEdgeID {
			return ErrInvalidProfile
		}
	}
	return nil
}
