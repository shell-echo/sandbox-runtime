package phase6egress

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// NewProviderPostgresAlias uses only the Provider owner's second, PostgreSQL-
// purpose signer for the inner TLS layer. The server's exact HBA/ident policy
// must still be observed in the deployment gate, not inferred from the client.
func NewProviderPostgresAlias(ctx context.Context, profile phase6security.Profile, owner string,
	client *egressbroker.Client, guard *phase6tls.PeerCRLGuard,
	source remotetls.CertificateSource) (*FixedAlias, error) {
	if ctx == nil || ctx.Err() != nil ||
		(owner != "provider-browser-runtime" && owner != "provider-desktop-runtime") ||
		profile.Validate() != nil || source == nil {
		return nil, ErrUnavailable
	}
	binding, database, _, principal, anchor, err := profile.PostgresClientAgentForOwner(owner)
	if err != nil || principal.TLS == nil || binding.SubjectDeployment != database.OwnerDeployment {
		return nil, ErrUnavailable
	}
	pem, err := trustanchor.Load(anchor, time.Now().UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(pem)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, ErrUnavailable
	}
	certificate, err := newPostgresClientCertificate(ctx, roots, workloadpki.PostgresClientIdentity{
		OwnerDeployment: owner, DatabaseName: database.DatabaseName, RuntimeRole: database.RuntimeRole,
		ServiceName: database.ServiceName, URI: principal.TLS.URI, CommonName: binding.CommonName,
		MaxTTL: time.Duration(principal.TLS.TTLSeconds) * time.Second,
	}, source, time.Now)
	if err != nil {
		return nil, ErrUnavailable
	}
	_, _, lease, err := selectTarget(profile, owner, "postgres")
	if err != nil {
		return nil, ErrUnavailable
	}
	return NewFixedAlias(profile, owner, "postgres", client, guard, certificate, lease)
}
