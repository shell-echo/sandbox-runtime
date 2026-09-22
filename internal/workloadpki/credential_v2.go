package workloadpki

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

// V2CredentialAdapter is the only production adapter from the Principal-based
// credential client into the certificate controller's short-lived Vault token
// source. It cannot accept or reinterpret a v1 lease.
type V2CredentialAdapter struct {
	Client *workloadcredentialv2.Client
}

func (a V2CredentialAdapter) Issue(ctx context.Context, ttl time.Duration) (CredentialLease, error) {
	if a.Client == nil {
		return CredentialLease{}, ErrUnavailable
	}
	lease, err := a.Client.Issue(ctx, ttl)
	return credentialLeaseFromV2(lease), err
}

func (a V2CredentialAdapter) Renew(ctx context.Context, lease CredentialLease, ttl time.Duration) (CredentialLease, error) {
	if a.Client == nil {
		return CredentialLease{}, ErrUnavailable
	}
	replacement, err := a.Client.Renew(ctx, credentialLeaseToV2(lease), ttl)
	return credentialLeaseFromV2(replacement), err
}

func (a V2CredentialAdapter) Revoke(ctx context.Context, lease CredentialLease) error {
	if a.Client == nil {
		return ErrUnavailable
	}
	return a.Client.Revoke(ctx, credentialLeaseToV2(lease))
}

func credentialLeaseFromV2(lease workloadcredentialv2.Lease) CredentialLease {
	defer lease.Destroy()
	return CredentialLease{ID: lease.ID, Revision: lease.Revision, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
		Renewable: lease.Renewable, Credential: append([]byte(nil), lease.Credential...)}
}

func credentialLeaseToV2(lease CredentialLease) workloadcredentialv2.Lease {
	return workloadcredentialv2.Lease{ID: lease.ID, Revision: lease.Revision, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
		Renewable: lease.Renewable, Credential: append([]byte(nil), lease.Credential...)}
}
