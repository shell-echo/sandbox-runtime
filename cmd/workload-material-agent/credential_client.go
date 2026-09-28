package main

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

type legacyCredentialIssuer struct{ client *workloadcredential.Client }

func (c legacyCredentialIssuer) Issue(ctx context.Context, ttl time.Duration) (credentialLease, error) {
	lease, err := c.client.Issue(ctx, ttl)
	return fromLegacyLease(lease), err
}

func (c legacyCredentialIssuer) Renew(ctx context.Context, lease credentialLease, ttl time.Duration) (credentialLease, error) {
	renewed, err := c.client.Renew(ctx, toLegacyLease(lease), ttl)
	return fromLegacyLease(renewed), err
}

func (c legacyCredentialIssuer) Revoke(ctx context.Context, lease credentialLease) error {
	return c.client.Revoke(ctx, toLegacyLease(lease))
}

func (c legacyCredentialIssuer) Close() { c.client.Close() }

type principalCredentialIssuer struct{ client *workloadcredentialv2.Client }

func (c principalCredentialIssuer) Issue(ctx context.Context, ttl time.Duration) (credentialLease, error) {
	lease, err := c.client.Issue(ctx, ttl)
	return fromPrincipalLease(lease), err
}

func (c principalCredentialIssuer) Renew(ctx context.Context, lease credentialLease, ttl time.Duration) (credentialLease, error) {
	renewed, err := c.client.Renew(ctx, toPrincipalLease(lease), ttl)
	return fromPrincipalLease(renewed), err
}

func (c principalCredentialIssuer) Revoke(ctx context.Context, lease credentialLease) error {
	return c.client.Revoke(ctx, toPrincipalLease(lease))
}

func (c principalCredentialIssuer) Close() { c.client.Close() }

func fromLegacyLease(lease workloadcredential.Lease) credentialLease {
	return credentialLease{lease.ID, lease.Revision, lease.IssuedAt, lease.ExpiresAt, lease.Renewable, lease.Credential}
}

func toLegacyLease(lease credentialLease) workloadcredential.Lease {
	return workloadcredential.Lease{ID: lease.ID, Revision: lease.Revision, IssuedAt: lease.IssuedAt,
		ExpiresAt: lease.ExpiresAt, Renewable: lease.Renewable, Credential: lease.Credential}
}

func fromPrincipalLease(lease workloadcredentialv2.Lease) credentialLease {
	return credentialLease{lease.ID, lease.Revision, lease.IssuedAt, lease.ExpiresAt, lease.Renewable, lease.Credential}
}

func toPrincipalLease(lease credentialLease) workloadcredentialv2.Lease {
	return workloadcredentialv2.Lease{ID: lease.ID, Revision: lease.Revision, IssuedAt: lease.IssuedAt,
		ExpiresAt: lease.ExpiresAt, Renewable: lease.Renewable, Credential: lease.Credential}
}
