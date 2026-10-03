// Package productguest adapts the neutral Guest Agent protocol to Product-owned
// PostgreSQL identity authority without exposing Product repositories to the
// Guest Agent package.
package productguest

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
)

type revocationEvidenceStore interface {
	AuthenticateGuestWithRevocationEvidence(context.Context, product.GuestAuthentication) (product.GuestBinding, bool, error)
}

type Authenticator struct {
	store           product.GuestBindingStore
	revocationStore revocationEvidenceStore
	onRevoked       func(string, int64)
}

func NewAuthenticator(store product.GuestBindingStore) (*Authenticator, error) {
	if store == nil {
		return nil, product.ErrInvalid
	}
	return &Authenticator{store: store}, nil
}

// NewAuthenticatorWithRevocationObservation enables a private, optional
// signed-attempt receipt. The callback must only enqueue bounded local data;
// it must not perform output or database work on the authentication path.
func NewAuthenticatorWithRevocationObservation(store product.GuestBindingStore, onRevoked func(string, int64)) (*Authenticator, error) {
	if store == nil || onRevoked == nil {
		return nil, product.ErrInvalid
	}
	observed, ok := store.(revocationEvidenceStore)
	if !ok {
		return nil, product.ErrInvalid
	}
	return &Authenticator{store: store, revocationStore: observed, onRevoked: onRevoked}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, request guestagent.AuthRequest) (guestagent.Identity, error) {
	signing, err := request.SigningBytes()
	if err != nil {
		return guestagent.Identity{}, guestagent.ErrUnauthorized
	}
	signature, err := request.SignatureBytes()
	if err != nil {
		return guestagent.Identity{}, guestagent.ErrUnauthorized
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.Challenge.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) || expiresAt.After(time.Now().UTC().Add(30*time.Second)) {
		return guestagent.Identity{}, guestagent.ErrUnauthorized
	}
	authentication := product.GuestAuthentication{
		GuestID: request.Hello.GuestID, BindingGeneration: request.Hello.BindingGeneration,
		ProtocolVersion: request.Hello.ProtocolVersion, OfferedCapabilities: append([]string(nil), request.Hello.Capabilities...),
		ClientNonce: request.Hello.ClientNonce, SigningBytes: signing, Signature: signature,
	}
	var binding product.GuestBinding
	if a.revocationStore != nil {
		var revoked bool
		binding, revoked, err = a.revocationStore.AuthenticateGuestWithRevocationEvidence(ctx, authentication)
		if revoked && errors.Is(err, product.ErrForbidden) {
			if digest, digestErr := request.AttemptDigest(); digestErr == nil {
				a.onRevoked(digest, request.Hello.BindingGeneration)
			}
		}
	} else {
		binding, err = a.store.AuthenticateGuest(ctx, authentication)
	}
	if err != nil {
		return guestagent.Identity{}, mapAuthenticationError(err)
	}
	return identity(binding), nil
}

func (a *Authenticator) CheckAuthority(ctx context.Context, current guestagent.Identity) error {
	err := a.store.CheckGuestAuthority(ctx, binding(current))
	if err != nil {
		return mapAuthenticationError(err)
	}
	return nil
}

func (a *Authenticator) Disconnected(ctx context.Context, current guestagent.Identity) error {
	return a.store.DisconnectGuest(ctx, binding(current))
}

func identity(binding product.GuestBinding) guestagent.Identity {
	return guestagent.Identity{
		TenantID: binding.TenantID, WorkspaceID: binding.WorkspaceID, SlotKey: binding.SlotKey,
		GuestID: binding.GuestID, SlotGeneration: binding.SlotGeneration, BindingGeneration: binding.BindingGeneration,
		ProtocolVersion: binding.ProtocolVersion, Capabilities: append([]string(nil), binding.Capabilities...),
		ClientNonce: binding.ClientNonce, ExpiresAt: binding.ExpiresAt,
	}
}

func binding(identity guestagent.Identity) product.GuestBinding {
	return product.GuestBinding{
		TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, SlotKey: identity.SlotKey,
		GuestID: identity.GuestID, BindingGeneration: identity.BindingGeneration,
		SlotGeneration:  identity.SlotGeneration,
		ProtocolVersion: identity.ProtocolVersion, Capabilities: append([]string(nil), identity.Capabilities...),
		ClientNonce: identity.ClientNonce, ExpiresAt: identity.ExpiresAt, State: "connected",
	}
}

func mapAuthenticationError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, product.ErrCapabilityUnsupported) {
		return guestagent.ErrIncompatible
	}
	if errors.Is(err, product.ErrStoreUnavailable) || errors.Is(err, product.ErrStoreOutcomeUnknown) {
		return guestagent.ErrUnavailable
	}
	return guestagent.ErrUnauthorized
}

var _ guestagent.Authenticator = (*Authenticator)(nil)
