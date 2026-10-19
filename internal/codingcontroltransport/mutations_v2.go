package codingcontroltransport

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

var ErrMutationUncertain = errors.New("Coding Control mutation result is uncertain")

// ControlClientV2 shares the exact status client's Profile-bound TLS/CRL
// transport. It receives no PG handle, Docker endpoint or legacy driver.
// Mutation results are acknowledgements only; the application must perform
// a distinct authenticated status observation before a typed PG commit.
type ControlClientV2 struct{ observer *StatusObserverV2 }

func NewControlClientV2(lifetime context.Context, p phase6security.ProfileV2,
	a phase6tls.PrivateServiceAuthorityV2, policyDigest string) (*ControlClientV2, error) {
	observer, err := NewStatusObserverV2(lifetime, p, a, policyDigest)
	if err != nil {
		return nil, err
	}
	return &ControlClientV2{observer: observer}, nil
}

func (c *ControlClientV2) Observe(ctx context.Context, request codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	if c == nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	return c.observer.Observe(ctx, request)
}

func (c *ControlClientV2) DispatchCodingCreateAuthority(ctx context.Context, create dockercontrol.CodingCreateAuthority) error {
	return c.dispatch(ctx, codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionCreate, Create: create})
}

func (c *ControlClientV2) DispatchCodingCleanupAuthority(ctx context.Context, create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority) error {
	return c.dispatch(ctx, codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionCleanup, Create: create, Cleanup: &cleanup})
}

func (c *ControlClientV2) dispatch(ctx context.Context, request codingcontrolprotocol.Request) error {
	if c == nil || c.observer == nil || c.observer.client == nil || c.observer.peer == nil ||
		c.observer.lifetime == nil || c.observer.lifetime.Err() != nil || ctx == nil || ctx.Err() != nil {
		return ErrMutationUncertain
	}
	o := c.observer
	return dispatchMutation(ctx, o.lifetime, o.client, o.peer, o.timeout, request)
}

// Kept private: the exported factory always supplies a concrete Profile-v2
// PeerCRLGuard. Component tests can exercise the send boundary without
// claiming a positive production Profile admission.
func dispatchMutation(ctx, lifetime context.Context, client *statusClient, peer statusPeer,
	timeout time.Duration, request codingcontrolprotocol.Request) error {
	if ctx == nil || lifetime == nil || ctx.Err() != nil || lifetime.Err() != nil ||
		client == nil || peer == nil || timeout < time.Second || timeout > 30*time.Second {
		return ErrMutationUncertain
	}
	if request.Validate(time.Now().UTC(), client.config.ProviderPrincipalDigest) != nil {
		return ErrMutationUncertain
	}
	deadline := request.Create.ExpiresAt
	if request.Action == codingcontrolprotocol.ActionCleanup && request.Cleanup != nil {
		deadline = request.Cleanup.ExpiresAt
	}
	if request.Action != codingcontrolprotocol.ActionCreate && request.Action != codingcontrolprotocol.ActionCleanup {
		return ErrMutationUncertain
	}
	operation, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	operation, cancelTimeout := context.WithTimeout(operation, timeout)
	defer cancelTimeout()
	stop := context.AfterFunc(lifetime, cancel)
	defer stop()
	if peer.Poll(operation) != nil || !peer.Ready() {
		return ErrMutationUncertain
	}
	response, err := client.exchange(operation, request)
	if err != nil || peer.Poll(operation) != nil || !peer.Ready() || operation.Err() != nil || lifetime.Err() != nil ||
		response.UpdatedAt.After(time.Now().UTC()) {
		return ErrMutationUncertain
	}
	if (request.Action == codingcontrolprotocol.ActionCreate && response.Status != codingcontrolprotocol.StatusCompleted) ||
		(request.Action == codingcontrolprotocol.ActionCleanup && response.Status != codingcontrolprotocol.StatusReleased) {
		return ErrMutationUncertain
	}
	if request.Action == codingcontrolprotocol.ActionCreate && request.Create.Validate(response.UpdatedAt) != nil {
		return ErrMutationUncertain
	}
	return nil
}

func (c *ControlClientV2) Close() {
	if c != nil && c.observer != nil {
		c.observer.Close()
	}
}

var _ codingcontrol.Observer = (*ControlClientV2)(nil)
