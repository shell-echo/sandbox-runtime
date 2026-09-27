package phase6egress

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

// CredentialResolver is intentionally narrower than a material registry. The
// deployment-specific registry has already checked role, agent and binding.
type CredentialResolver interface {
	Resolve(context.Context, string, secretref.Purpose, string) (secretref.SecretMaterial, error)
}

type credentialIdentity struct {
	binding, digest, revision string
	window                    secretref.RotationWindow
}

// CredentialGuard pins the two independently scoped external credentials for
// one ingress lifetime. Rotation is a drain-and-restart event: existing pools
// must never continue with a credential after its agent stops authorizing it.
type CredentialGuard struct {
	resolver              CredentialResolver
	capacityID, witnessID string
	witnessTarget         WitnessTarget
	capacity, witness     credentialIdentity
	interval              time.Duration
	now                   func() time.Time
	mu                    sync.Mutex
	failed, started       bool
	drain                 func()
}

// NewCredentialGuard resolves both secrets once and returns caller-owned
// parsed values for construction of bounded, broker-routed clients. It stores
// only non-secret binding and material identities for subsequent checks.
func NewCredentialGuard(ctx context.Context, resolver CredentialResolver, capacityID, witnessID string,
	target WitnessTarget, interval time.Duration, now func() time.Time,
) (*CredentialGuard, CapacityValkeyCredentials, *pgxpool.Config, error) {
	if ctx == nil || resolver == nil || capacityID == "" || witnessID == "" || capacityID == witnessID ||
		interval < 100*time.Millisecond || interval > 5*time.Second || now == nil || now().IsZero() {
		return nil, CapacityValkeyCredentials{}, nil, ErrUnavailable
	}
	guard := &CredentialGuard{resolver: resolver, capacityID: capacityID, witnessID: witnessID,
		witnessTarget: target, interval: interval, now: now}
	capacity, capacityIdentity, err := guard.resolveCapacity(ctx)
	if err != nil {
		return nil, CapacityValkeyCredentials{}, nil, ErrUnavailable
	}
	witness, witnessIdentity, err := guard.resolveWitness(ctx)
	if err != nil {
		return nil, CapacityValkeyCredentials{}, nil, ErrUnavailable
	}
	guard.capacity, guard.witness = capacityIdentity, witnessIdentity
	return guard, capacity, witness, nil
}

func (g *CredentialGuard) resolveCapacity(ctx context.Context) (CapacityValkeyCredentials, credentialIdentity, error) {
	material, err := g.resolver.Resolve(ctx, g.capacityID, secretref.PurposeCapacityValkeyCredentials, secretref.SystemTenant)
	defer material.Destroy()
	if err != nil || material.Validate(g.now()) != nil ||
		material.Binding.Purpose != secretref.PurposeCapacityValkeyCredentials ||
		material.Binding.TenantID != secretref.SystemTenant || material.Binding.Role != secretref.RoleGateway {
		return CapacityValkeyCredentials{}, credentialIdentity{}, ErrUnavailable
	}
	credentials, err := DecodeCapacityValkeyCredentials(material.Bytes)
	if err != nil {
		return CapacityValkeyCredentials{}, credentialIdentity{}, ErrUnavailable
	}
	return credentials, materialIdentity(material), nil
}

func (g *CredentialGuard) resolveWitness(ctx context.Context) (*pgxpool.Config, credentialIdentity, error) {
	material, err := g.resolver.Resolve(ctx, g.witnessID, secretref.PurposeActionHistoryWitnessDSN, secretref.SystemTenant)
	defer material.Destroy()
	if err != nil || material.Validate(g.now()) != nil ||
		material.Binding.Purpose != secretref.PurposeActionHistoryWitnessDSN ||
		material.Binding.TenantID != secretref.SystemTenant || material.Binding.Role != secretref.RoleGateway {
		return nil, credentialIdentity{}, ErrUnavailable
	}
	config, err := ParseActionHistoryWitnessDSN(material.Bytes, g.witnessTarget)
	if err != nil {
		return nil, credentialIdentity{}, ErrUnavailable
	}
	return config, materialIdentity(material), nil
}

func materialIdentity(material secretref.SecretMaterial) credentialIdentity {
	return credentialIdentity{binding: material.Binding.Digest(), digest: material.Digest,
		revision: material.Revision, window: material.Window}
}

func (g *CredentialGuard) resolveIdentity(ctx context.Context, id string, purpose secretref.Purpose) (credentialIdentity, error) {
	material, err := g.resolver.Resolve(ctx, id, purpose, secretref.SystemTenant)
	defer material.Destroy()
	if err != nil || material.Validate(g.now()) != nil || material.Binding.Purpose != purpose ||
		material.Binding.TenantID != secretref.SystemTenant || material.Binding.Role != secretref.RoleGateway {
		return credentialIdentity{}, ErrUnavailable
	}
	return materialIdentity(material), nil
}

// Check re-resolves through the live agent and latches the first loss, expiry,
// semantic drift or version change. It never accepts an in-place credential
// replacement; a fresh process must build new pools from the new binding.
func (g *CredentialGuard) Check(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	failed := g.failed
	g.mu.Unlock()
	if failed {
		return ErrUnavailable
	}
	capacity, capacityErr := g.resolveIdentity(ctx, g.capacityID, secretref.PurposeCapacityValkeyCredentials)
	witness, witnessErr := g.resolveIdentity(ctx, g.witnessID, secretref.PurposeActionHistoryWitnessDSN)
	if capacityErr != nil || witnessErr != nil || capacity != g.capacity || witness != g.witness ||
		!g.now().Before(g.capacity.window.NotAfter) || !g.now().Before(g.witness.window.NotAfter) {
		g.fail()
		return ErrUnavailable
	}
	g.mu.Lock()
	failed = g.failed
	g.mu.Unlock()
	if failed {
		return ErrUnavailable
	}
	return nil
}

func (g *CredentialGuard) fail() {
	g.mu.Lock()
	if g.failed {
		g.mu.Unlock()
		return
	}
	g.failed = true
	drain := g.drain
	g.mu.Unlock()
	if drain != nil {
		drain()
	}
}

// StartPolling monitors idle upgraded streams as well as new actions. The
// drain callback must cancel the server and close both database client pools.
// Check calls also trigger that callback, exactly once.
func (g *CredentialGuard) StartPolling(ctx context.Context, drain func()) (<-chan struct{}, error) {
	if g == nil || ctx == nil || drain == nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	g.started, g.drain = true, drain
	failed := g.failed
	g.mu.Unlock()
	if failed {
		drain()
		return nil, ErrUnavailable
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(g.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if g.Check(ctx) != nil {
					return
				}
			}
		}
	}()
	return done, nil
}

// CredentialGatedAuthority inserts live secret authorization before every
// serialized Browser CDP action, including the initial ingress activation.
type CredentialGatedAuthority struct {
	Guard *CredentialGuard
	Next  gateway.DownstreamFenceAuthority
}

func (a CredentialGatedAuthority) AuthorizeAction(ctx context.Context, subject gateway.DownstreamFenceSubject,
	fence gateway.DownstreamFence, window time.Duration) (gateway.DownstreamFenceDecision, error) {
	if a.Guard == nil || a.Next == nil || a.Guard.Check(ctx) != nil {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	return a.Next.AuthorizeAction(ctx, subject, fence, window)
}

var _ gateway.DownstreamFenceAuthority = CredentialGatedAuthority{}
