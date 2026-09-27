package phase6egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type mutableCredentialResolver struct {
	mu       sync.Mutex
	material map[string]secretref.SecretMaterial
	err      error
}

func (r *mutableCredentialResolver) Resolve(_ context.Context, id string, purpose secretref.Purpose, tenant string) (secretref.SecretMaterial, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return secretref.SecretMaterial{}, r.err
	}
	material, ok := r.material[id]
	if !ok || material.Binding.Purpose != purpose || material.Binding.TenantID != tenant {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material, nil
}

func testCredentialMaterial(purpose secretref.Purpose, id string, value []byte, now time.Time) secretref.SecretMaterial {
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: secretref.Reference("secret://vault/" + id), Version: "v1", Purpose: purpose,
		TenantID: secretref.SystemTenant, Role: secretref.RoleGateway}
	digest := sha256.Sum256(value)
	return secretref.SecretMaterial{Binding: binding, Bytes: append([]byte(nil), value...),
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), State: secretref.KeyActive}}
}

func testCredentialGuard(t *testing.T) (*CredentialGuard, *mutableCredentialResolver, *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	resolver := &mutableCredentialResolver{material: map[string]secretref.SecretMaterial{
		"capacity": testCredentialMaterial(secretref.PurposeCapacityValkeyCredentials, "capacity",
			[]byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"ingress_capacity","password":"secret"}`), now),
		"witness": testCredentialMaterial(secretref.PurposeActionHistoryWitnessDSN, "witness",
			[]byte("postgres://ingress_witness:secret@witness.sandbox-runtime.test:5432/action_history?sslmode=verify-full"), now),
	}}
	guard, capacity, witness, err := NewCredentialGuard(context.Background(), resolver, "capacity", "witness",
		WitnessTarget{Host: "witness.sandbox-runtime.test", Port: 5432, Database: "action_history", User: "ingress_witness"},
		100*time.Millisecond, func() time.Time { return now })
	if err != nil || capacity.Username != "ingress_capacity" || witness == nil || witness.ConnConfig.Database != "action_history" {
		t.Fatalf("credential guard bootstrap = %v, %#v, %#v", err, capacity, witness)
	}
	return guard, resolver, &now
}

func TestCredentialGuardLatchesRotationAndDrainsExactlyOnce(t *testing.T) {
	guard, resolver, _ := testCredentialGuard(t)
	if err := guard.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	var drains atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := guard.StartPolling(ctx, func() { drains.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	changed := resolver.material["capacity"]
	changed.Revision = "revision-2"
	resolver.material["capacity"] = changed
	resolver.mu.Unlock()
	if err := guard.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rotated credential accepted: %v", err)
	}
	if err := guard.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("latched credential failure accepted: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle credential monitor did not stop")
	}
	if got := drains.Load(); got != 1 {
		t.Fatalf("drains = %d, want 1", got)
	}
}

func TestCredentialGuardIdleAgentLossAndExpiry(t *testing.T) {
	t.Run("agent loss", func(t *testing.T) {
		guard, resolver, _ := testCredentialGuard(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		drained := make(chan struct{}, 1)
		done, err := guard.StartPolling(ctx, func() { drained <- struct{}{} })
		if err != nil {
			t.Fatal(err)
		}
		resolver.mu.Lock()
		resolver.err = secretref.ErrUnavailable
		resolver.mu.Unlock()
		select {
		case <-drained:
		case <-time.After(time.Second):
			t.Fatal("idle agent loss did not drain")
		}
		<-done
	})
	t.Run("expiry", func(t *testing.T) {
		guard, _, now := testCredentialGuard(t)
		*now = now.Add(2 * time.Minute)
		if err := guard.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expired material accepted: %v", err)
		}
	})
}

type countingFenceAuthority struct{ calls int }

func (a *countingFenceAuthority) AuthorizeAction(context.Context, gateway.DownstreamFenceSubject,
	gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
	a.calls++
	return gateway.DownstreamFenceDecision{}, nil
}

func TestCredentialGatedAuthorityDeniesAfterRevocation(t *testing.T) {
	guard, resolver, _ := testCredentialGuard(t)
	next := &countingFenceAuthority{}
	authority := CredentialGatedAuthority{Guard: guard, Next: next}
	if _, err := authority.AuthorizeAction(context.Background(), gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, time.Second); err != nil || next.calls != 1 {
		t.Fatalf("healthy authority = %v, calls=%d", err, next.calls)
	}
	resolver.mu.Lock()
	resolver.err = secretref.ErrRevoked
	resolver.mu.Unlock()
	if _, err := authority.AuthorizeAction(context.Background(), gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, time.Second); !errors.Is(err, gateway.ErrDownstreamUnavailable) || next.calls != 1 {
		t.Fatalf("revoked authority = %v, calls=%d", err, next.calls)
	}
}

func TestCredentialGuardRejectsWrongTargetAndMalformedSecret(t *testing.T) {
	_, resolver, _ := testCredentialGuard(t)
	for name, target := range map[string]WitnessTarget{
		"wrong database": {Host: "witness.sandbox-runtime.test", Port: 5432, Database: "product", User: "ingress_witness"},
		"wrong user":     {Host: "witness.sandbox-runtime.test", Port: 5432, Database: "action_history", User: "gateway"},
		"wrong host":     {Host: "other.sandbox-runtime.test", Port: 5432, Database: "action_history", User: "ingress_witness"},
	} {
		t.Run(name, func(t *testing.T) {
			if guard, _, _, err := NewCredentialGuard(context.Background(), resolver, "capacity", "witness",
				target, time.Second, time.Now); guard != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("mismatched witness target accepted: %v", err)
			}
		})
	}
	resolver.mu.Lock()
	invalid := resolver.material["capacity"]
	invalid.Bytes = []byte(`{"protocol":"sandbox-runtime.capacity-valkey-credentials.v1","username":"default","password":"secret"}`)
	digest := sha256.Sum256(invalid.Bytes)
	invalid.Digest = "sha256:" + hex.EncodeToString(digest[:])
	resolver.material["capacity"] = invalid
	resolver.mu.Unlock()
	if guard, _, _, err := NewCredentialGuard(context.Background(), resolver, "capacity", "witness",
		WitnessTarget{Host: "witness.sandbox-runtime.test", Port: 5432, Database: "action_history", User: "ingress_witness"},
		time.Second, time.Now); guard != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed capacity credential accepted: %v", err)
	}
}
