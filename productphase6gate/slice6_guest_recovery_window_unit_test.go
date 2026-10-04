//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSlice6NetworkCleanupDeadlineCannotRefreshOnNestedRestore(t *testing.T) {
	parent, cancel := context.WithTimeout(t.Context(), 45*time.Millisecond)
	defer cancel()
	first, stopFirst := slice6NetworkCleanupContext(parent)
	defer stopFirst()
	firstDeadline, ok := first.Deadline()
	if !ok {
		t.Fatal("first cleanup lacks absolute deadline")
	}
	nested, stopNested := slice6NetworkCleanupContext(first)
	defer stopNested()
	nestedDeadline, ok := nested.Deadline()
	if !ok || !nestedDeadline.Equal(firstDeadline) {
		t.Fatal("nested restore refreshed the cleanup deadline")
	}
	<-first.Done()
	select {
	case <-nested.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("nested restore continued past original cleanup deadline")
	}
	called := 0
	command := func(context.Context, ...string) ([]byte, error, bool) { called++; return nil, nil, false }
	guestProbe := func(context.Context, slice6GuestRecoveryEdge, bool) (slice6GuestRecoveryEdgeAction, error) {
		called++
		return slice6GuestRecoveryEdgeAction{}, nil
	}
	pgProbe := func(context.Context, slice6ProductPGFaultEdge, bool) (slice6ProductPGFaultAction, error) {
		called++
		return slice6ProductPGFaultAction{}, nil
	}
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	guestEdge := slice6GuestRecoveryEdge{Run: run, ProductID: strings.Repeat("b", 64),
		GuestID: strings.Repeat("c", 64), ProductNetworkID: strings.Repeat("d", 64)}
	guestDetached := slice6GuestRecoveryEdgeAction{RunID: run.id, ProductID: guestEdge.ProductID,
		GuestID: guestEdge.GuestID, ProductNetworkID: guestEdge.ProductNetworkID,
		Disconnected: true, AfterDigest: "sha256:" + strings.Repeat("e", 64)}
	if _, err := slice6RestoreGuestProductEdgeWithProbe(nested, guestEdge, guestDetached, command, guestProbe); err == nil {
		t.Fatal("expired Guest cleanup accepted")
	}
	pgEdge := slice6ProductPGFaultEdge{Run: run, ProductID: guestEdge.ProductID,
		PostgresID: strings.Repeat("f", 64), NetworkID: guestEdge.ProductNetworkID}
	pgDetached := slice6ProductPGFaultAction{RunID: run.id, ProductID: pgEdge.ProductID,
		PostgresID: pgEdge.PostgresID, NetworkID: pgEdge.NetworkID,
		Disconnected: true, AfterDigest: "sha256:" + strings.Repeat("1", 64)}
	if _, err := slice6RestoreProductPGEdgeWithProbe(nested, pgEdge, pgDetached, command, pgProbe); err == nil {
		t.Fatal("expired Product-PG cleanup accepted")
	}
	if called != 0 {
		t.Fatal("expired cleanup issued another Docker request or probe")
	}
}

func TestSlice6BlockedRestoreDoesNotProbeAfterOriginalDeadline(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	guestEdge := slice6GuestRecoveryEdge{Run: run, ProductID: strings.Repeat("b", 64),
		GuestID: strings.Repeat("c", 64), ProductNetworkID: strings.Repeat("d", 64)}
	guestDetached := slice6GuestRecoveryEdgeAction{RunID: run.id, ProductID: guestEdge.ProductID,
		GuestID: guestEdge.GuestID, ProductNetworkID: guestEdge.ProductNetworkID,
		ProductPID: 101, GuestPID: 102, ProductStartedAt: "start-product", GuestStartedAt: "start-guest",
		Disconnected: true, AfterDigest: "sha256:" + strings.Repeat("e", 64)}
	pgEdge := slice6ProductPGFaultEdge{Run: run, ProductID: guestEdge.ProductID,
		PostgresID: strings.Repeat("f", 64), NetworkID: guestEdge.ProductNetworkID}
	pgDetached := slice6ProductPGFaultAction{RunID: run.id, ProductID: pgEdge.ProductID,
		PostgresID: pgEdge.PostgresID, NetworkID: pgEdge.NetworkID,
		ProductPID: 101, PostgresPID: 103, ProductOtherNetworks: "other", PostgresNetworks: "pg",
		Disconnected: true, AfterDigest: "sha256:" + strings.Repeat("1", 64)}
	for _, role := range []string{"guest", "product-pg"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 55*time.Millisecond)
			defer cancel()
			commands, afterProbes := 0, 0
			command := func(ctx context.Context, _ ...string) ([]byte, error, bool) {
				commands++
				<-ctx.Done()
				return nil, ctx.Err(), false
			}
			if role == "guest" {
				probe := func(_ context.Context, _ slice6GuestRecoveryEdge, connected bool) (slice6GuestRecoveryEdgeAction, error) {
					if connected {
						afterProbes++
					}
					return slice6GuestRecoveryEdgeAction{BeforeDigest: guestDetached.AfterDigest,
						ProductPID: guestDetached.ProductPID, GuestPID: guestDetached.GuestPID,
						ProductStartedAt: guestDetached.ProductStartedAt, GuestStartedAt: guestDetached.GuestStartedAt}, nil
				}
				outcome, err := slice6RestoreGuestProductEdgeWithProbe(ctx, guestEdge, guestDetached, command, probe)
				if err == nil || !outcome.Attempted || !outcome.OutcomeUnknown {
					t.Fatalf("blocked Guest restore did not fail incomplete: %v", err)
				}
			} else {
				probe := func(_ context.Context, _ slice6ProductPGFaultEdge, connected bool) (slice6ProductPGFaultAction, error) {
					if connected {
						afterProbes++
					}
					return slice6ProductPGFaultAction{BeforeDigest: pgDetached.AfterDigest,
						ProductPID: pgDetached.ProductPID, PostgresPID: pgDetached.PostgresPID,
						ProductOtherNetworks: pgDetached.ProductOtherNetworks,
						PostgresNetworks:     pgDetached.PostgresNetworks}, nil
				}
				outcome, err := slice6RestoreProductPGEdgeWithProbe(ctx, pgEdge, pgDetached, command, probe)
				if err == nil || !outcome.Attempted || !outcome.OutcomeUnknown {
					t.Fatalf("blocked Product-PG restore did not fail incomplete: %v", err)
				}
			}
			if commands != 1 || afterProbes != 0 {
				t.Fatalf("deadline renewed or post-deadline request issued: commands=%d probes=%d", commands, afterProbes)
			}
		})
	}
}

func TestSlice6DisconnectMutationSharesPreRegisteredCleanupDeadline(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	checkCommand := func(t *testing.T) slice6NetworkCommand {
		t.Helper()
		return func(ctx context.Context, _ ...string) ([]byte, error, bool) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
				t.Error("disconnect command did not inherit the pre-registered finite cleanup deadline")
			}
			return nil, nil, false
		}
	}
	guestEdge := slice6GuestRecoveryEdge{Run: run, ProductID: strings.Repeat("b", 64),
		GuestID: strings.Repeat("c", 64), ProductNetworkID: strings.Repeat("d", 64)}
	guestProbe := func(_ context.Context, _ slice6GuestRecoveryEdge, connected bool) (slice6GuestRecoveryEdgeAction, error) {
		if connected {
			return slice6GuestRecoveryEdgeAction{ProductPID: 101, GuestPID: 102,
				ProductStartedAt: "product-start", GuestStartedAt: "guest-start"}, nil
		}
		return slice6GuestRecoveryEdgeAction{BeforeDigest: "sha256:" + strings.Repeat("e", 64),
			ProductPID: 101, GuestPID: 102,
			ProductStartedAt: "product-start", GuestStartedAt: "guest-start"}, nil
	}
	if action, err := slice6DetachGuestProductEdgeWithProbe(t.Context(), guestEdge,
		checkCommand(t), guestProbe); err != nil || !action.Disconnected {
		t.Fatalf("Guest action did not use shared deadline: %v", err)
	}
	pgEdge := slice6ProductPGFaultEdge{Run: run, ProductID: guestEdge.ProductID,
		PostgresID: strings.Repeat("f", 64), NetworkID: guestEdge.ProductNetworkID}
	pgProbe := func(_ context.Context, _ slice6ProductPGFaultEdge, connected bool) (slice6ProductPGFaultAction, error) {
		if connected {
			return slice6ProductPGFaultAction{ProductPID: 101, PostgresPID: 103,
				ProductStartedAt: "product-start", PostgresStartedAt: "pg-start",
				ProductOtherNetworks: "other", PostgresNetworks: "pg"}, nil
		}
		return slice6ProductPGFaultAction{BeforeDigest: "sha256:" + strings.Repeat("1", 64),
			ProductPID: 101, PostgresPID: 103,
			ProductStartedAt: "product-start", PostgresStartedAt: "pg-start",
			ProductOtherNetworks: "other", PostgresNetworks: "pg"}, nil
	}
	if action, err := slice6DisconnectProductPGEdgeWithProbe(t.Context(), pgEdge,
		checkCommand(t), pgProbe); err != nil || !action.Disconnected {
		t.Fatalf("Product-PG action did not use shared deadline: %v", err)
	}
}
