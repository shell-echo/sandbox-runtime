package rediscapacity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestNewActionFencerRequiresExactSessionCapacity(t *testing.T) {
	if fencer, err := NewActionFencer(nil); fencer != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("NewActionFencer(nil) = %#v, %v", fencer, err)
	}
	options := testOptions(t)
	options.MaxPerTenant = 2
	options.MaxPerSession = 2
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if fencer, err := NewActionFencer(capacity); fencer != nil || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("NewActionFencer(multi-session) = %#v, %v", fencer, err)
	}
}

func TestActionFencingDescriptorContainsOnlyStableFingerprints(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "private-action-fencing-namespace"
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	fencer, err := NewActionFencer(capacity)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fencer.Descriptor()
	formatted := fmt.Sprintf("%+v", descriptor)
	for _, forbidden := range []string{options.Namespace, "sandbox-runtime:", capacity.keyTag} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("Descriptor() exposed private state %q: %s", forbidden, formatted)
		}
	}
	for _, value := range []string{
		descriptor.PolicyFormat, descriptor.PolicyFingerprint, descriptor.CapacityPolicyFingerprint,
		descriptor.ProvisionScript, descriptor.AuthorizeScript,
	} {
		if value == "" {
			t.Fatalf("Descriptor() contains empty identity: %#v", descriptor)
		}
	}
	if descriptor.CapacityPolicyFingerprint != capacity.Descriptor().PolicyFingerprint {
		t.Fatal("action policy is not bound to the unchanged capacity policy")
	}
	if descriptor.MaxClaimLifetimeMS != gateway.MaxDownstreamClaimLifetime.Milliseconds() ||
		descriptor.MaxActionWindowMS != gateway.MaxDownstreamActionWindow.Milliseconds() {
		t.Fatalf("descriptor bounds = %#v", descriptor)
	}
}

func TestConnectionLeaseProjectsOpaqueFenceOnlyWhileUsable(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject("tenant-private", "sandbox-private", "browser-private")
	tenant, session := subjectFingerprints(subject)
	member := strings.Repeat("a", 32) + ":00000000000000000001:" + tenant + ":" + session + ":" +
		fmt.Sprint(subject.ExpiresAt.UnixMilli())

	newLease := func() *connectionLease {
		return &connectionLease{capacity: capacity, member: member}
	}
	t.Run("stable opaque claim", func(t *testing.T) {
		lease := newLease()
		first, err := lease.DownstreamFence()
		if err != nil {
			t.Fatal(err)
		}
		second, err := lease.DownstreamFence()
		if err != nil || second.Opaque() != first.Opaque() {
			t.Fatalf("repeated claim = %v, %v", second, err)
		}
		want := actionClaimPrefix + base64.RawURLEncoding.EncodeToString([]byte(member))
		if first.Opaque() != want {
			t.Fatal("claim did not encode the exact capacity member")
		}
		if strings.Contains(fmt.Sprint(first), member) || strings.Contains(fmt.Sprintf("%#v", first), member) {
			t.Fatal("formatted claim exposed the capacity member")
		}
	})
	for _, test := range []struct {
		name string
		set  func(*connectionLease)
		want error
	}{
		{"release started", func(lease *connectionLease) { lease.releasing = true }, gateway.ErrDownstreamFenceLost},
		{"released", func(lease *connectionLease) { lease.released = true }, gateway.ErrDownstreamFenceLost},
		{"lease lost", func(lease *connectionLease) { lease.terminationKind = "lost" }, gateway.ErrDownstreamFenceLost},
		{"authority unavailable", func(lease *connectionLease) { lease.terminationKind = "unavailable" }, gateway.ErrDownstreamUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := newLease()
			test.set(lease)
			if claim, err := lease.DownstreamFence(); claim.Opaque() != "" || !errors.Is(err, test.want) {
				t.Fatalf("DownstreamFence() = %v, %v; want %v", claim, err, test.want)
			}
		})
	}
}

func TestDecodeActionClaimRejectsNonCanonicalOrMalformedMembers(t *testing.T) {
	inputs := []string{
		"not-a-member",
		strings.Repeat("a", 32) + ":00000000000000000000:" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":1",
		strings.Repeat("a", 32) + ":00000000000000000001:" + strings.Repeat("b", 63) + ":" + strings.Repeat("c", 64) + ":1",
		strings.Repeat("a", 32) + ":00000000000000000001:" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":9999999999999999",
	}
	for _, member := range inputs {
		claim, err := gateway.NewDownstreamFence(actionClaimPrefix + base64.RawURLEncoding.EncodeToString([]byte(member)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := decodeActionClaim(claim); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
			t.Fatalf("decodeActionClaim(%q) error = %v", member, err)
		}
	}

	validMember := strings.Repeat("a", 32) + ":00000000000000000001:" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":1"
	padded, err := gateway.NewDownstreamFence(actionClaimPrefix + base64.URLEncoding.EncodeToString([]byte(validMember)))
	if err == nil {
		t.Fatalf("padded claim unexpectedly passed root validation: %v", padded)
	}
}

func TestActionFencerRejectsInvalidInputBeforeRedis(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	fencer, err := NewActionFencer(capacity)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := gateway.NewDownstreamFence("v1.YQ")
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []gateway.DownstreamFenceSubject{
		{},
		{TenantID: "tenant", SandboxID: "sandbox", BrowserSessionID: "browser", CapabilityProfileID: "browser-v1", ConnectionGeneration: 1, ExpiresAt: time.UnixMilli(maxLuaExactInteger + 1)},
	} {
		decision, err := fencer.AuthorizeAction(t.Context(), subject, claim, 50*time.Millisecond)
		if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
			t.Fatalf("AuthorizeAction() = %#v, %v", decision, err)
		}
	}
	validSubject := gateway.DownstreamFenceSubject{
		TenantID: "tenant", SandboxID: "sandbox", BrowserSessionID: "browser",
		CapabilityProfileID: "browser-v1", ConnectionGeneration: 1, ExpiresAt: time.Now().Add(time.Minute),
	}
	for _, window := range []time.Duration{
		0, gateway.MinDownstreamActionWindow - time.Millisecond,
		gateway.MaxDownstreamActionWindow + time.Millisecond, gateway.MinDownstreamActionWindow + time.Nanosecond,
	} {
		decision, err := fencer.AuthorizeAction(t.Context(), validSubject, claim, window)
		if decision.Activated || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
			t.Fatalf("AuthorizeAction(window=%s) = %#v, %v", window, decision, err)
		}
	}
}
