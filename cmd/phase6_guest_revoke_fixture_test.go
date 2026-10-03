//go:build phase6slice6fixture

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/product"
)

func guestRevokeFixtureTestInput() guestRevokeFixtureInput {
	run := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("b", 64)
	return guestRevokeFixtureInput{
		Protocol: guestRevokeFixtureProtocol, Operation: guestRevokeFixtureOperation,
		RunID: run, ProfileDigest: profile,
		ExecutableDigest:   "sha256:" + strings.Repeat("c", 64),
		ProductContainerID: strings.Repeat("d", 64),
		InitialBinding: guestBindingFixtureReceipt{
			Protocol: guestBindingFixtureProtocol, RunID: run, ProfileDigest: profile,
			PublicKeySHA256: "sha256:" + strings.Repeat("e", 64),
			WorkspaceID:     "wrk-run-owned", GuestID: "gst-run-owned",
			BindingGeneration: 1, SlotGeneration: 1, EventCount: 1,
			AuditCount: 1, IdempotentReplay: true,
		},
	}
}

func TestGuestRevokeFixtureRejectsUnboundInput(t *testing.T) {
	base := guestRevokeFixtureTestInput()
	document, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeGuestRevokeFixtureInput(document); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*guestRevokeFixtureInput){
		"operation": func(v *guestRevokeFixtureInput) { v.Operation = "read-any-binding" },
		"target":    func(v *guestRevokeFixtureInput) { v.ProductContainerID = strings.Repeat("f", 63) },
		"artifact":  func(v *guestRevokeFixtureInput) { v.ExecutableDigest = "sha256:bad" },
		"run":       func(v *guestRevokeFixtureInput) { v.RunID = strings.Repeat("f", 32) },
		"profile":   func(v *guestRevokeFixtureInput) { v.ProfileDigest = "sha256:" + strings.Repeat("f", 64) },
		"receipt":   func(v *guestRevokeFixtureInput) { v.InitialBinding.GuestID = "" },
		"key":       func(v *guestRevokeFixtureInput) { v.InitialBinding.PublicKeySHA256 = "sha256:bad" },
		"audit":     func(v *guestRevokeFixtureInput) { v.InitialBinding.AuditCount = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			encoded, _ := json.Marshal(changed)
			if _, err := decodeGuestRevokeFixtureInput(encoded); err == nil {
				t.Fatal("unbound mutation fixture input was admitted")
			}
		})
	}
	for _, changed := range [][]byte{
		append(bytes.Clone(document), '\n'),
		[]byte(strings.Replace(string(document), `"protocol":`, `"extra":true,"protocol":`, 1)),
		[]byte(strings.Replace(string(document), `"protocol":`, `"protocol":"`+guestRevokeFixtureProtocol+`","protocol":`, 1)),
		[]byte(strings.Repeat("x", 4097)),
	} {
		if _, err := decodeGuestRevokeFixtureInput(changed); err == nil {
			t.Fatal("noncanonical, unknown or oversized mutation input was admitted")
		}
	}
}

func TestGuestRevokeFixtureBindingMatchesOnlyInitialScope(t *testing.T) {
	input := guestRevokeFixtureTestInput()
	public := bytes.Repeat([]byte{7}, 32)
	digest := sha256.Sum256(public)
	input.InitialBinding.PublicKeySHA256 = "sha256:" + hex.EncodeToString(digest[:])
	base := guestRevokeFixtureBinding{
		TenantID: "tenant-phase6-" + input.RunID, WorkspaceID: input.InitialBinding.WorkspaceID,
		SlotKey: product.PrimarySlotKey, SlotProfileID: "coding-shell-v1",
		SlotGeneration: 1, BindingGeneration: 1, GuestID: input.InitialBinding.GuestID,
		PublicKey: public, CredentialDigest: digest[:], ProtocolVersion: guestagent.ProtocolVersion,
		Capabilities: []byte(`["development.health"]`), State: "connected", ConnectionNonce: "nonce",
		ExpiresAt: time.Now().Add(5 * time.Minute), ObservedAt: time.Now(),
	}
	if !guestRevokeFixtureBindingMatches(input, base) {
		t.Fatal("exact initial binding was rejected")
	}
	for name, mutate := range map[string]func(*guestRevokeFixtureBinding){
		"tenant":  func(v *guestRevokeFixtureBinding) { v.TenantID = "tenant-other" },
		"slot":    func(v *guestRevokeFixtureBinding) { v.SlotKey = "other" },
		"key":     func(v *guestRevokeFixtureBinding) { v.PublicKey = bytes.Repeat([]byte{8}, 32) },
		"digest":  func(v *guestRevokeFixtureBinding) { v.CredentialDigest = bytes.Repeat([]byte{9}, 32) },
		"cap":     func(v *guestRevokeFixtureBinding) { v.Capabilities = []byte(`["other"]`) },
		"guest":   func(v *guestRevokeFixtureBinding) { v.GuestID = "gst-other" },
		"profile": func(v *guestRevokeFixtureBinding) { v.SlotProfileID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if guestRevokeFixtureBindingMatches(input, changed) {
				t.Fatal("drifted binding was admitted")
			}
		})
	}
	if guestdevelopment.CapabilityHealth != "development.health" {
		t.Fatal("Guest health capability drift")
	}
	after := base
	after.State = "revoked"
	after.ConnectionNonce = ""
	if !guestRevokeFixtureAfterMatches(base, after) {
		t.Fatal("only state and nonce changed but after-scope check failed")
	}
	after.PublicKey = bytes.Repeat([]byte{8}, 32)
	if guestRevokeFixtureAfterMatches(base, after) {
		t.Fatal("public-key drift survived after-scope check")
	}
}

func TestGuestRevokeFixtureOutcomeNeverRetriesUnknown(t *testing.T) {
	now := time.Now()
	before := guestRevokeFixtureBinding{TenantID: "tenant", GuestID: "guest", State: "connected",
		ConnectionNonce: "nonce", ExpiresAt: now.Add(time.Minute), ObservedAt: now}
	after := before
	after.State, after.ConnectionNonce = "revoked", ""
	if outcome, err := guestRevokeFixtureOutcome(before, after, nil); err != nil || outcome != "confirmed" {
		t.Fatal("confirmed revoke was not classified exactly")
	}
	if outcome, err := guestRevokeFixtureOutcome(before, after, errors.New("write outcome unknown")); err != nil || outcome != "revoked-after-unknown" {
		t.Fatal("unknown write was misattributed as confirmed")
	}
	if outcome, err := guestRevokeFixtureOutcome(before, before, errors.New("write outcome unknown")); err != nil || outcome != "not-committed-after-unknown" {
		t.Fatal("still-connected binding was misclassified")
	}
	after.GuestID = "other"
	if _, err := guestRevokeFixtureOutcome(before, after, nil); err == nil {
		t.Fatal("cross-binding readback survived outcome classification")
	}
	after = before
	after.State, after.ConnectionNonce = "revoked", ""
	after.ObservedAt = after.ExpiresAt
	if _, err := guestRevokeFixtureOutcome(before, after, nil); err == nil {
		t.Fatal("expired binding was accepted as live revocation")
	}
}
