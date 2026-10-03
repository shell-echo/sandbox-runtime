//go:build phase6slice6fixture

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestGuestBindingFixtureRejectsUnboundOrNoncanonicalInput(t *testing.T) {
	runID := strings.Repeat("a", 32)
	public := make([]byte, 32)
	for index := range public {
		public[index] = byte(index + 1)
	}
	sum := sha256.Sum256(public)
	base := guestBindingFixtureInput{Protocol: guestBindingFixtureProtocol, RunID: runID,
		ProfileDigest: "sha256:" + strings.Repeat("b", 64), TenantID: "tenant-phase6-" + runID,
		ActorID: "actor-phase6-" + runID, PublicKey: public,
		PublicKeySHA256: "sha256:" + hex.EncodeToString(sum[:])}
	document, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeGuestBindingFixtureInput(document); err != nil {
		t.Fatalf("canonical run-bound public fixture input rejected: %v", err)
	}
	for name, mutate := range map[string]func(*guestBindingFixtureInput){
		"run":     func(v *guestBindingFixtureInput) { v.RunID = strings.Repeat("c", 32) },
		"profile": func(v *guestBindingFixtureInput) { v.ProfileDigest = "sha256:bad" },
		"tenant":  func(v *guestBindingFixtureInput) { v.TenantID = "tenant-other" },
		"actor":   func(v *guestBindingFixtureInput) { v.ActorID = "actor-other" },
		"key":     func(v *guestBindingFixtureInput) { v.PublicKey[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.PublicKey = append([]byte(nil), base.PublicKey...)
			mutate(&changed)
			encoded, _ := json.Marshal(changed)
			if _, err := decodeGuestBindingFixtureInput(encoded); err == nil {
				t.Fatal("unbound fixture input accepted")
			}
		})
	}
	for _, candidate := range [][]byte{
		append(append([]byte(nil), document...), '\n'),
		[]byte(strings.Replace(string(document), `"protocol":`, `"extra":true,"protocol":`, 1)),
		[]byte(strings.Replace(string(document), `"protocol":`, `"protocol":"`+guestBindingFixtureProtocol+`","protocol":`, 1)),
		[]byte(strings.Repeat("x", 4097)),
	} {
		if _, err := decodeGuestBindingFixtureInput(candidate); err == nil {
			t.Fatal("noncanonical, duplicate, unknown or oversized fixture input accepted")
		}
	}
}

func TestGuestBindingFixturePrimarySlotIsExact(t *testing.T) {
	policy := guestBindingFixturePrimarySlot{}
	base := product.SlotSpec{SlotKey: product.PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1",
		DesiredState: "ready", RequiredCapabilities: []product.CapabilityRequirement{
			{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"},
			{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"},
		}}
	if err := policy.AuthorizePrimarySlot(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.RequiredCapabilities = append([]product.CapabilityRequirement(nil), base.RequiredCapabilities...)
	changed.RequiredCapabilities[1].CapabilityID = "sandbox.desktop"
	if policy.AuthorizePrimarySlot(context.Background(), changed) == nil {
		t.Fatal("fixture primary-slot policy admitted another business capability")
	}
}
