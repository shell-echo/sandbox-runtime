package productpostgres

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestObservedGuestSigningBindingRejectsTupleDrift(t *testing.T) {
	now := time.Now().UTC()
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	clientNonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	request := guestagent.AuthRequest{
		Challenge: guestagent.Challenge{Type: "challenge", Nonce: nonce, ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)},
		Hello: guestagent.Hello{Type: "hello", GuestID: "gst-observed", BindingGeneration: 2,
			ProtocolVersion: guestagent.ProtocolVersion, ClientNonce: clientNonce,
			Capabilities: []string{"files.list", "guest.health"}},
	}
	signing, err := request.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	baseline := product.GuestAuthentication{
		GuestID: request.Hello.GuestID, BindingGeneration: request.Hello.BindingGeneration,
		ProtocolVersion: request.Hello.ProtocolVersion, ClientNonce: clientNonce,
		OfferedCapabilities: []string{"guest.health", "files.list"},
		SigningBytes:        signing, Signature: make([]byte, 64),
	}
	if !validObservedGuestSigningBinding(baseline, now) {
		t.Fatal("canonical signed tuple rejected")
	}
	checks := []struct {
		name   string
		mutate func(*product.GuestAuthentication)
	}{
		{"guest", func(v *product.GuestAuthentication) { v.GuestID = "gst-other" }},
		{"generation", func(v *product.GuestAuthentication) { v.BindingGeneration++ }},
		{"protocol", func(v *product.GuestAuthentication) { v.ProtocolVersion = "other" }},
		{"client nonce", func(v *product.GuestAuthentication) { v.ClientNonce = nonce }},
		{"capability", func(v *product.GuestAuthentication) { v.OfferedCapabilities = []string{"guest.health"} }},
		{"duplicate capability", func(v *product.GuestAuthentication) { v.OfferedCapabilities = []string{"guest.health", "guest.health"} }},
		{"oversized", func(v *product.GuestAuthentication) { v.SigningBytes = make([]byte, 4097) }},
		{"signature length", func(v *product.GuestAuthentication) { v.Signature = []byte{1} }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := baseline
			check.mutate(&candidate)
			if validObservedGuestSigningBinding(candidate, now) {
				t.Fatal("invalid tuple accepted for revoked evidence")
			}
		})
	}
	if validObservedGuestSigningBinding(baseline, now.Add(time.Minute)) {
		t.Fatal("expired challenge accepted for revoked evidence")
	}
}
