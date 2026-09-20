package tokenidentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const (
	testIssuer   = "https://identity.product.example.test"
	testAudience = "urn:shell-echo:sandbox-runtime:product-api:production"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestProductionIdentityAcceptsOverlappingActiveKeys(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	publicA, privateA, _ := ed25519.GenerateKey(rand.Reader)
	publicB, privateB, _ := ed25519.GenerateKey(rand.Reader)
	path := writeKeyRing(t, now, map[string]ed25519.PublicKey{"key-a": publicA, "key-b": publicB}, nil)
	authenticator, err := load(path, testIssuer, testAudience, 30*time.Second, 15*time.Minute, fixedClock{now})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for keyID, privateKey := range map[string]ed25519.PrivateKey{"key-a": privateA, "key-b": privateB} {
		principal, err := authenticator.Authenticate(context.Background(), signToken(t, keyID, privateKey, claimsAt(now)))
		if err != nil {
			t.Fatalf("Authenticate %s: %v", keyID, err)
		}
		if principal.TenantID != "tenant-production" || principal.Role != productapi.RoleOwner || principal.Actor.ID != "actor-production" {
			t.Fatalf("principal = %#v", principal)
		}
	}
}

func TestProductionIdentityRejectsRevokedKeyAndClosedPolicyViolations(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	revokedPath := writeKeyRing(t, now, map[string]ed25519.PublicKey{"key-a": publicKey}, []string{"key-a"})
	revoked, err := load(revokedPath, testIssuer, testAudience, 30*time.Second, 15*time.Minute, fixedClock{now})
	if err != nil {
		t.Fatalf("Load revoked ring: %v", err)
	}
	if _, err := revoked.Authenticate(context.Background(), signToken(t, "key-a", privateKey, claimsAt(now))); err == nil {
		t.Fatal("revoked key authenticated")
	}

	activePath := writeKeyRing(t, now, map[string]ed25519.PublicKey{"key-a": publicKey}, nil)
	active, err := load(activePath, testIssuer, testAudience, 30*time.Second, 15*time.Minute, fixedClock{now})
	if err != nil {
		t.Fatalf("Load active ring: %v", err)
	}
	tests := map[string]func(*tokenClaims){
		"issuer":        func(c *tokenClaims) { c.Issuer = "https://other.example.test" },
		"audience":      func(c *tokenClaims) { c.Audience = "https://other.example.test" },
		"expired":       func(c *tokenClaims) { c.ExpiresAt = now.Add(-time.Minute).Unix() },
		"future":        func(c *tokenClaims) { c.NotBefore = now.Add(time.Minute).Unix() },
		"long lifetime": func(c *tokenClaims) { c.ExpiresAt = now.Add(16 * time.Minute).Unix() },
		"bad role":      func(c *tokenClaims) { c.Role = "administrator" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claims := claimsAt(now)
			mutate(&claims)
			if _, err := active.Authenticate(context.Background(), signToken(t, "key-a", privateKey, claims)); err == nil {
				t.Fatal("invalid token authenticated")
			}
		})
	}
	claimsDocument := map[string]any{}
	rawClaims, _ := json.Marshal(claimsAt(now))
	if err := json.Unmarshal(rawClaims, &claimsDocument); err != nil {
		t.Fatal(err)
	}
	claimsDocument["unexpected"] = true
	if _, err := active.Authenticate(context.Background(), signClaimsDocument(t, "key-a", privateKey, claimsDocument)); err == nil {
		t.Fatal("token with an unknown claim authenticated")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := active.Authenticate(cancelled, signToken(t, "key-a", privateKey, claimsAt(now))); err == nil {
		t.Fatal("cancelled authentication accepted")
	}
}

func TestProductionIdentityRejectsMalformedKeyRings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	for name, body := range map[string]string{
		"unknown field": `{"version":"` + KeyRingVersion + `","keys":[],"revoked_key_ids":[],"unknown":true}`,
		"no keys":       `{"version":"` + KeyRingVersion + `","keys":[],"revoked_key_ids":[]}`,
		"trailing":      `{"version":"` + KeyRingVersion + `","keys":[],"revoked_key_ids":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := load(path, testIssuer, testAudience, 0, time.Minute, fixedClock{time.Now()}); err == nil {
				t.Fatal("invalid key ring loaded")
			}
		})
	}
}

func writeKeyRing(t *testing.T, now time.Time, keys map[string]ed25519.PublicKey, revoked []string) string {
	t.Helper()
	document := keyRingDocument{Version: KeyRingVersion, RevokedKeyIDs: revoked}
	if document.RevokedKeyIDs == nil {
		document.RevokedKeyIDs = []string{}
	}
	for keyID, publicKey := range keys {
		document.Keys = append(document.Keys, keyDocument{KeyID: keyID, Algorithm: "EdDSA", PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339)})
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ring.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claimsAt(now time.Time) tokenClaims {
	return tokenClaims{Issuer: testIssuer, Audience: testAudience, Subject: "actor-production", TenantID: "tenant-production",
		ActorType: product.ActorHuman, ActorID: "actor-production", Role: productapi.RoleOwner, IssuedAt: now.Add(-time.Minute).Unix(),
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), JTI: "jti-production-0001"}
}

func signToken(t *testing.T, keyID string, privateKey ed25519.PrivateKey, claims tokenClaims) string {
	t.Helper()
	raw, _ := json.Marshal(claims)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return signClaimsDocument(t, keyID, privateKey, document)
}

func signClaimsDocument(t *testing.T, keyID string, privateKey ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(tokenHeader{Algorithm: "EdDSA", KeyID: keyID, Type: expectedTokenType})
	payload, _ := json.Marshal(claims)
	first := base64.RawURLEncoding.EncodeToString(header)
	second := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(privateKey, []byte(first+"."+second))
	return first + "." + second + "." + base64.RawURLEncoding.EncodeToString(signature)
}
