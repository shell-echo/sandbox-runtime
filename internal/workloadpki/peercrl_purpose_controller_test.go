package workloadpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type purposePeerIndex struct {
	mappingDigest string
	lookups       int
}

func (p *purposePeerIndex) MappingDigest() string { return p.mappingDigest }

func (p *purposePeerIndex) AuthorizedSourceID(_, mappingDigest, edgeID, _, direction, anchorID, issuerDigest,
	postgresOwner string) (string, error) {
	p.lookups++
	if mappingDigest != p.mappingDigest || direction != "outbound" || anchorID != "external-server-ca" ||
		issuerDigest == "" {
		return "", ErrDenied
	}
	if edgeID == "postgres-server-peer-edge" && postgresOwner == "product-runtime" {
		return "postgres-server-peer", nil
	}
	if edgeID == "ordinary-peer-edge" && postgresOwner == "" {
		return "ordinary-peer", nil
	}
	return "", ErrDenied
}

type purposePeerAuthority struct {
	fakeCertificateAuthority
	material crlTestMaterial
	reads    int
}

func (p *purposePeerAuthority) PeerIssuerCertificate(context.Context, string) ([]byte, error) {
	p.reads++
	return bytes.Clone(p.material.issuerDER), nil
}

func (p *purposePeerAuthority) PeerRevocations(context.Context, string, []byte) (RevocationSnapshot, error) {
	p.reads++
	return RevocationSnapshot{DER: bytes.Clone(p.material.snapshot.DER),
		ThisUpdate: p.material.snapshot.ThisUpdate, NextUpdate: p.material.snapshot.NextUpdate}, nil
}

func (p *purposePeerAuthority) ValidatePeerSources([]phase6security.PeerCRLSource) error { return nil }

func TestControllerPeerCRLIndependentlyRejectsCrossPurposeAndOwner(t *testing.T) {
	fixture := newProtocolFixture(t)
	material := newCRLTestMaterial(t, fixture.now, 42, true)
	issuerHash := sha256.Sum256(material.issuerDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerHash[:])
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postgres := phase6PostgresPolicy(t, phase6DelegationCase{"product-runtime", "product_postgres_tls_agent",
		"product", securityprincipal.KindRuntimeRole, securityprincipal.RoleProduct})
	postgres.PublicKey, postgres.ExpectedUID, postgres.ExpectedGID = public, uint32(os.Getuid()), uint32(os.Getgid())
	if postgres.Validate() != nil {
		t.Fatal("fixed PostgreSQL-purpose policy invalid")
	}
	ordinary := fixture.policy
	ordinary.ExpectedUID, ordinary.ExpectedGID = postgres.ExpectedUID, postgres.ExpectedGID
	if ordinary.Validate() != nil {
		t.Fatal("ordinary signed policy invalid")
	}
	otherOwner := phase6PostgresPolicy(t, phase6DelegationCase{"provider-runtime", "provider_postgres_tls_agent",
		"provider", securityprincipal.KindRuntimeRole, securityprincipal.RoleProvider})
	otherOwner.ID = "phase6-postgres-purpose-provider"
	otherOwner.PublicKey, otherOwner.ExpectedUID, otherOwner.ExpectedGID = public, postgres.ExpectedUID, postgres.ExpectedGID
	if otherOwner.Validate() != nil {
		t.Fatal("other-owner purpose policy invalid")
	}
	index := &purposePeerIndex{mappingDigest: "sha256:" + hex.EncodeToString(issuerHash[:])}
	authority := &purposePeerAuthority{fakeCertificateAuthority: fakeCertificateAuthority{fixture: fixture}, material: material}
	controller := &Controller{permit: make(chan struct{}, 1),
		ledgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		ledger:     Ledger{Schema: LedgerSchema, Revision: 1},
		policies:   map[string]Policy{postgres.ID: postgres, ordinary.ID: ordinary, otherOwner.ID: otherOwner},
		authority:  authority, controllerKeyID: fixture.controllerID, controllerKey: fixture.controllerPriv,
		now: func() time.Time { return fixture.now }, maximumActive: 2, maximumLedgerAge: time.Hour,
		peerCRLProfile: &phase6security.Profile{ProfileDigest: index.mappingDigest}, peerCRLSources: &phase6security.PeerCRLSources{},
		peerCRLIdentity: index}
	controller.permit <- struct{}{}
	request := func(policy Policy, key ed25519.PrivateKey, edge string, marker byte) PeerCRLRequest {
		t.Helper()
		value, err := NewPeerCRLRequest(policy, "peer-crl-purpose-"+hex.EncodeToString([]byte{marker}),
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 32)),
			fixture.now.Add(30*time.Second), index.mappingDigest, edge, policy.Subject.Digest(),
			"outbound", "external-server-ca", issuerDigest, "postgres-server-peer", key, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, candidate := range []struct {
		name    string
		policy  Policy
		key     ed25519.PrivateKey
		edge    string
		marker  byte
		allowed bool
	}{
		{"ordinary signer to PostgreSQL", ordinary, fixture.agentPrivate, "postgres-server-peer-edge", 1, false},
		{"PostgreSQL signer to ordinary", postgres, private, "ordinary-peer-edge", 2, false},
		{"PostgreSQL signer to other owner", otherOwner, private, "postgres-server-peer-edge", 3, false},
		{"correct PostgreSQL signer", postgres, private, "postgres-server-peer-edge", 4, true},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			before := authority.reads
			response, err := controller.HandlePeerCRL(t.Context(), request(candidate.policy, candidate.key,
				candidate.edge, candidate.marker), candidate.policy.ExpectedUID, candidate.policy.ExpectedGID)
			if candidate.allowed {
				if err != nil || response.Status != StatusOK || authority.reads != before+2 {
					t.Fatalf("correct policy/source rejected: %v status=%s reads=%d", err, response.Status, authority.reads-before)
				}
			} else if err == nil || response.Status != StatusDenied || authority.reads != before {
				t.Fatalf("cross-purpose source reached authority: %v status=%s reads=%d", err, response.Status, authority.reads-before)
			}
		})
	}
	if index.lookups != 4 {
		t.Fatalf("controller did not independently use prevalidated index: %d", index.lookups)
	}
}
