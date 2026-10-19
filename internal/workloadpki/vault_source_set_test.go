package workloadpki

import (
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestVaultPeerSourcesRequireExactSet(t *testing.T) {
	general := phase6security.PeerCRLSource{ID: "general-peer", Mount: "pki",
		IssuerID: "11111111-1111-4111-8111-111111111111", IssuerDigest: "sha256:" + strings.Repeat("a", 64)}
	broker := phase6security.PeerCRLSource{ID: "broker-peer", Mount: "pki",
		IssuerID: "22222222-2222-4222-8222-222222222222", IssuerDigest: "sha256:" + strings.Repeat("b", 64)}
	client := &VaultClient{requireImmediateCompleteCRL: true, peerIssuerSources: map[string]VaultPeerIssuerSource{}}
	for _, source := range []phase6security.PeerCRLSource{general, broker} {
		client.peerIssuerSources[source.ID] = VaultPeerIssuerSource{SourceID: source.ID,
			Mount: source.Mount, IssuerID: source.IssuerID, IssuerDigest: source.IssuerDigest}
	}
	for _, sources := range [][]phase6security.PeerCRLSource{{general, broker}, {broker, general}} {
		if err := client.ValidatePeerSources(sources); err != nil {
			t.Fatal("exact source set rejected", err)
		}
	}
	for name, sources := range map[string][]phase6security.PeerCRLSource{
		"duplicate general omits broker": {general, general},
		"duplicate broker omits general": {broker, broker},
		"missing":                        {general},
		"extra":                          {general, broker, general},
	} {
		t.Run(name, func(t *testing.T) {
			if client.ValidatePeerSources(sources) == nil {
				t.Fatal("non-exact source set accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*phase6security.PeerCRLSource){
		"id":     func(s *phase6security.PeerCRLSource) { s.ID = "unknown" },
		"mount":  func(s *phase6security.PeerCRLSource) { s.Mount = "other" },
		"issuer": func(s *phase6security.PeerCRLSource) { s.IssuerID = broker.IssuerID },
		"digest": func(s *phase6security.PeerCRLSource) { s.IssuerDigest = broker.IssuerDigest },
	} {
		t.Run(name, func(t *testing.T) {
			changed := general
			mutate(&changed)
			if client.ValidatePeerSources([]phase6security.PeerCRLSource{changed, broker}) == nil {
				t.Fatal("source identity drift accepted")
			}
		})
	}
}
