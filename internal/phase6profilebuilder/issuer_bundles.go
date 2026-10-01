package phase6profilebuilder

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The five Profile anchor IDs are purposes, not five CAs. For this local
// candidate the broker-only issuer is also needed on the five local broker
// server edges; no other general-purpose bundle may silently inherit it.
// Live Vault issuer ownership, leaf policy and actual mounts remain gate work.
func verifySlice6CandidateIssuerBundles(anchors TrustAnchorSupply, dns DNSClientCASupply) error {
	if len(anchors.anchors) != len(phase6security.Slice6DesiredFinalTrustAnchorTemplates()) ||
		len(dns.bundle) == 0 {
		return ErrInvalidCandidateProfile
	}
	generalBundle, err := anchors.BundleBytes("external-server-ca")
	if err != nil {
		return ErrInvalidCandidateProfile
	}
	general, err := slice6BundleDERSet(generalBundle)
	if err != nil || len(general) != 1 {
		return ErrInvalidCandidateProfile
	}
	broker, err := slice6BundleDERSet(dns.bundle)
	if err != nil || len(broker) != 1 {
		return ErrInvalidCandidateProfile
	}
	for digest := range broker {
		if general[digest] {
			return ErrInvalidCandidateProfile
		}
	}
	for _, id := range []string{"internal-client-ca", "postgres-client-ca", "vault-client-ca", "internal-server-ca"} {
		bundle, err := anchors.BundleBytes(id)
		if err != nil {
			return ErrInvalidCandidateProfile
		}
		actual, err := slice6BundleDERSet(bundle)
		if err != nil {
			return ErrInvalidCandidateProfile
		}
		want := len(general)
		if id == "internal-server-ca" {
			want++
		}
		if len(actual) != want {
			return ErrInvalidCandidateProfile
		}
		for digest := range general {
			if !actual[digest] {
				return ErrInvalidCandidateProfile
			}
		}
		if id == "internal-server-ca" {
			for digest := range broker {
				if !actual[digest] {
					return ErrInvalidCandidateProfile
				}
			}
		}
	}
	return nil
}

func slice6BundleDERSet(bundle []byte) (map[string]bool, error) {
	result := make(map[string]bool)
	for rest := bytes.TrimSpace(bundle); len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidCandidateProfile
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || result[string(block.Bytes)] {
			return nil, ErrInvalidCandidateProfile
		}
		result[string(block.Bytes)] = true
		rest = bytes.TrimSpace(remaining)
	}
	if len(result) == 0 {
		return nil, ErrInvalidCandidateProfile
	}
	return result, nil
}
