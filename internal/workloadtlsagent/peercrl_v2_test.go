package workloadtlsagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func peerCRLTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func peerCRLTestRequest(t *testing.T, now time.Time, issuerDigest string) PeerCRLRequest {
	t.Helper()
	request, err := NewPeerCRLRequest(PeerCRLRequest{RequestID: "crl_" + strings.Repeat("a", 32),
		Nonce:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		Deadline: now.Add(20 * time.Second).Format(time.RFC3339Nano), ProfileDigest: peerCRLTestDigest("profile"),
		EdgeID: "product-provider-contract", LocalPrincipalDigest: peerCRLTestDigest("product"),
		Direction: "outbound", PeerAnchorID: "internal-server-ca", IssuerDigest: issuerDigest}, now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func peerCRLTestDER(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "peer CRL issuer"},
		SubjectKeyId: []byte{1, 2, 3, 4}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(7),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return issuerDER, crlDER
}

func TestPeerCRLV2CanonicalRequestAndNoV1Fallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, _ := peerCRLTestDER(t, now)
	issuerHash := sha256.Sum256(issuerDER)
	request := peerCRLTestRequest(t, now, "sha256:"+hex.EncodeToString(issuerHash[:]))
	document, err := EncodePeerCRLRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodePeerCRLRequest(document, now); err != nil || decoded != request {
		t.Fatalf("v2 canonical request rejected: %v", err)
	}
	if _, err := decodeRequest(document, now); err == nil {
		t.Fatal("v1 accepted v2 peer CRL request")
	}
	unknown := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"source_id":"caller-chosen"}`)...)
	duplicate := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"edge_id":"product-provider-contract"}`)...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "trailing": append(append([]byte(nil), document...), '\n'),
		"noncanonical": bytes.Replace(document, []byte(`"protocol"`), []byte(`"protocol" `), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePeerCRLRequest(candidate, now); err == nil {
				t.Fatal("unsafe v2 request accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*PeerCRLRequest){
		"wrong edge":      func(value *PeerCRLRequest) { value.EdgeID = "gateway-provider-private" },
		"wrong role":      func(value *PeerCRLRequest) { value.LocalPrincipalDigest = peerCRLTestDigest("gateway") },
		"wrong direction": func(value *PeerCRLRequest) { value.Direction = "inbound" },
		"wrong anchor":    func(value *PeerCRLRequest) { value.PeerAnchorID = "internal-client-ca" },
		"wrong issuer":    func(value *PeerCRLRequest) { value.IssuerDigest = peerCRLTestDigest("other") },
		"expired":         func(value *PeerCRLRequest) { value.Deadline = now.Add(-time.Second).Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if changed.Validate(now) == nil {
				t.Fatal("binding mutation accepted")
			}
		})
	}
}

func TestPeerCRLV2ResponseBindsRequestSourceAndCompleteBytes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	issuerHash := sha256.Sum256(issuerDER)
	request := peerCRLTestRequest(t, now, "sha256:"+hex.EncodeToString(issuerHash[:]))
	response, err := NewPeerCRLResponse(request, "vault-peer-source", issuerDER, crlDER, now)
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodePeerCRLResponse(response, request, issuerDER, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePeerCRLResponse(document, request, issuerDER, now)
	if err != nil || !bytes.Equal(decoded.CRLDER, crlDER) || decoded.SourceID != "vault-peer-source" {
		t.Fatalf("valid v2 response rejected: %v", err)
	}
	otherIssuerDER, _ := peerCRLTestDER(t, now)
	if _, err := DecodePeerCRLResponse(document, request, otherIssuerDER, now); err == nil {
		t.Fatal("signed CRL accepted under another peer issuer")
	}
	for name, mutate := range map[string]func(*PeerCRLResponse){
		"wrong request":    func(value *PeerCRLResponse) { value.RequestDigest = peerCRLTestDigest("other") },
		"wrong edge":       func(value *PeerCRLResponse) { value.EdgeID = "gateway-provider-private" },
		"wrong issuer":     func(value *PeerCRLResponse) { value.IssuerDigest = peerCRLTestDigest("other") },
		"missing source":   func(value *PeerCRLResponse) { value.SourceID = "" },
		"wrong CRL digest": func(value *PeerCRLResponse) { value.CRLDigest = peerCRLTestDigest("other") },
		"wrong number":     func(value *PeerCRLResponse) { value.CRLNumber = "8" },
		"stale":            func(value *PeerCRLResponse) { value.NextUpdate = now.Add(-time.Second).Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := response
			mutate(&changed)
			if changed.Validate(request, now) == nil {
				t.Fatal("v2 response mutation accepted")
			}
		})
	}
	var wire map[string]any
	if err := json.Unmarshal(document, &wire); err != nil {
		t.Fatal(err)
	}
	wire["unknown"] = true
	unknown, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePeerCRLResponse(unknown, request, issuerDER, now); err == nil {
		t.Fatal("unknown v2 response field accepted")
	}
}
