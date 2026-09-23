package workloadpki

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

func peerCRLProtocolFixture(t *testing.T) (protocolFixture, crlTestMaterial, PeerCRLRequest) {
	t.Helper()
	fixture := newProtocolFixture(t)
	material := newCRLTestMaterial(t, fixture.now, 42, true)
	issuerHash := sha256.Sum256(material.issuerDER)
	request, err := NewPeerCRLRequest(fixture.policy, "peer-crl-1",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), fixture.now.Add(30*time.Second),
		"sha256:"+strings.Repeat("a", 64), "product-provider-contract", fixture.policy.Subject.Digest(),
		"outbound", "internal-server-ca", "sha256:"+hex.EncodeToString(issuerHash[:]),
		"provider-peer-ca", fixture.agentPrivate, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, material, request
}

func TestPeerCRLV2SignedCanonicalWireBindsPolicyAndEdge(t *testing.T) {
	fixture, _, request := peerCRLProtocolFixture(t)
	document, err := EncodePeerCRLRequest(request, fixture.policy, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePeerCRLRequest(document, fixture.policy, fixture.now)
	if err != nil || decoded != request {
		t.Fatalf("signed request round trip: %v", err)
	}
	for name, mutate := range map[string]func(*PeerCRLRequest){
		"cross-edge":      func(r *PeerCRLRequest) { r.EdgeID = "gateway-provider-private" },
		"cross-role":      func(r *PeerCRLRequest) { r.LocalPrincipalDigest = "sha256:" + strings.Repeat("b", 64) },
		"cross-direction": func(r *PeerCRLRequest) { r.Direction = "inbound" },
		"cross-anchor":    func(r *PeerCRLRequest) { r.PeerAnchorID = "internal-client-ca" },
		"source-switch":   func(r *PeerCRLRequest) { r.SourceID = "another-ca" },
		"issuer-switch":   func(r *PeerCRLRequest) { r.IssuerDigest = "sha256:" + strings.Repeat("b", 64) },
		"profile-switch":  func(r *PeerCRLRequest) { r.ProfileDigest = "sha256:" + strings.Repeat("b", 64) },
		"expired":         func(r *PeerCRLRequest) { r.Deadline = fixture.now.Add(-time.Second).Format(time.RFC3339Nano) },
		"v1-downgrade":    func(r *PeerCRLRequest) { r.Protocol = ProtocolID },
		"signature-change": func(r *PeerCRLRequest) {
			r.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			candidate, _ := json.Marshal(changed)
			if _, err := DecodePeerCRLRequest(candidate, fixture.policy, fixture.now); err == nil {
				t.Fatal("changed signed request accepted")
			}
		})
	}
	unknown := bytes.Replace(document, []byte(`"source_id":"provider-peer-ca"`),
		[]byte(`"source_id":"provider-peer-ca","vault_path":"/v1/pki/crl"`), 1)
	duplicate := bytes.Replace(document, []byte(`"source_id":"provider-peer-ca"`),
		[]byte(`"source_id":"provider-peer-ca","source_id":"provider-peer-ca"`), 1)
	for _, candidate := range [][]byte{unknown, duplicate, append(append([]byte(nil), document...), '\n'),
		bytes.Repeat([]byte{'x'}, maxRequestBytes+1)} {
		if _, err := DecodePeerCRLRequest(candidate, fixture.policy, fixture.now); err == nil {
			t.Fatal("noncanonical or oversized request accepted")
		}
	}
}

func TestPeerCRLV2ResponseSignatureAndCompleteCRL(t *testing.T) {
	fixture, material, request := peerCRLProtocolFixture(t)
	response, err := NewPeerCRLResponse(request, StatusOK, material.issuerDER, material.snapshot,
		fixture.controllerID, fixture.controllerPriv, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodePeerCRLResponse(response, request, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePeerCRLResponse(document, request, fixture.policy, fixture.controllerID,
		fixture.controllerPub, fixture.now)
	if err != nil || !bytes.Equal(decoded.CRLDER, material.snapshot.DER) || !bytes.Equal(decoded.IssuerDER, material.issuerDER) {
		t.Fatalf("signed complete CRL response: %v", err)
	}
	for name, mutate := range map[string]func(*PeerCRLResponse){
		"source-switch": func(r *PeerCRLResponse) { r.SourceID = "other-ca" },
		"issuer-switch": func(r *PeerCRLResponse) { r.IssuerDER = newCRLTestMaterial(t, fixture.now, 42, false).issuerDER },
		"digest-change": func(r *PeerCRLResponse) { r.CRLDigest = "sha256:" + strings.Repeat("a", 64) },
		"number-change": func(r *PeerCRLResponse) { r.CRLNumber = "9" },
		"bad-signature": func(r *PeerCRLResponse) {
			r.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 64))
		},
		"profile-switch": func(r *PeerCRLResponse) { r.ProfileDigest = "sha256:" + strings.Repeat("b", 64) },
		"expired":        func(r *PeerCRLResponse) { r.NextUpdate = fixture.now.Add(-time.Second).Format(time.RFC3339Nano) },
		"old collection": func(r *PeerCRLResponse) { r.CollectedAt = fixture.now.Add(-2 * time.Minute).Format(time.RFC3339Nano) },
		"v1-downgrade":   func(r *PeerCRLResponse) { r.Protocol = ProtocolID },
	} {
		t.Run(name, func(t *testing.T) {
			changed := response
			mutate(&changed)
			candidate, _ := json.Marshal(changed)
			if _, err := DecodePeerCRLResponse(candidate, request, fixture.policy, fixture.controllerID,
				fixture.controllerPub, fixture.now); err == nil {
				t.Fatal("changed response accepted")
			}
		})
	}
	if _, err := DecodePeerCRLResponse(document, request, fixture.policy, fixture.controllerID,
		fixture.controllerPub, fixture.now.Add(6*time.Minute)); err == nil {
		t.Fatal("stale response accepted")
	}
}

func TestPeerCRLV2UnixClientSignedRoundTrip(t *testing.T) {
	fixture, material, _ := peerCRLProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	directory := securePKIDirectory(t)
	socket := filepath.Join(directory, "controller.sock")
	layout := restrictedunix.Layout{DirectoryMode: 0o700, SocketMode: 0o600,
		OwnerUID: uint32(os.Getuid()), DirectoryGID: uint32(os.Getgid())}
	listener, info, err := restrictedunix.Listen(socket, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close(); restrictedunix.RemoveIfSame(socket, info) }()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		document, err := readFrame(connection, maxRequestBytes)
		if err != nil {
			serverDone <- err
			return
		}
		request, err := DecodePeerCRLRequest(document, fixture.policy, time.Now().UTC())
		if err != nil {
			serverDone <- err
			return
		}
		response, err := NewPeerCRLResponse(request, StatusOK, material.issuerDER, material.snapshot,
			fixture.controllerID, fixture.controllerPriv, time.Now().UTC())
		if err != nil {
			serverDone <- err
			return
		}
		encoded, err := EncodePeerCRLResponse(response, request, time.Now().UTC())
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- writeFrame(connection, encoded, maxResponseBytes)
	}()
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()),
		ExpectedGID: uint32(os.Getgid()), DirectoryGID: uint32(os.Getgid()), InternalSelf: true,
		Policy: fixture.policy, AgentPrivateKey: fixture.agentPrivate, ControllerKeyID: fixture.controllerID,
		ControllerPublic: fixture.controllerPub, OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	issuerHash := sha256.Sum256(material.issuerDER)
	response, err := client.PeerRevocations(t.Context(), PeerCRLBinding{
		ProfileDigest: "sha256:" + strings.Repeat("a", 64), EdgeID: "product-provider-contract",
		LocalPrincipalDigest: fixture.policy.Subject.Digest(), Direction: "outbound",
		PeerAnchorID: "internal-server-ca", IssuerDigest: "sha256:" + hex.EncodeToString(issuerHash[:]),
		SourceID: "provider-peer-ca"})
	if err != nil || !bytes.Equal(response.CRLDER, material.snapshot.DER) {
		t.Fatalf("Unix signed CRL response: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(fmt.Errorf("controller socket: %w", err))
	}
}
