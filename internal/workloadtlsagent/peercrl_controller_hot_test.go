package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

type hotPeerIndex struct {
	request PeerCRLRequest
	owner   string
	called  int
}

func (i *hotPeerIndex) AuthorizedSourceID(profile, mapping, edge, principal, direction, anchor, issuer, owner string) (string, error) {
	i.called++
	if profile != i.request.ProfileDigest || mapping != i.request.SourceMappingDigest ||
		edge != i.request.EdgeID || principal != i.request.LocalPrincipalDigest ||
		direction != i.request.Direction || anchor != i.request.PeerAnchorID ||
		issuer != i.request.IssuerDigest || owner != i.owner {
		return "", ErrUnavailable
	}
	return "peer-source", nil
}

type hotPeerController struct {
	response workloadpki.PeerCRLResponse
	called   int
}

func (c *hotPeerController) PeerRevocations(_ context.Context, binding workloadpki.PeerCRLBinding) (workloadpki.PeerCRLResponse, error) {
	c.called++
	if binding.SourceID != "peer-source" {
		return workloadpki.PeerCRLResponse{}, ErrUnavailable
	}
	response := c.response
	response.IssuerDER = bytes.Clone(response.IssuerDER)
	response.CRLDER = bytes.Clone(response.CRLDER)
	return response, nil
}

func TestControllerPeerCRLProviderHotPathAndOwnerBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	issuerHash := sha256.Sum256(issuerDER)
	request := peerCRLTestRequest(t, now, "sha256:"+hex.EncodeToString(issuerHash[:]))
	verified, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
		DER: crlDER, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)}, issuerDER, now)
	if err != nil {
		t.Fatal(err)
	}
	index := &hotPeerIndex{request: request, owner: "product-migration-job"}
	controller := &hotPeerController{response: workloadpki.PeerCRLResponse{
		Status: workloadpki.StatusOK, SourceID: "peer-source", ProfileDigest: request.ProfileDigest,
		EdgeID: request.EdgeID, Direction: request.Direction, PeerAnchorID: request.PeerAnchorID,
		IssuerDigest: request.IssuerDigest, IssuerDER: issuerDER, CRLDER: crlDER,
		ThisUpdate:  verified.ThisUpdate().UTC().Format(time.RFC3339Nano),
		NextUpdate:  verified.NextUpdate().UTC().Format(time.RFC3339Nano),
		CollectedAt: now.Format(time.RFC3339Nano),
	}}
	provider := &ControllerPeerCRLProvider{profileDigest: request.ProfileDigest, identity: index,
		subjectDigest: request.LocalPrincipalDigest, postgresOwner: index.owner, client: controller,
		now: func() time.Time { return now }}
	source, issuer, crl, collected, err := provider.ReadPeerCRL(t.Context(), request)
	if err != nil || source != "peer-source" || !bytes.Equal(issuer, issuerDER) ||
		!bytes.Equal(crl, crlDER) || !collected.Equal(now) || index.called != 1 || controller.called != 1 {
		t.Fatalf("hot read: source=%q collected=%s error=%v lookups=%d controller=%d", source, collected, err, index.called, controller.called)
	}
	request.SourceMappingDigest = peerCRLTestDigest("wrong-mapping")
	request, err = NewPeerCRLRequest(PeerCRLRequest{RequestID: request.RequestID, Nonce: request.Nonce,
		Deadline: request.Deadline, ProfileDigest: request.ProfileDigest,
		SourceMappingDigest: request.SourceMappingDigest, EdgeID: request.EdgeID,
		LocalPrincipalDigest: request.LocalPrincipalDigest, Direction: request.Direction,
		PeerAnchorID: request.PeerAnchorID, IssuerDigest: request.IssuerDigest}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := provider.ReadPeerCRL(t.Context(), request); err == nil || controller.called != 1 {
		t.Fatal("mapping drift reached controller")
	}
	provider.postgresOwner = "other-owner"
	request = index.request
	if _, _, _, _, err := provider.ReadPeerCRL(t.Context(), request); err == nil || controller.called != 1 {
		t.Fatal("owner drift reached controller")
	}
}
