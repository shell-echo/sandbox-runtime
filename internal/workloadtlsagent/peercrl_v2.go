package workloadtlsagent

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// PeerCRLProtocolID is separate from the frozen v1 snapshot/sign protocol.
// A production peer-revocation path must explicitly select v2; there is no
// transparent downgrade to v1 if the peer-CRL capability is unavailable.
const PeerCRLProtocolID = "sandbox-runtime.workload-tls-agent.v2"

const (
	PeerCRLRequestType  = "peer_crl"
	PeerCRLSnapshotType = "peer_crl_snapshot"
	PeerCRLErrorType    = "error"
	maxPeerCRLBytes     = 256 << 10
	maxPeerCRLFrame     = 512 << 10
)

var (
	peerCRLNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	peerCRLIDPattern     = regexp.MustCompile(`^crl_[0-9a-f]{32}$`)
	peerCRLDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	peerCRLNumberPattern = regexp.MustCompile(`^[1-9][0-9]{0,38}$`)
)

// PeerCRLRequest binds a read-only pull to one exact profile edge and local
// role. The source path/issuer ID is intentionally absent: the agent must
// resolve and authorize those from its fixed profile mapping.
type PeerCRLRequest struct {
	Protocol             string `json:"protocol"`
	Type                 string `json:"type"`
	RequestID            string `json:"request_id"`
	Nonce                string `json:"nonce"`
	Deadline             string `json:"deadline"`
	ProfileDigest        string `json:"profile_digest"`
	SourceMappingDigest  string `json:"source_mapping_digest"`
	EdgeID               string `json:"edge_id"`
	LocalPrincipalDigest string `json:"local_principal_digest"`
	Direction            string `json:"direction"`
	PeerAnchorID         string `json:"peer_anchor_id"`
	IssuerDigest         string `json:"issuer_digest"`
	RequestDigest        string `json:"request_digest"`
}

// PeerCRLResponse carries one complete CRL, not a claim that a particular
// leaf is good. The role must re-check the signed CRL against its own pinned
// issuer and the actual TLS-verified peer leaf before admission or retention.
type PeerCRLResponse struct {
	Protocol            string `json:"protocol"`
	Type                string `json:"type"`
	RequestID           string `json:"request_id"`
	RequestDigest       string `json:"request_digest"`
	ProfileDigest       string `json:"profile_digest"`
	SourceMappingDigest string `json:"source_mapping_digest"`
	EdgeID              string `json:"edge_id"`
	Direction           string `json:"direction"`
	PeerAnchorID        string `json:"peer_anchor_id"`
	IssuerDigest        string `json:"issuer_digest"`
	SourceID            string `json:"source_id"`
	IssuerDER           []byte `json:"issuer_der"`
	CRLDER              []byte `json:"crl_der"`
	CRLDigest           string `json:"crl_digest"`
	CRLNumber           string `json:"crl_number"`
	ThisUpdate          string `json:"this_update"`
	NextUpdate          string `json:"next_update"`
	CollectedAt         string `json:"collected_at"`
}

func (r PeerCRLRequest) Validate(now time.Time) error {
	deadline, err := parseProtocolTime(r.Deadline)
	if now.IsZero() || r.Protocol != PeerCRLProtocolID || r.Type != PeerCRLRequestType ||
		!peerCRLIDPattern.MatchString(r.RequestID) || !validNonce(r.Nonce) || err != nil ||
		!deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		!peerCRLDigestPattern.MatchString(r.ProfileDigest) || !peerCRLDigestPattern.MatchString(r.SourceMappingDigest) ||
		!peerCRLNamePattern.MatchString(r.EdgeID) ||
		!peerCRLDigestPattern.MatchString(r.LocalPrincipalDigest) ||
		(r.Direction != "inbound" && r.Direction != "outbound") ||
		!peerCRLNamePattern.MatchString(r.PeerAnchorID) || !peerCRLDigestPattern.MatchString(r.IssuerDigest) ||
		r.RequestDigest != peerCRLRequestDigest(r) {
		return ErrUnavailable
	}
	return nil
}

func (r PeerCRLResponse) Validate(request PeerCRLRequest, now time.Time) error {
	if request.Validate(now) != nil || r.Protocol != PeerCRLProtocolID || r.RequestID != request.RequestID ||
		r.RequestDigest != request.RequestDigest || r.ProfileDigest != request.ProfileDigest ||
		r.SourceMappingDigest != request.SourceMappingDigest ||
		r.EdgeID != request.EdgeID || r.Direction != request.Direction || r.PeerAnchorID != request.PeerAnchorID ||
		r.IssuerDigest != request.IssuerDigest {
		return ErrUnavailable
	}
	if r.Type == PeerCRLErrorType {
		if r.SourceID != "" || len(r.IssuerDER) != 0 || len(r.CRLDER) != 0 || r.CRLDigest != "" || r.CRLNumber != "" ||
			r.ThisUpdate != "" || r.NextUpdate != "" || r.CollectedAt != "" {
			return ErrUnavailable
		}
		return nil
	}
	if r.Type != PeerCRLSnapshotType || !peerCRLNamePattern.MatchString(r.SourceID) ||
		len(r.IssuerDER) < 1 || len(r.IssuerDER) > 64<<10 ||
		len(r.CRLDER) < 1 || len(r.CRLDER) > maxPeerCRLBytes || !peerCRLDigestPattern.MatchString(r.CRLDigest) ||
		!peerCRLNumberPattern.MatchString(r.CRLNumber) {
		return ErrUnavailable
	}
	thisUpdate, firstErr := parseProtocolTime(r.ThisUpdate)
	nextUpdate, secondErr := parseProtocolTime(r.NextUpdate)
	collectedAt, thirdErr := parseProtocolTime(r.CollectedAt)
	list, listErr := x509.ParseRevocationList(r.CRLDER)
	if firstErr != nil || secondErr != nil || thirdErr != nil || listErr != nil || list.Number == nil || list.Number.Sign() < 1 ||
		list.Number.String() != r.CRLNumber || !list.ThisUpdate.Equal(thisUpdate) || !list.NextUpdate.Equal(nextUpdate) ||
		now.Before(thisUpdate) || !now.Before(nextUpdate) || !nextUpdate.After(thisUpdate) ||
		collectedAt.Before(thisUpdate) || !collectedAt.Before(nextUpdate) ||
		collectedAt.Before(now.Add(-time.Minute)) || collectedAt.After(now.Add(5*time.Second)) {
		return ErrUnavailable
	}
	digest := sha256.Sum256(r.CRLDER)
	issuerDigest := sha256.Sum256(r.IssuerDER)
	if r.CRLDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
		r.IssuerDigest != "sha256:"+hex.EncodeToString(issuerDigest[:]) {
		return ErrUnavailable
	}
	return nil
}

func NewPeerCRLRequest(request PeerCRLRequest, now time.Time) (PeerCRLRequest, error) {
	if (request.Protocol != "" && request.Protocol != PeerCRLProtocolID) ||
		(request.Type != "" && request.Type != PeerCRLRequestType) || request.RequestDigest != "" {
		return PeerCRLRequest{}, ErrUnavailable
	}
	request.Protocol, request.Type = PeerCRLProtocolID, PeerCRLRequestType
	request.RequestDigest = peerCRLRequestDigest(request)
	if request.Validate(now) != nil {
		return PeerCRLRequest{}, ErrUnavailable
	}
	return request, nil
}

func NewPeerCRLResponse(request PeerCRLRequest, sourceID string, issuerDER, crlDER []byte, collectedAt, now time.Time) (PeerCRLResponse, error) {
	list, err := x509.ParseRevocationList(crlDER)
	if err != nil || list.Number == nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	digest := sha256.Sum256(crlDER)
	response := PeerCRLResponse{Protocol: PeerCRLProtocolID, Type: PeerCRLSnapshotType,
		RequestID: request.RequestID, RequestDigest: request.RequestDigest, ProfileDigest: request.ProfileDigest,
		SourceMappingDigest: request.SourceMappingDigest,
		EdgeID:              request.EdgeID, Direction: request.Direction, PeerAnchorID: request.PeerAnchorID,
		IssuerDigest: request.IssuerDigest, SourceID: sourceID, IssuerDER: append([]byte(nil), issuerDER...),
		CRLDER:    append([]byte(nil), crlDER...),
		CRLDigest: "sha256:" + hex.EncodeToString(digest[:]), CRLNumber: list.Number.String(),
		ThisUpdate: list.ThisUpdate.UTC().Format(time.RFC3339Nano), NextUpdate: list.NextUpdate.UTC().Format(time.RFC3339Nano),
		CollectedAt: collectedAt.UTC().Format(time.RFC3339Nano)}
	if response.Validate(request, now) != nil || verifyPeerCRLResponseIssuer(response, request, issuerDER, now) != nil {
		clear(response.IssuerDER)
		clear(response.CRLDER)
		return PeerCRLResponse{}, ErrUnavailable
	}
	return response, nil
}

func EncodePeerCRLRequest(request PeerCRLRequest, now time.Time) ([]byte, error) {
	if request.Validate(now) != nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(request)
}

func DecodePeerCRLRequest(document []byte, now time.Time) (PeerCRLRequest, error) {
	var request PeerCRLRequest
	if decodeCanonical(document, maxRequestBytes, &request) != nil || request.Validate(now) != nil {
		return PeerCRLRequest{}, ErrUnavailable
	}
	return request, nil
}

func EncodePeerCRLResponse(response PeerCRLResponse, request PeerCRLRequest, issuerDER []byte, now time.Time) ([]byte, error) {
	if response.Validate(request, now) != nil ||
		(response.Type == PeerCRLSnapshotType && verifyPeerCRLResponseIssuer(response, request, issuerDER, now) != nil) {
		return nil, ErrUnavailable
	}
	return json.Marshal(response)
}

func DecodePeerCRLResponse(document []byte, request PeerCRLRequest, issuerDER []byte, now time.Time) (PeerCRLResponse, error) {
	var response PeerCRLResponse
	if decodeCanonical(document, maxPeerCRLFrame, &response) != nil || response.Validate(request, now) != nil ||
		response.Type == PeerCRLErrorType || verifyPeerCRLResponseIssuer(response, request, issuerDER, now) != nil {
		clear(response.IssuerDER)
		clear(response.CRLDER)
		return PeerCRLResponse{}, ErrUnavailable
	}
	return response, nil
}

func verifyPeerCRLResponseIssuer(response PeerCRLResponse, request PeerCRLRequest, issuerDER []byte, now time.Time) error {
	if len(issuerDER) != 0 && !bytes.Equal(response.IssuerDER, issuerDER) {
		return ErrUnavailable
	}
	thisUpdate, _ := parseProtocolTime(response.ThisUpdate)
	nextUpdate, _ := parseProtocolTime(response.NextUpdate)
	verified, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{DER: response.CRLDER,
		ThisUpdate: thisUpdate, NextUpdate: nextUpdate}, response.IssuerDER, now)
	if err != nil || verified.IssuerDigest() != request.IssuerDigest {
		return ErrUnavailable
	}
	return nil
}

func peerCRLRequestDigest(request PeerCRLRequest) string {
	request.RequestDigest = ""
	document, _ := json.Marshal(request)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-tls-agent/peer-crl-request/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}
