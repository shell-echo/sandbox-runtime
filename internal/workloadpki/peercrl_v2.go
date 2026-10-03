package workloadpki

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

// PeerCRLProtocolID is deliberately separate from the frozen certificate v1
// wire contract. A peer-revocation request never grants write authority.
const PeerCRLProtocolID = "sandbox-runtime.workload-certificate.v2"

type PeerCRLRequest struct {
	Protocol             string `json:"protocol"`
	Type                 string `json:"type"`
	RequestID            string `json:"request_id"`
	AgentID              string `json:"agent_id"`
	RequesterDigest      string `json:"requester_digest"`
	PolicyID             string `json:"policy_id"`
	Principal            string `json:"principal"`
	SubjectDigest        string `json:"subject_digest"`
	Nonce                string `json:"nonce"`
	Deadline             string `json:"deadline"`
	ProfileDigest        string `json:"profile_digest"`
	EdgeID               string `json:"edge_id"`
	LocalPrincipalDigest string `json:"local_principal_digest"`
	Direction            string `json:"direction"`
	PeerAnchorID         string `json:"peer_anchor_id"`
	IssuerDigest         string `json:"issuer_digest"`
	SourceID             string `json:"source_id"`
	RequestDigest        string `json:"request_digest"`
	Signature            string `json:"signature"`
}

type PeerCRLResponse struct {
	Protocol        string `json:"protocol"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	RequestID       string `json:"request_id"`
	RequestDigest   string `json:"request_digest"`
	AgentID         string `json:"agent_id"`
	PolicyID        string `json:"policy_id"`
	ProfileDigest   string `json:"profile_digest"`
	EdgeID          string `json:"edge_id"`
	Direction       string `json:"direction"`
	PeerAnchorID    string `json:"peer_anchor_id"`
	IssuerDigest    string `json:"issuer_digest"`
	SourceID        string `json:"source_id"`
	IssuerDER       []byte `json:"issuer_der"`
	CRLDER          []byte `json:"crl_der"`
	CRLDigest       string `json:"crl_digest"`
	CRLNumber       string `json:"crl_number"`
	ThisUpdate      string `json:"this_update"`
	NextUpdate      string `json:"next_update"`
	CollectedAt     string `json:"collected_at"`
	ControllerKeyID string `json:"controller_key_id"`
	ResponseDigest  string `json:"response_digest"`
	Signature       string `json:"signature"`
}

func NewPeerCRLRequest(policy Policy, requestID, nonce string, deadline time.Time, profileDigest, edgeID,
	localPrincipalDigest, direction, peerAnchorID, issuerDigest, sourceID string, privateKey ed25519.PrivateKey,
	now time.Time) (PeerCRLRequest, error) {
	if len(privateKey) != ed25519.PrivateKeySize || policy.Validate() != nil ||
		!privateKey.Public().(ed25519.PublicKey).Equal(policy.PublicKey) {
		return PeerCRLRequest{}, ErrInvalid
	}
	r := PeerCRLRequest{Protocol: PeerCRLProtocolID, Type: RevocationsType, RequestID: requestID,
		AgentID: policy.Requester.Name, RequesterDigest: policy.Requester.Digest(), PolicyID: policy.ID,
		Principal: policy.Subject.Name, SubjectDigest: policy.Subject.Digest(), Nonce: nonce,
		Deadline: deadline.UTC().Format(time.RFC3339Nano), ProfileDigest: profileDigest,
		EdgeID: edgeID, LocalPrincipalDigest: localPrincipalDigest, Direction: direction,
		PeerAnchorID: peerAnchorID, IssuerDigest: issuerDigest, SourceID: sourceID}
	r.RequestDigest = peerCRLRequestDigest(r)
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(r.RequestDigest)))
	if r.Validate(policy, now) != nil {
		return PeerCRLRequest{}, ErrInvalid
	}
	return r, nil
}

func (r PeerCRLRequest) Validate(policy Policy, now time.Time) error {
	deadline, err := parseTime(r.Deadline)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(r.Signature)
	if policy.Validate() != nil || now.IsZero() || r.Protocol != PeerCRLProtocolID || r.Type != RevocationsType ||
		r.AgentID != policy.Requester.Name || r.RequesterDigest != policy.Requester.Digest() || r.PolicyID != policy.ID ||
		r.Principal != policy.Subject.Name || r.SubjectDigest != policy.Subject.Digest() ||
		r.LocalPrincipalDigest != policy.Subject.Digest() || !namePattern.MatchString(r.RequestID) ||
		!validNonce(r.Nonce) || err != nil || !deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		!digestPattern.MatchString(r.ProfileDigest) || !namePattern.MatchString(r.EdgeID) ||
		(r.Direction != "inbound" && r.Direction != "outbound") || !namePattern.MatchString(r.PeerAnchorID) ||
		!digestPattern.MatchString(r.IssuerDigest) || !namePattern.MatchString(r.SourceID) ||
		r.RequestDigest != peerCRLRequestDigest(r) || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(policy.PublicKey, []byte(r.RequestDigest), signature) {
		return ErrDenied
	}
	return nil
}

func EncodePeerCRLRequest(request PeerCRLRequest, policy Policy, now time.Time) ([]byte, error) {
	if request.Validate(policy, now) != nil {
		return nil, ErrInvalid
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > maxRequestBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func DecodePeerCRLRequest(document []byte, policy Policy, now time.Time) (PeerCRLRequest, error) {
	var request PeerCRLRequest
	if decodeCanonical(document, maxRequestBytes, &request) != nil || request.Validate(policy, now) != nil {
		return PeerCRLRequest{}, ErrDenied
	}
	return request, nil
}

func NewPeerCRLResponse(request PeerCRLRequest, status string, issuerDER []byte, snapshot RevocationSnapshot,
	controllerKeyID string, privateKey ed25519.PrivateKey, now time.Time) (PeerCRLResponse, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !namePattern.MatchString(controllerKeyID) {
		return PeerCRLResponse{}, ErrInvalid
	}
	r := PeerCRLResponse{Protocol: PeerCRLProtocolID, Type: RevocationSnapshotType, Status: status,
		RequestID: request.RequestID, RequestDigest: request.RequestDigest, AgentID: request.AgentID,
		PolicyID: request.PolicyID, ProfileDigest: request.ProfileDigest, EdgeID: request.EdgeID,
		Direction: request.Direction, PeerAnchorID: request.PeerAnchorID, IssuerDigest: request.IssuerDigest,
		SourceID: request.SourceID, ControllerKeyID: controllerKeyID}
	if status == StatusOK {
		verified, err := VerifyCRLForIssuer(snapshot, issuerDER, now)
		if err != nil || verified.IssuerDigest() != request.IssuerDigest {
			return PeerCRLResponse{}, ErrUnavailable
		}
		r.IssuerDER, r.CRLDER = append([]byte(nil), issuerDER...), append([]byte(nil), snapshot.DER...)
		r.CRLDigest, r.CRLNumber = verified.CRLDigest(), verified.Number().String()
		r.ThisUpdate, r.NextUpdate = verified.ThisUpdate().UTC().Format(time.RFC3339Nano), verified.NextUpdate().UTC().Format(time.RFC3339Nano)
		r.CollectedAt = now.UTC().Format(time.RFC3339Nano)
	} else {
		r.Type = ErrorType
	}
	r.ResponseDigest = peerCRLResponseDigest(r)
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(r.ResponseDigest)))
	if r.validateStructure(request, now) != nil {
		clear(r.IssuerDER)
		clear(r.CRLDER)
		return PeerCRLResponse{}, ErrInvalid
	}
	return r, nil
}

func (r PeerCRLResponse) Validate(request PeerCRLRequest, policy Policy, controllerKeyID string,
	controllerPublic ed25519.PublicKey, now time.Time) error {
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if request.Validate(policy, now) != nil || r.ControllerKeyID != controllerKeyID ||
		len(controllerPublic) != ed25519.PublicKeySize || r.ResponseDigest != peerCRLResponseDigest(r) ||
		err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(controllerPublic, []byte(r.ResponseDigest), signature) || r.validateStructure(request, now) != nil {
		return ErrUnavailable
	}
	if r.Status == StatusDenied {
		return ErrDenied
	}
	if r.Status != StatusOK {
		return ErrUnavailable
	}
	return nil
}

func (r PeerCRLResponse) validateStructure(request PeerCRLRequest, now time.Time) error {
	if r.Protocol != PeerCRLProtocolID || r.RequestID != request.RequestID || r.RequestDigest != request.RequestDigest ||
		r.AgentID != request.AgentID || r.PolicyID != request.PolicyID || r.ProfileDigest != request.ProfileDigest ||
		r.EdgeID != request.EdgeID || r.Direction != request.Direction || r.PeerAnchorID != request.PeerAnchorID ||
		r.IssuerDigest != request.IssuerDigest || r.SourceID != request.SourceID ||
		!digestPattern.MatchString(r.ResponseDigest) || !validSignature(r.Signature) {
		return ErrInvalid
	}
	if r.Status != StatusOK {
		if r.Type != ErrorType || (r.Status != StatusDenied && r.Status != StatusUnavailable) ||
			len(r.IssuerDER) != 0 || len(r.CRLDER) != 0 || r.CRLDigest != "" || r.CRLNumber != "" ||
			r.ThisUpdate != "" || r.NextUpdate != "" || r.CollectedAt != "" {
			return ErrInvalid
		}
		return nil
	}
	if r.Type != RevocationSnapshotType || len(r.IssuerDER) < 1 || len(r.IssuerDER) > 64<<10 ||
		len(r.CRLDER) < 1 || len(r.CRLDER) > maxCRLBytes || !digestPattern.MatchString(r.CRLDigest) {
		return ErrInvalid
	}
	thisUpdate, err1 := parseTime(r.ThisUpdate)
	nextUpdate, err2 := parseTime(r.NextUpdate)
	collectedAt, err3 := parseTime(r.CollectedAt)
	if err1 != nil || err2 != nil || err3 != nil || collectedAt.After(now.Add(5*time.Second)) ||
		collectedAt.Before(now.Add(-time.Minute)) || collectedAt.Before(thisUpdate) || !collectedAt.Before(nextUpdate) {
		return ErrInvalid
	}
	verified, err := VerifyCRLForIssuer(RevocationSnapshot{DER: r.CRLDER, ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate}, r.IssuerDER, now)
	if err != nil || verified.IssuerDigest() != request.IssuerDigest || verified.CRLDigest() != r.CRLDigest ||
		verified.Number().String() != r.CRLNumber {
		return ErrUnavailable
	}
	return nil
}

func EncodePeerCRLResponse(response PeerCRLResponse, request PeerCRLRequest, now time.Time) ([]byte, error) {
	if response.validateStructure(request, now) != nil {
		return nil, ErrInvalid
	}
	document, err := json.Marshal(response)
	if err != nil || len(document) > maxResponseBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func DecodePeerCRLResponse(document []byte, request PeerCRLRequest, policy Policy, controllerKeyID string,
	controllerPublic ed25519.PublicKey, now time.Time) (PeerCRLResponse, error) {
	var response PeerCRLResponse
	if decodeCanonical(document, maxResponseBytes, &response) != nil ||
		response.Validate(request, policy, controllerKeyID, controllerPublic, now) != nil {
		clear(response.IssuerDER)
		clear(response.CRLDER)
		return PeerCRLResponse{}, ErrUnavailable
	}
	return response, nil
}

func peerCRLRequestDigest(request PeerCRLRequest) string {
	request.RequestDigest, request.Signature = "", ""
	document, _ := json.Marshal(request)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-certificate/peer-crl-request/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func peerCRLResponseDigest(response PeerCRLResponse) string {
	response.ResponseDigest, response.Signature = "", ""
	document, _ := json.Marshal(response)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-certificate/peer-crl-response/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (c *Controller) HandlePeerCRL(ctx context.Context, request PeerCRLRequest, peerUID, peerGID uint32) (PeerCRLResponse, error) {
	if c == nil || ctx == nil || c.peerCRLProfile == nil || c.peerCRLSources == nil || c.peerCRLIdentity == nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	if err := c.acquireRequest(ctx, request.Deadline); err != nil {
		return PeerCRLResponse{}, err
	}
	defer c.release()
	now := c.now().UTC()
	policy, known := c.policies[request.PolicyID]
	if !known || policy.ExpectedUID != peerUID || policy.ExpectedGID != peerGID ||
		request.Validate(policy, now) != nil || request.ProfileDigest != c.peerCRLProfile.ProfileDigest {
		return c.peerCRLError(request, StatusDenied, ErrDenied)
	}
	postgresOwner := ""
	if policy.Purpose == PostgresClientPurpose {
		postgresOwner = policy.Postgres.OwnerDeployment
	} else if policy.Purpose != "" {
		return c.peerCRLError(request, StatusDenied, ErrDenied)
	}
	sourceID, err := c.peerCRLIdentity.AuthorizedSourceID(request.ProfileDigest,
		c.peerCRLIdentity.MappingDigest(), request.EdgeID, request.LocalPrincipalDigest,
		request.Direction, request.PeerAnchorID, request.IssuerDigest, postgresOwner)
	if err != nil || sourceID != request.SourceID {
		return c.peerCRLError(request, StatusDenied, ErrDenied)
	}
	if err := ctx.Err(); err != nil {
		return PeerCRLResponse{}, err
	}
	if !c.consumeReplay(request.Nonce, request.Deadline, now) {
		return c.peerCRLError(request, StatusDenied, ErrDenied)
	}
	if err := c.persist(); err != nil {
		return c.peerCRLError(request, StatusUnavailable, ErrUnavailable)
	}
	deadline, _ := parseTime(request.Deadline)
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	authority := c.authority.(PeerIssuerAuthority)
	issuerDER, err := authority.PeerIssuerCertificate(operationContext, sourceID)
	if err != nil {
		return c.peerCRLError(request, StatusUnavailable, normalizeAuthorityError(err))
	}
	defer clear(issuerDER)
	issuerHash := sha256.Sum256(issuerDER)
	if "sha256:"+hex.EncodeToString(issuerHash[:]) != request.IssuerDigest {
		return c.peerCRLError(request, StatusUnavailable, ErrUnavailable)
	}
	snapshot, err := authority.PeerRevocations(operationContext, sourceID, issuerDER)
	if err != nil {
		return c.peerCRLError(request, StatusUnavailable, normalizeAuthorityError(err))
	}
	defer snapshot.Destroy()
	response, err := NewPeerCRLResponse(request, StatusOK, issuerDER, snapshot, c.controllerKeyID, c.controllerKey, c.now().UTC())
	if err != nil {
		return c.peerCRLError(request, StatusUnavailable, ErrUnavailable)
	}
	return response, nil
}

func (c *Controller) peerCRLError(request PeerCRLRequest, status string, result error) (PeerCRLResponse, error) {
	response, err := NewPeerCRLResponse(request, status, nil, RevocationSnapshot{}, c.controllerKeyID, c.controllerKey, c.now().UTC())
	if err != nil {
		return PeerCRLResponse{}, result
	}
	return response, result
}
