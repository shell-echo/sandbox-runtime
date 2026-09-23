package egresspolicystate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	CurrentProtocolID = "sandbox-runtime.egress-policy-current.v1"
	MaxCurrentBytes   = 8 << 10
	MaxCurrentTTL     = 5 * time.Second
)

type CurrentRequest struct {
	Protocol          string `json:"protocol"`
	EnvironmentDigest string `json:"environment_digest"`
	ProfileDigest     string `json:"profile_digest"`
	PolicyID          string `json:"policy_id"`
	PolicyRevision    string `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	PrincipalDigest   string `json:"principal_digest"`
	BrokerDigest      string `json:"broker_digest"`
	Challenge         string `json:"challenge"`
	Deadline          string `json:"deadline"`
	RequestDigest     string `json:"request_digest"`
}

type CurrentRecord struct {
	Generation     uint64
	Status         string
	SnapshotDigest string
}

type CurrentResponse struct {
	Protocol          string `json:"protocol"`
	RequestDigest     string `json:"request_digest"`
	Challenge         string `json:"challenge"`
	EnvironmentDigest string `json:"environment_digest"`
	ProfileDigest     string `json:"profile_digest"`
	PolicyID          string `json:"policy_id"`
	PolicyRevision    string `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	PrincipalDigest   string `json:"principal_digest"`
	BrokerDigest      string `json:"broker_digest"`
	Generation        uint64 `json:"generation"`
	Status            string `json:"status"`
	SnapshotDigest    string `json:"snapshot_digest"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
	OperatorKeyID     string `json:"operator_key_id"`
	ResponseDigest    string `json:"response_digest"`
	Signature         string `json:"signature"`
}

func NewCurrentRequest(binding Binding, now time.Time) (CurrentRequest, error) {
	if now.IsZero() || len(binding.operatorPublicKey) != ed25519.PublicKeySize {
		return CurrentRequest{}, ErrInvalid
	}
	var challenge [32]byte
	if _, err := io.ReadFull(rand.Reader, challenge[:]); err != nil {
		return CurrentRequest{}, ErrInvalid
	}
	request := CurrentRequest{Protocol: CurrentProtocolID, EnvironmentDigest: binding.environmentDigest,
		ProfileDigest: binding.profileDigest, PolicyID: binding.policyID, PolicyRevision: binding.policyRevision,
		PolicyDigest: binding.policyDigest, PrincipalDigest: binding.principalDigest, BrokerDigest: binding.brokerDigest,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge[:]),
		Deadline:  now.UTC().Add(MaxCurrentTTL).Format(time.RFC3339Nano)}
	request.RequestDigest = request.digest()
	if request.Verify(binding, now) != nil {
		return CurrentRequest{}, ErrInvalid
	}
	return request, nil
}

func DecodeCurrentRequest(document []byte, binding Binding, now time.Time) (CurrentRequest, error) {
	if len(document) < 1 || len(document) > MaxCurrentBytes {
		return CurrentRequest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var request CurrentRequest
	if decoder.Decode(&request) != nil {
		return CurrentRequest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CurrentRequest{}, ErrInvalid
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, document) || request.Verify(binding, now) != nil {
		return CurrentRequest{}, ErrInvalid
	}
	return request, nil
}

func (r CurrentRequest) Verify(binding Binding, now time.Time) error {
	deadline, err := canonicalTime(r.Deadline)
	challenge, challengeErr := base64.RawURLEncoding.DecodeString(r.Challenge)
	if r.Protocol != CurrentProtocolID || r.EnvironmentDigest != binding.environmentDigest ||
		r.ProfileDigest != binding.profileDigest || r.PolicyID != binding.policyID ||
		r.PolicyRevision != binding.policyRevision || r.PolicyDigest != binding.policyDigest ||
		r.PrincipalDigest != binding.principalDigest || r.BrokerDigest != binding.brokerDigest ||
		err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(MaxCurrentTTL)) ||
		challengeErr != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != r.Challenge ||
		r.RequestDigest != r.digest() {
		return ErrInvalid
	}
	return nil
}

func (r CurrentRequest) digest() string {
	r.RequestDigest = ""
	document, _ := json.Marshal(r)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/egress-policy-current-request/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func SignCurrent(binding Binding, request CurrentRequest, record CurrentRecord, now time.Time, privateKey ed25519.PrivateKey) (CurrentResponse, error) {
	if request.Verify(binding, now) != nil || record.Generation < 1 || !digestRegex.MatchString(record.SnapshotDigest) ||
		(record.Status != "active" && record.Status != "revoked") || len(privateKey) != ed25519.PrivateKeySize ||
		!privateKey.Public().(ed25519.PublicKey).Equal(binding.operatorPublicKey) {
		return CurrentResponse{}, ErrInvalid
	}
	response := CurrentResponse{Protocol: CurrentProtocolID, RequestDigest: request.RequestDigest, Challenge: request.Challenge,
		EnvironmentDigest: binding.environmentDigest, ProfileDigest: binding.profileDigest, PolicyID: binding.policyID,
		PolicyRevision: binding.policyRevision, PolicyDigest: binding.policyDigest,
		PrincipalDigest: binding.principalDigest, BrokerDigest: binding.brokerDigest,
		Generation: record.Generation, Status: record.Status, SnapshotDigest: record.SnapshotDigest,
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.UTC().Add(MaxCurrentTTL).Format(time.RFC3339Nano),
		OperatorKeyID: binding.operatorKeyID}
	response.ResponseDigest = response.digest()
	response.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(response.ResponseDigest)))
	return response, nil
}

func DecodeCurrentResponse(document []byte, request CurrentRequest, binding Binding, now time.Time) (CurrentResponse, error) {
	if len(document) < 1 || len(document) > MaxCurrentBytes {
		return CurrentResponse{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var response CurrentResponse
	if decoder.Decode(&response) != nil {
		return CurrentResponse{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CurrentResponse{}, ErrInvalid
	}
	canonical, err := json.Marshal(response)
	if err != nil || !bytes.Equal(canonical, document) || response.Verify(request, binding, now) != nil {
		return CurrentResponse{}, ErrInvalid
	}
	return response, nil
}

func (r CurrentResponse) Verify(request CurrentRequest, binding Binding, now time.Time) error {
	issued, issueErr := canonicalTime(r.IssuedAt)
	expires, expiryErr := canonicalTime(r.ExpiresAt)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(r.Signature)
	if request.Verify(binding, now) != nil || r.Protocol != CurrentProtocolID || r.RequestDigest != request.RequestDigest ||
		r.Challenge != request.Challenge || r.EnvironmentDigest != binding.environmentDigest ||
		r.ProfileDigest != binding.profileDigest || r.PolicyID != binding.policyID ||
		r.PolicyRevision != binding.policyRevision || r.PolicyDigest != binding.policyDigest ||
		r.PrincipalDigest != binding.principalDigest || r.BrokerDigest != binding.brokerDigest ||
		r.Generation < 1 || (r.Status != "active" && r.Status != "revoked") ||
		!digestRegex.MatchString(r.SnapshotDigest) || r.OperatorKeyID != binding.operatorKeyID ||
		issueErr != nil || expiryErr != nil || issued.After(now) || !expires.After(now) ||
		!expires.After(issued) || expires.Sub(issued) > MaxCurrentTTL ||
		r.ResponseDigest != r.digest() || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != r.Signature ||
		!ed25519.Verify(binding.operatorPublicKey, []byte(r.ResponseDigest), signature) {
		return ErrInvalid
	}
	return nil
}

func (r CurrentResponse) digest() string {
	r.ResponseDigest, r.Signature = "", ""
	document, _ := json.Marshal(r)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/egress-policy-current-response/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func CompareCurrent(snapshot Snapshot, response CurrentResponse) error {
	if snapshot.Generation != response.Generation || snapshot.Status != response.Status ||
		snapshot.SnapshotDigest != response.SnapshotDigest || snapshot.Status != "active" {
		return ErrInvalid
	}
	return nil
}
