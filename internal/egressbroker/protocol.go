package egressbroker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const (
	ProtocolID = "sandbox-runtime.egress-broker.v1"
	OpenType   = "open"
	AcceptType = "accepted"
	DenyType   = "denied"

	maxRequestBytes  = 8 << 10
	maxResponseBytes = 8 << 10
)

var requestIDPattern = regexp.MustCompile(`^egress_[0-9a-f]{32}$`)

type Open struct {
	Protocol        string `json:"protocol"`
	Type            string `json:"type"`
	RequestID       string `json:"request_id"`
	Nonce           string `json:"nonce"`
	Deadline        string `json:"deadline"`
	PolicyID        string `json:"policy_id"`
	PolicyRevision  string `json:"policy_revision"`
	PrincipalDigest string `json:"principal_digest"`
	BrokerDigest    string `json:"broker_digest"`
	TargetAlias     string `json:"target_alias"`
	LeaseSeconds    int64  `json:"lease_seconds"`
	RequestDigest   string `json:"request_digest"`
}

type Accepted struct {
	Protocol        string `json:"protocol"`
	Type            string `json:"type"`
	RequestID       string `json:"request_id"`
	RequestDigest   string `json:"request_digest"`
	PolicyRevision  string `json:"policy_revision"`
	PrincipalDigest string `json:"principal_digest"`
	BrokerDigest    string `json:"broker_digest"`
	LeaseExpiresAt  string `json:"lease_expires_at"`
}

func newOpen(policy Policy, requestID, nonce, alias string, deadline time.Time, lease time.Duration) Open {
	request := Open{Protocol: ProtocolID, Type: OpenType, RequestID: requestID, Nonce: nonce,
		Deadline: deadline.UTC().Format(time.RFC3339Nano), PolicyID: policy.ID, PolicyRevision: policy.Revision,
		PrincipalDigest: policy.Principal.Digest(), BrokerDigest: policy.Broker.Digest(), TargetAlias: alias,
		LeaseSeconds: int64(lease / time.Second)}
	request.RequestDigest = openDigest(request)
	return request
}

func (o Open) Validate(policy Policy, now time.Time) error {
	deadline, err := parseTime(o.Deadline)
	if policy.Validate() != nil || o.Protocol != ProtocolID || o.Type != OpenType || !requestIDPattern.MatchString(o.RequestID) ||
		!validNonce(o.Nonce) || err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		o.PolicyID != policy.ID || o.PolicyRevision != policy.Revision || o.PrincipalDigest != policy.Principal.Digest() ||
		o.BrokerDigest != policy.Broker.Digest() || o.RequestDigest != openDigest(o) || o.LeaseSeconds < 1 ||
		time.Duration(o.LeaseSeconds)*time.Second > policy.Lease {
		return ErrDenied
	}
	if _, known := policy.target(o.TargetAlias); !known {
		return ErrDenied
	}
	return nil
}

func (a Accepted) Validate(request Open, policy Policy, now time.Time) error {
	if a.Protocol != ProtocolID || a.RequestID != request.RequestID || a.RequestDigest != request.RequestDigest ||
		a.PolicyRevision != policy.Revision || a.PrincipalDigest != policy.Principal.Digest() || a.BrokerDigest != policy.Broker.Digest() {
		return ErrUnavailable
	}
	if a.Type == DenyType {
		if a.LeaseExpiresAt != "" {
			return ErrUnavailable
		}
		return nil
	}
	expiresAt, err := parseTime(a.LeaseExpiresAt)
	if a.Type != AcceptType || err != nil || now.IsZero() || !expiresAt.After(now) ||
		expiresAt.After(now.Add(time.Duration(request.LeaseSeconds)*time.Second+time.Second)) {
		return ErrUnavailable
	}
	return nil
}

func acceptedFor(request Open, policy Policy, expiry time.Time) Accepted {
	return Accepted{Protocol: ProtocolID, Type: AcceptType, RequestID: request.RequestID, RequestDigest: request.RequestDigest,
		PolicyRevision: policy.Revision, PrincipalDigest: policy.Principal.Digest(), BrokerDigest: policy.Broker.Digest(),
		LeaseExpiresAt: expiry.UTC().Format(time.RFC3339Nano)}
}

func deniedFor(request Open, policy Policy) Accepted {
	return Accepted{Protocol: ProtocolID, Type: DenyType, RequestID: request.RequestID, RequestDigest: request.RequestDigest,
		PolicyRevision: policy.Revision, PrincipalDigest: policy.Principal.Digest(), BrokerDigest: policy.Broker.Digest()}
}

func encodeOpen(request Open, policy Policy, now time.Time) ([]byte, error) {
	if request.Validate(policy, now) != nil {
		return nil, ErrDenied
	}
	return json.Marshal(request)
}

func decodeOpen(document []byte, policy Policy, now time.Time) (Open, error) {
	var request Open
	if decodeCanonical(document, maxRequestBytes, &request) != nil || request.Validate(policy, now) != nil {
		return Open{}, ErrDenied
	}
	return request, nil
}

func encodeAccepted(response Accepted, request Open, policy Policy, now time.Time) ([]byte, error) {
	if response.Validate(request, policy, now) != nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(response)
}

func decodeAccepted(document []byte, request Open, policy Policy, now time.Time) (Accepted, error) {
	var response Accepted
	if decodeCanonical(document, maxResponseBytes, &response) != nil || response.Validate(request, policy, now) != nil || response.Type != AcceptType {
		return Accepted{}, ErrDenied
	}
	return response, nil
}

func openDigest(request Open) string {
	request.RequestDigest = ""
	document, _ := json.Marshal(request)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/egress-broker/open/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func decodeCanonical(document []byte, maximum int, target any) error {
	if len(document) < 1 || len(document) > maximum || rejectDuplicates(document) != nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrInvalid
	}
	return nil
}

func rejectDuplicates(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var scan func(json.Token) error
	scan = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
