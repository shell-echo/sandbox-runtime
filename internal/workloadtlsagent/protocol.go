package workloadtlsagent

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
	ProtocolID = "sandbox-runtime.workload-tls-agent.v1"

	SnapshotType = "snapshot"
	SignType     = "sign"
	SuccessType  = "success"
	ErrorType    = "error"

	maxRequestBytes  = 8 << 10
	maxResponseBytes = 256 << 10
)

var requestIDPattern = regexp.MustCompile(`^tls_[0-9a-f]{32}$`)

type Request struct {
	Protocol      string `json:"protocol"`
	Type          string `json:"type"`
	RequestID     string `json:"request_id"`
	Nonce         string `json:"nonce"`
	Deadline      string `json:"deadline"`
	Generation    int64  `json:"generation"`
	Hash          string `json:"hash"`
	Digest        []byte `json:"digest"`
	RequestDigest string `json:"request_digest"`
}

type Response struct {
	Protocol         string   `json:"protocol"`
	Type             string   `json:"type"`
	RequestID        string   `json:"request_id"`
	RequestDigest    string   `json:"request_digest"`
	Generation       int64    `json:"generation"`
	IssuerRevision   string   `json:"issuer_revision"`
	Serial           string   `json:"serial"`
	CertificateDER   [][]byte `json:"certificate_der"`
	PublicKeyDER     []byte   `json:"public_key_der"`
	NotBefore        string   `json:"not_before"`
	NotAfter         string   `json:"not_after"`
	RevocationSafeTo string   `json:"revocation_safe_to"`
	Signature        []byte   `json:"signature"`
}

func (r Request) Validate(now time.Time) error {
	deadline, err := parseProtocolTime(r.Deadline)
	if r.Protocol != ProtocolID || !requestIDPattern.MatchString(r.RequestID) || !validNonce(r.Nonce) || err != nil || now.IsZero() ||
		!deadline.After(now) || deadline.After(now.Add(time.Minute)) || r.RequestDigest != requestDigest(r) {
		return ErrUnavailable
	}
	switch r.Type {
	case SnapshotType:
		if r.Generation != 0 || r.Hash != "" || len(r.Digest) != 0 {
			return ErrUnavailable
		}
	case SignType:
		if r.Generation < 1 || r.Hash != "sha256" || len(r.Digest) != sha256.Size {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func (r Response) Validate(request Request, now time.Time) error {
	if r.Protocol != ProtocolID || r.RequestID != request.RequestID || r.RequestDigest != request.RequestDigest || now.IsZero() {
		return ErrUnavailable
	}
	if r.Type == ErrorType {
		if r.Generation != 0 || r.IssuerRevision != "" || r.Serial != "" || len(r.CertificateDER) != 0 || len(r.PublicKeyDER) != 0 ||
			r.NotBefore != "" || r.NotAfter != "" || r.RevocationSafeTo != "" || len(r.Signature) != 0 {
			return ErrUnavailable
		}
		return nil
	}
	if r.Type != SuccessType {
		return ErrUnavailable
	}
	switch request.Type {
	case SnapshotType:
		notBefore, beforeErr := parseProtocolTime(r.NotBefore)
		notAfter, afterErr := parseProtocolTime(r.NotAfter)
		safeTo, safeErr := parseProtocolTime(r.RevocationSafeTo)
		if r.Generation < 1 || r.IssuerRevision == "" || r.Serial == "" || len(r.CertificateDER) < 2 || len(r.CertificateDER) > 9 ||
			len(r.PublicKeyDER) < 1 || len(r.PublicKeyDER) > 4<<10 || beforeErr != nil || afterErr != nil || safeErr != nil ||
			now.Before(notBefore) || !now.Before(notAfter) || !now.Before(safeTo) || len(r.Signature) != 0 {
			return ErrUnavailable
		}
		for _, certificate := range r.CertificateDER {
			if len(certificate) < 1 || len(certificate) > 64<<10 {
				return ErrUnavailable
			}
		}
	case SignType:
		if r.Generation != request.Generation || r.IssuerRevision != "" || r.Serial != "" || len(r.CertificateDER) != 0 || len(r.PublicKeyDER) != 0 ||
			r.NotBefore != "" || r.NotAfter != "" || r.RevocationSafeTo != "" || len(r.Signature) < 8 || len(r.Signature) > 256 {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func newRequest(kind, requestID, nonce string, deadline time.Time, generation int64, digest []byte) Request {
	request := Request{Protocol: ProtocolID, Type: kind, RequestID: requestID, Nonce: nonce, Deadline: deadline.UTC().Format(time.RFC3339Nano),
		Generation: generation, Digest: append([]byte(nil), digest...)}
	if kind == SignType {
		request.Hash = "sha256"
	}
	request.RequestDigest = requestDigest(request)
	return request
}

func responseFor(request Request, snapshot Snapshot, signature []byte) Response {
	response := Response{Protocol: ProtocolID, Type: SuccessType, RequestID: request.RequestID, RequestDigest: request.RequestDigest}
	if request.Type == SnapshotType {
		response.Generation, response.IssuerRevision, response.Serial = snapshot.Generation, snapshot.IssuerRevision, snapshot.Serial
		response.CertificateDER, response.PublicKeyDER = cloneDER(snapshot.CertificateDER), append([]byte(nil), snapshot.PublicKeyDER...)
		response.NotBefore, response.NotAfter = snapshot.NotBefore.Format(time.RFC3339Nano), snapshot.NotAfter.Format(time.RFC3339Nano)
		response.RevocationSafeTo = snapshot.RevocationSafeTo.Format(time.RFC3339Nano)
	} else {
		response.Generation, response.Signature = request.Generation, append([]byte(nil), signature...)
	}
	return response
}

func errorResponse(request Request) Response {
	return Response{Protocol: ProtocolID, Type: ErrorType, RequestID: request.RequestID, RequestDigest: request.RequestDigest}
}

func encodeRequest(request Request, now time.Time) ([]byte, error) {
	if request.Validate(now) != nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(request)
}

func decodeRequest(document []byte, now time.Time) (Request, error) {
	var request Request
	if decodeCanonical(document, maxRequestBytes, &request) != nil || request.Validate(now) != nil {
		return Request{}, ErrUnavailable
	}
	return request, nil
}

func encodeResponse(response Response, request Request, now time.Time) ([]byte, error) {
	if response.Validate(request, now) != nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(response)
}

func decodeResponse(document []byte, request Request, now time.Time) (Response, error) {
	var response Response
	if decodeCanonical(document, maxResponseBytes, &response) != nil || response.Validate(request, now) != nil || response.Type == ErrorType {
		return Response{}, ErrUnavailable
	}
	return response, nil
}

func requestDigest(request Request) string {
	request.RequestDigest = ""
	document, _ := json.Marshal(request)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-tls-agent/request/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func decodeCanonical(document []byte, maximum int, target any) error {
	if len(document) < 1 || len(document) > maximum || rejectDuplicates(document) != nil {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrUnavailable
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
					return ErrUnavailable
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrUnavailable
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrUnavailable
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrUnavailable
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrUnavailable
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrUnavailable
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func parseProtocolTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrUnavailable
	}
	return parsed, nil
}
