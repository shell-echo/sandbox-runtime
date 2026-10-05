package artifactscanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

const (
	ProtocolID        = "sandbox-runtime.private-artifact-scan.v1"
	MaxAuthorityBytes = 4 << 10
	MaxResponseBytes  = 4 << 10
	maxAuthorityAge   = 30 * time.Second
)

var (
	ErrInvalidScanProtocol = errors.New("invalid private artifact scan protocol")
	scanDigestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	scanIDPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

// Authority is a short-lived private request binding, not an additional
// signing key or a Provider authorization decision. mTLS authenticates the
// exact coding Provider peer; the server independently hashes the body.
type Authority struct {
	Protocol      string    `json:"protocol"`
	RequestID     string    `json:"request_id"`
	ProfileDigest string    `json:"profile_digest"`
	TenantDigest  string    `json:"tenant_digest"`
	SandboxID     string    `json:"sandbox_id"`
	OperationID   string    `json:"operation_id"`
	RequestDigest string    `json:"request_digest"`
	ContentDigest string    `json:"content_digest"`
	MediaType     string    `json:"media_type"`
	Generation    int64     `json:"generation"`
	Fence         int64     `json:"fence"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func NewAuthority(ctx context.Context, request artifact.Request, profileDigest string, now time.Time, operationTimeout time.Duration) (Authority, error) {
	if ctx == nil {
		return Authority{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return Authority{}, err
	}
	// The Stager already checked the Contract at acceptedAt. Do not restart
	// the retention window at scan time: Validate(now) would reject a valid
	// already-accepted request near its deadline.
	if operationTimeout < time.Second || operationTimeout > maxAuthorityAge ||
		!request.Deadline.After(now) {
		return Authority{}, ErrInvalidScanProtocol
	}
	if err := request.Validate(request.Deadline.Add(-request.Retention)); err != nil {
		return Authority{}, err
	}
	expiry := now.UTC().Add(operationTimeout)
	if request.Deadline.Before(expiry) {
		expiry = request.Deadline.UTC()
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiry) {
		expiry = deadline.UTC()
	}
	value := Authority{Protocol: ProtocolID,
		RequestID:     scanDigest([]byte("request\x00" + request.OperationID + "\x00" + request.AttemptID + "\x00" + request.RequestDigest + "\x00" + request.ExpectedDigest)),
		ProfileDigest: profileDigest, TenantDigest: scanDigest([]byte("tenant\x00" + request.TenantID)),
		SandboxID: request.SandboxID, OperationID: request.OperationID,
		RequestDigest: request.RequestDigest, ContentDigest: request.ExpectedDigest,
		MediaType: request.ExpectedMediaType, Generation: request.ExpectedGeneration,
		Fence: request.FencingToken, IssuedAt: now.UTC(), ExpiresAt: expiry}
	if err := value.Validate(now); err != nil {
		return Authority{}, err
	}
	return value, nil
}

func (a Authority) Validate(now time.Time) error {
	if a.Protocol != ProtocolID || !scanDigestPattern.MatchString(a.RequestID) ||
		!scanDigestPattern.MatchString(a.ProfileDigest) || !scanDigestPattern.MatchString(a.TenantDigest) ||
		!scanIDPattern.MatchString(a.SandboxID) || !scanIDPattern.MatchString(a.OperationID) ||
		!scanDigestPattern.MatchString(a.RequestDigest) || !scanDigestPattern.MatchString(a.ContentDigest) ||
		a.MediaType != "application/json" || a.Generation < 1 || a.Fence < 1 ||
		a.IssuedAt.IsZero() || a.IssuedAt.After(now) || !a.ExpiresAt.After(now) ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.After(a.IssuedAt.Add(maxAuthorityAge)) {
		return ErrInvalidScanProtocol
	}
	return nil
}

func (a Authority) Digest() string {
	encoded, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return scanDigest(encoded)
}

type Response struct {
	Protocol        string               `json:"protocol"`
	RequestID       string               `json:"request_id"`
	AuthorityDigest string               `json:"authority_digest"`
	ContentDigest   string               `json:"content_digest"`
	RuleSetDigest   string               `json:"rule_set_digest"`
	Active          artifact.CheckStatus `json:"active"`
	Malware         artifact.CheckStatus `json:"malware"`
	CheckedAt       time.Time            `json:"checked_at"`
}

func (r Response) Validate(authority Authority, now time.Time) error {
	if r.Protocol != ProtocolID || r.RequestID != authority.RequestID ||
		r.AuthorityDigest != authority.Digest() || r.ContentDigest != authority.ContentDigest ||
		!scanDigestPattern.MatchString(r.RuleSetDigest) || r.CheckedAt.IsZero() ||
		r.CheckedAt.Before(authority.IssuedAt) || r.CheckedAt.After(now) ||
		r.CheckedAt.After(authority.ExpiresAt) || !authority.ExpiresAt.After(now) ||
		!((r.Active == artifact.CheckPassed && (r.Malware == artifact.CheckPassed || r.Malware == artifact.CheckFailed)) ||
			(r.Active == artifact.CheckFailed && r.Malware == artifact.CheckNotRun)) {
		return ErrInvalidScanProtocol
	}
	return nil
}

func EncodeAuthority(a Authority) ([]byte, error) {
	encoded, err := json.Marshal(a)
	if err != nil || len(encoded) > MaxAuthorityBytes {
		return nil, ErrInvalidScanProtocol
	}
	return encoded, nil
}

func DecodeAuthority(encoded []byte, now time.Time) (Authority, error) {
	var value Authority
	if len(encoded) == 0 || len(encoded) > MaxAuthorityBytes || json.Unmarshal(encoded, &value) != nil {
		return Authority{}, ErrInvalidScanProtocol
	}
	canonical, err := EncodeAuthority(value)
	if err != nil || !bytes.Equal(encoded, canonical) || value.Validate(now) != nil {
		return Authority{}, ErrInvalidScanProtocol
	}
	return value, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxResponseBytes {
		return nil, ErrInvalidScanProtocol
	}
	return encoded, nil
}

func DecodeResponse(encoded []byte, authority Authority, now time.Time) (Response, error) {
	var value Response
	if len(encoded) == 0 || len(encoded) > MaxResponseBytes || json.Unmarshal(encoded, &value) != nil {
		return Response{}, ErrInvalidScanProtocol
	}
	canonical, err := EncodeResponse(value)
	if err != nil || !bytes.Equal(encoded, canonical) || value.Validate(authority, now) != nil {
		return Response{}, ErrInvalidScanProtocol
	}
	return value, nil
}

func scanDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
