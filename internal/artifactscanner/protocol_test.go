package artifactscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

func TestScanAuthorityRejectsDriftAndNoncanonicalWire(t *testing.T) {
	now := time.Now().UTC()
	content := []byte(`{"safe":true}`)
	authority, err := NewAuthority(context.Background(), scannerTestRequest(content), scanDigest([]byte("profile")), now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeAuthority(encoded, now); err != nil || decoded != authority {
		t.Fatalf("roundtrip = %#v, %v", decoded, err)
	}
	for name, wire := range map[string][]byte{
		"unknown":   bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"unknown":true,"protocol":`), 1),
		"duplicate": bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"protocol":"bad","protocol":`), 1),
		"spacing":   append([]byte(" "), encoded...),
		"oversize":  bytes.Repeat([]byte("x"), MaxAuthorityBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAuthority(wire, now); !errors.Is(err, ErrInvalidScanProtocol) {
				t.Fatalf("decode = %v", err)
			}
		})
	}
	if _, err := DecodeAuthority(encoded, authority.ExpiresAt); !errors.Is(err, ErrInvalidScanProtocol) {
		t.Fatalf("expired authority = %v", err)
	}
	request := scannerTestRequest(content)
	acceptedAt := now.Add(-time.Second)
	request.Deadline = acceptedAt.Add(request.Retention)
	if err := request.Validate(acceptedAt); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(now); err == nil {
		t.Fatal("test fixture did not reproduce retention restart bug")
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(2*time.Second))
	defer cancel()
	accepted, err := NewAuthority(ctx, request, scanDigest([]byte("profile")), now, 5*time.Second)
	if err != nil || accepted.ExpiresAt.After(now.Add(2*time.Second)) {
		t.Fatalf("already-accepted request was refused or extended: %#v, %v", accepted, err)
	}
	authority.ContentDigest = scanDigest([]byte("different"))
	if authority.Digest() == "" {
		t.Fatal("tampered authority unexpectedly lacks digest")
	}
}

func TestScanResponseRejectsMismatchSkipAndNoncanonicalWire(t *testing.T) {
	now := time.Now().UTC()
	authority, err := NewAuthority(context.Background(), scannerTestRequest([]byte(`{"safe":true}`)), scanDigest([]byte("profile")), now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Protocol: ProtocolID, RequestID: authority.RequestID,
		AuthorityDigest: authority.Digest(), ContentDigest: authority.ContentDigest,
		RuleSetDigest: scanDigest([]byte("rules")), Active: artifact.CheckPassed,
		Malware: artifact.CheckPassed, CheckedAt: now}
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(encoded, authority, now); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]func(*Response){
		"authority": func(r *Response) { r.AuthorityDigest = scanDigest([]byte("wrong")) },
		"content":   func(r *Response) { r.ContentDigest = scanDigest([]byte("wrong")) },
		"request":   func(r *Response) { r.RequestID = scanDigest([]byte("wrong")) },
		"skip":      func(r *Response) { r.Malware = artifact.CheckNotRun },
		"time":      func(r *Response) { r.CheckedAt = now.Add(time.Minute) },
		"early":     func(r *Response) { r.CheckedAt = authority.IssuedAt.Add(-time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := response
			changed(&candidate)
			wire, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeResponse(wire, authority, now); !errors.Is(err, ErrInvalidScanProtocol) {
				t.Fatalf("decode = %v", err)
			}
		})
	}
	if _, err := DecodeResponse(encoded, authority, authority.ExpiresAt); !errors.Is(err, ErrInvalidScanProtocol) {
		t.Fatalf("late response = %v", err)
	}
	for name, wire := range map[string][]byte{
		"unknown":   bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"extra":1,"protocol":`), 1),
		"duplicate": bytes.Replace(encoded, []byte(`"protocol":`), []byte(`"protocol":"bad","protocol":`), 1),
		"spacing":   append(encoded, ' '),
		"oversize":  []byte(strings.Repeat("x", MaxResponseBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResponse(wire, authority, now); !errors.Is(err, ErrInvalidScanProtocol) {
				t.Fatalf("decode = %v", err)
			}
		})
	}
}
