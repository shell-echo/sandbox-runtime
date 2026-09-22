package egressbroker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProtocolRejectsUnknownDuplicateNonCanonicalAndOversizedOpen(t *testing.T) {
	policy := testPolicy(t)
	now := time.Now().UTC().Truncate(time.Second)
	request := newOpen(policy, "egress_"+strings.Repeat("a", 32), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"packages", now.Add(10*time.Second), time.Second)
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(document[:len(document)-1], []byte(`,"unknown":true}`)...)
	duplicate := append(document[:len(document)-1], []byte(`,"nonce":"`+request.Nonce+`"}`)...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "noncanonical": append(document, '\n'),
		"oversized": bytes.Repeat([]byte{'x'}, maxRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOpen(candidate, policy, now); !errors.Is(err, ErrDenied) {
				t.Fatalf("decodeOpen() error = %v", err)
			}
		})
	}
}

func TestOpenBindsPolicyPrincipalsTargetLeaseAndDeadline(t *testing.T) {
	policy := testPolicy(t)
	now := time.Now().UTC().Truncate(time.Second)
	valid := newOpen(policy, "egress_"+strings.Repeat("a", 32), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		"packages", now.Add(10*time.Second), time.Second)
	if valid.Validate(policy, now) != nil {
		t.Fatal("valid open rejected")
	}
	mutations := []func(*Open){
		func(value *Open) { value.PolicyRevision = "policy-2" },
		func(value *Open) { value.PrincipalDigest = policy.Broker.Digest() },
		func(value *Open) { value.BrokerDigest = policy.Principal.Digest() },
		func(value *Open) { value.TargetAlias = "93.184.216.34" },
		func(value *Open) { value.LeaseSeconds = 3 },
		func(value *Open) { value.Deadline = now.Format(time.RFC3339Nano) },
		func(value *Open) { value.RequestDigest = "sha256:" + strings.Repeat("0", 64) },
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		if candidate.Validate(policy, now) == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}
