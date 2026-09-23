package egresspolicystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFreshCurrentAttestationRejectsRestartReplayAndCrossBinding(t *testing.T) {
	binding, key, now := stateFixture(t)
	request, err := NewCurrentRequest(binding, now)
	if err != nil {
		t.Fatal(err)
	}
	requestDocument, _ := json.Marshal(request)
	if _, err := DecodeCurrentRequest(requestDocument, binding, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewSigned(binding, 2, now, now.Add(10*time.Second), "active", key)
	if err != nil {
		t.Fatal(err)
	}
	response, err := SignCurrent(binding, request, CurrentRecord{Generation: snapshot.Generation,
		Status: snapshot.Status, SnapshotDigest: snapshot.SnapshotDigest}, now.Add(time.Second), key)
	if err != nil {
		t.Fatal(err)
	}
	responseDocument, _ := json.Marshal(response)
	if _, err := DecodeCurrentResponse(responseDocument, request, binding, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := CompareCurrent(snapshot, response); err != nil {
		t.Fatal(err)
	}
	old, err := NewSigned(binding, 1, now, now.Add(10*time.Second), "active", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareCurrent(old, response); !errors.Is(err, ErrInvalid) {
		t.Fatalf("still-valid old snapshot matched current authority: %v", err)
	}
	otherRequest, err := NewCurrentRequest(binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCurrentResponse(responseDocument, otherRequest, binding, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed challenge response = %v", err)
	}
	if _, err := DecodeCurrentResponse(responseDocument, request, binding, now.Add(6*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired current attestation = %v", err)
	}
	for name, mutate := range map[string]func(*CurrentResponse){
		"broker":      func(r *CurrentResponse) { r.BrokerDigest = "sha256:" + strings.Repeat("f", 64) },
		"environment": func(r *CurrentResponse) { r.EnvironmentDigest = "sha256:" + strings.Repeat("f", 64) },
		"generation":  func(r *CurrentResponse) { r.Generation++ },
		"signature":   func(r *CurrentResponse) { r.Signature = "invalid" },
		"challenge":   func(r *CurrentResponse) { r.Challenge = otherRequest.Challenge },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := response
			mutate(&candidate)
			encoded, _ := json.Marshal(candidate)
			if _, err := DecodeCurrentResponse(encoded, request, binding, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("attestation drift accepted: %v", err)
			}
		})
	}
	for name, candidate := range map[string][]byte{
		"unknown":      bytes.Replace(responseDocument, []byte(`"protocol":`), []byte(`"extra":true,"protocol":`), 1),
		"duplicate":    bytes.Replace(responseDocument, []byte(`"protocol":`), []byte(`"protocol":"x","protocol":`), 1),
		"noncanonical": append([]byte(" "), responseDocument...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCurrentResponse(candidate, request, binding, now.Add(2*time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("attestation document accepted: %v", err)
			}
		})
	}
	revoked, err := NewSigned(binding, 3, now, now.Add(10*time.Second), "revoked", key)
	if err != nil {
		t.Fatal(err)
	}
	revokedResponse, err := SignCurrent(binding, request, CurrentRecord{Generation: revoked.Generation,
		Status: revoked.Status, SnapshotDigest: revoked.SnapshotDigest}, now.Add(time.Second), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareCurrent(revoked, revokedResponse); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked state admitted broker startup: %v", err)
	}
}
