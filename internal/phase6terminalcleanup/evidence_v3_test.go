package phase6terminalcleanup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func terminalV3SyntheticEvidence(t *testing.T) (Plan, EvidenceV3) {
	t.Helper()
	plan, remote, _, now, _ := terminalV2Fixture(t)
	observed := make(map[string]TokenObservation, len(remote.observed))
	for key, value := range remote.observed {
		observed[key] = value
	}
	receipt, err := Execute(context.Background(), plan, remote, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	issuer := sha256.Sum256(remote.issuerDER)
	crl := sha256.Sum256(remote.crlDER)
	evidence := EvidenceV3{Protocol: EvidenceV3Protocol, RunID: plan.RunID,
		ProfileDigest: plan.ProfileDigest, PlanDigest: plan.Digest,
		CRLVerifiedUTC: now.UTC().Format(time.RFC3339Nano),
		IssuerDER:      append([]byte(nil), remote.issuerDER...),
		CRLDER:         append([]byte(nil), remote.crlDER...), Receipt: receipt}
	appendEvent := func(kind, target string, status int, media string) *EvidenceV3Event {
		evidence.Events = append(evidence.Events, EvidenceV3Event{
			Kind: kind, TargetDigest: target, Status: status, MediaType: media})
		return &evidence.Events[len(evidence.Events)-1]
	}
	for _, target := range plan.Tokens {
		value := observed[target.Accessor]
		event := appendEvent("lookup-preflight", targetDigest("token", target.Accessor), 200, "application/json")
		event.ObservedDigest = targetDigest("token", value.Accessor)
		event.Token = &EvidenceV3Token{Policies: value.Policies, Metadata: value.Metadata,
			Role: value.Role, Type: value.Type, Orphan: value.Orphan,
			Renewable: value.Renewable, TTLSeconds: value.TTLSeconds}
	}
	for _, target := range plan.Certificates {
		if target.State != "active" {
			continue
		}
		kind := "certificate"
		if target.Kind == externalPostgresKind {
			kind = externalPostgresKind
		}
		event := appendEvent("certificate-revoke", targetDigest(kind, target.Serial), 200, "application/json")
		event.RevocationState = "revoked"
		event.RevocationUnix = now.Add(-time.Second).Unix()
		event.RevocationRFC3339 = now.Add(-time.Second).UTC().Truncate(time.Second).Format(time.RFC3339Nano)
	}
	issuerDigest := "sha256:" + hex.EncodeToString(issuer[:])
	crlDigest := "sha256:" + hex.EncodeToString(crl[:])
	appendEvent("issuer-read", plan.GeneralIssuerDigest, 200, "application/pkix-cert").ObservedDigest = issuerDigest
	appendEvent("crl-config", plan.GeneralIssuerDigest, 200, "application/json").CRLConfig = &EvidenceV3CRLConfig{}
	appendEvent("issuer-reread", plan.GeneralIssuerDigest, 200, "application/pkix-cert").ObservedDigest = issuerDigest
	appendEvent("crl-read", plan.GeneralIssuerDigest, 200, "application/pkix-crl").ObservedDigest = crlDigest
	for _, target := range plan.Tokens {
		if target.State != "active" {
			continue
		}
		digest := targetDigest("token", target.Accessor)
		appendEvent("accessor-revoke", digest, 204, "")
		appendEvent("lookup-post-revoke", digest, 400, "application/json").InvalidAccessorError = "invalid accessor"
	}
	appendEvent("self-revoke", plan.Digest, 204, "")
	return plan, evidence
}

func TestTerminalEvidenceV3OfflineReplayAndClosedEnvelope(t *testing.T) {
	plan, evidence := terminalV3SyntheticEvidence(t)
	if err := VerifyEvidenceV3(plan, evidence); err != nil {
		t.Fatalf("synthetic v2 plan/v3 private response projection rejected: %v", err)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	line := append(append([]byte(nil), encoded...), '\n')
	decoded, err := DecodeEvidenceV3(line)
	if err != nil || VerifyEvidenceV3(plan, decoded) != nil {
		t.Fatalf("canonical v3 private line did not replay: %v", err)
	}
	for name, raw := range map[string][]byte{
		"missing newline": encoded,
		"trailing":        append(append([]byte(nil), line...), '\n'),
		"unknown":         append(bytes.Replace(encoded, []byte(`"Protocol":`), []byte(`"Unknown":1,"Protocol":`), 1), '\n'),
		"duplicate":       append(bytes.Replace(encoded, []byte(`"Protocol":`), []byte(`"Protocol":"x","Protocol":`), 1), '\n'),
		"oversized":       bytes.Repeat([]byte{'x'}, MaxEvidenceV3Bytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEvidenceV3(raw); err == nil {
				t.Fatal("noncanonical or oversized evidence admitted")
			}
		})
	}
	for name, mutate := range map[string]func(*EvidenceV3){
		"wrong run":    func(e *EvidenceV3) { e.RunID = strings.Repeat("b", 32) },
		"wrong issuer": func(e *EvidenceV3) { e.IssuerDER[3] ^= 1 },
		"wrong CRL":    func(e *EvidenceV3) { e.CRLDER[3] ^= 1 },
		"receipt-only confirmed": func(e *EvidenceV3) {
			e.Events = e.Events[:len(e.Events)-1]
		},
		"duplicate self": func(e *EvidenceV3) {
			e.Events = append(e.Events, e.Events[len(e.Events)-1])
		},
		"wrong target":       func(e *EvidenceV3) { e.Events[0].TargetDigest = plan.Digest },
		"lookup 404":         func(e *EvidenceV3) { e.Events[len(e.Events)-2].Status = 404 },
		"forged absence":     func(e *EvidenceV3) { e.Events[len(e.Events)-2].InvalidAccessorError = "permission denied" },
		"token metadata":     func(e *EvidenceV3) { e.Events[0].Token.Metadata["lease_id"] = "wrong" },
		"CRL auto rebuild":   func(e *EvidenceV3) { e.Events[6].CRLConfig.AutoRebuild = true },
		"self response body": func(e *EvidenceV3) { e.Events[len(e.Events)-1].InvalidAccessorError = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			// JSON roundtrip gives this negative its own deep copy.
			var changed EvidenceV3
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("copy evidence")
			}
			mutate(&changed)
			if err := VerifyEvidenceV3(plan, changed); err == nil {
				t.Fatal("unsafe private evidence admitted")
			}
		})
	}
}
