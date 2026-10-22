package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func slice6ValidationJSON(t testing.TB, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func slice6ValidationEvidence(t testing.TB, document []byte) Slice6Evidence {
	t.Helper()
	var evidence Slice6Evidence
	if err := json.Unmarshal(document, &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func slice6ValidationExternalIDs(evidence Slice6Evidence) map[string]string {
	ids := make(map[string]string, len(evidence.External))
	for _, service := range evidence.External {
		ids[service.Name] = service.ContainerID
	}
	return ids
}

func TestSlice6EvidenceValidationPreservesInput(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	document := slice6ValidationJSON(t, evidence)
	profile := slice6ValidationJSON(t, evidence.Profile)
	ids := slice6ValidationExternalIDs(evidence)
	external := slice6ValidationJSON(t, ids)
	for _, check := range []struct {
		name string
		run  func() error
	}{
		{"final_gate", func() error { return VerifySlice6FinalGateProfile(evidence.Profile) }},
		{"public_observations", func() error {
			return ValidateObservationsWithExternal(evidence.Profile, evidence.Observations, ids)
		}},
		{"evidence", evidence.Validate},
		{"document", func() error {
			got, err := VerifySlice6Evidence(document)
			if err == nil {
				encoded, marshalErr := json.Marshal(got)
				if marshalErr != nil {
					return marshalErr
				}
				if !bytes.Equal(encoded, document) {
					return errors.New("document validation changed the returned evidence")
				}
			}
			return err
		}},
	} {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(slice6ValidationJSON(t, evidence), document) ||
				!bytes.Equal(slice6ValidationJSON(t, evidence.Profile), profile) ||
				!bytes.Equal(slice6ValidationJSON(t, ids), external) {
				t.Fatal("validation modified an input or its aliased profile fields")
			}
		})
	}
}

func TestSlice6EvidenceObservationPublicEntriesRevalidateEveryCall(t *testing.T) {
	original := slice6ValidationJSON(t, validSlice6EvidenceFixture(t))
	check := func(t *testing.T, evidence Slice6Evidence, valid bool) {
		t.Helper()
		ids := slice6ValidationExternalIDs(evidence)
		observationDocument := slice6ValidationJSON(t, evidence.Observations)
		observationErr := ValidateObservationsWithExternal(evidence.Profile, evidence.Observations, ids)
		decoded, decodeErr := DecodeObservationsWithExternal(observationDocument, evidence.Profile, ids)
		evidenceErr := evidence.Validate()
		verified, verifyErr := VerifySlice6Evidence(slice6ValidationJSON(t, evidence))
		if valid {
			if observationErr != nil || decodeErr != nil || evidenceErr != nil || verifyErr != nil {
				t.Fatalf("valid input rejected: %v / %v / %v / %v", observationErr, decodeErr, evidenceErr, verifyErr)
			}
			return
		}
		if !errors.Is(observationErr, ErrInvalidObservation) || !errors.Is(decodeErr, ErrInvalidObservation) ||
			!errors.Is(evidenceErr, ErrInvalidSlice6Evidence) || !errors.Is(verifyErr, ErrInvalidSlice6Evidence) ||
			!reflect.DeepEqual(decoded, ObservationSet{}) || !reflect.DeepEqual(verified, Slice6Evidence{}) {
			t.Fatalf("unsafe reentry escaped a public boundary: %v / %v / %v / %v", observationErr, decodeErr, evidenceErr, verifyErr)
		}
	}
	check(t, slice6ValidationEvidence(t, original), true)
	for _, test := range []struct {
		name   string
		mutate func(*Profile)
	}{
		{"privilege", func(p *Profile) { p.Principals[0].NoNewPrivileges = false }},
		{"revision", func(p *Profile) { p.Revision = "slice6-!" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := slice6ValidationEvidence(t, original)
			test.mutate(&candidate.Profile)
			candidate.Profile.ProfileDigest = candidate.Profile.Digest()
			candidate.Observations.ProfileDigest = candidate.Profile.ProfileDigest
			candidate.ManifestDigest = slice6EvidenceDigest(candidate)
			if candidate.Profile.Validate() == nil || !candidate.Observations.Containers[0].NoNewPrivileges ||
				candidate.Profile.ProfileDigest != candidate.Profile.Digest() ||
				candidate.Observations.ProfileDigest != candidate.Profile.ProfileDigest ||
				candidate.ManifestDigest != slice6EvidenceDigest(candidate) {
				t.Fatal("unsafe fixture must retain independently invalid profile and aligned digest bindings")
			}
			check(t, candidate, false)
			check(t, slice6ValidationEvidence(t, original), true)
		})
	}
}

func TestSlice6EvidenceObservationChecksSurviveValidatedProfile(t *testing.T) {
	original := slice6ValidationJSON(t, validSlice6EvidenceFixture(t))
	for _, test := range []struct {
		name   string
		mutate func(*Slice6Evidence)
	}{
		{"namespace_isolation", func(e *Slice6Evidence) { e.Observations.ContainerNamespaceIsolationEstablished = false }},
		{"profile_binding", func(e *Slice6Evidence) { e.Observations.ProfileDigest = testDigest("stale") }},
		{"measured_uid", func(e *Slice6Evidence) { e.Observations.Containers[0].ProcessUID++ }},
		{"component_pid", func(e *Slice6Evidence) { e.Observations.Components[0].PID = 0 }},
		{"network_member", func(e *Slice6Evidence) { e.Observations.Networks[0].ContainerIDs[0] = testDigest("wrong-member")[7:] }},
		{"network_endpoint", func(e *Slice6Evidence) { e.Observations.Networks[0].Endpoints[0].IPv4Address = "not-an-ip" }},
		{"duplicate_external_id", func(e *Slice6Evidence) { e.External[1].ContainerID = e.External[0].ContainerID }},
		{"unknown_external_service", func(e *Slice6Evidence) { e.External[0].Name = "unreviewed-service" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := slice6ValidationEvidence(t, original)
			test.mutate(&candidate)
			candidate.ManifestDigest = slice6EvidenceDigest(candidate)
			if err := VerifySlice6FinalGateProfile(candidate.Profile); err != nil {
				t.Fatalf("observation refusal fixture lost its valid final profile: %v", err)
			}
			if err := ValidateObservationsWithExternal(candidate.Profile, candidate.Observations, slice6ValidationExternalIDs(candidate)); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("invalid observation accepted by public boundary: %v", err)
			}
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidSlice6Evidence) {
				t.Fatalf("invalid observation accepted by evidence validation: %v", err)
			}
			got, err := VerifySlice6Evidence(slice6ValidationJSON(t, candidate))
			if !errors.Is(err, ErrInvalidSlice6Evidence) || !reflect.DeepEqual(got, Slice6Evidence{}) {
				t.Fatalf("invalid observation accepted by document validation: %v", err)
			}
		})
	}
}
