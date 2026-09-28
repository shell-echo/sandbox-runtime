package phase6security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSlice6ReceiptBundleRejectsCrossRunAndTampering(t *testing.T) {
	evidence, index, root, manifest := validSlice6ReceiptBundleFixture(t)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		t.Fatalf("complete private receipt bundle rejected: %v", err)
	}
	first := index.Entries[0]
	rawPath := filepath.Join(root, first.RawPath)
	originalRaw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawPath, []byte("substituted raw observation"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("raw observation substitution admitted")
	}
	if err := os.WriteFile(rawPath, originalRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(root, first.EnvelopePath)
	originalEnvelope, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Slice6RunReceipt){
		"cross run":         func(value *Slice6RunReceipt) { value.RunID = strings.Repeat("d", 32) },
		"wrong subject":     func(value *Slice6RunReceipt) { value.Subject = "unrelated" },
		"wrong config":      func(value *Slice6RunReceipt) { value.ConfigDigest = testDigest("unrelated") },
		"wrong source tree": func(value *Slice6RunReceipt) { value.SourceTreeDigest = testDigest("unrelated-tree") },
		"wrong outcome":     func(value *Slice6RunReceipt) { value.Outcome = "observed" },
		"future receipt":    func(value *Slice6RunReceipt) { value.ObservedAt = "2999-01-01T00:00:00Z" },
		"wrong raw digest":  func(value *Slice6RunReceipt) { value.RawDigest = testDigest("unrelated") },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate Slice6RunReceipt
			if err := json.Unmarshal(originalEnvelope, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			writeSlice6ReceiptTestJSON(t, envelopePath, candidate)
			index.Entries[0].EnvelopeDigest = fileSlice6ReceiptTestDigest(t, envelopePath)
			writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
			if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
				t.Fatal("rewritten envelope and index admitted")
			}
			if err := os.WriteFile(envelopePath, originalEnvelope, 0o600); err != nil {
				t.Fatal(err)
			}
			index.Entries[0].EnvelopeDigest = digestSlice6Receipt(originalEnvelope)
			writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
		})
	}
	index.Entries[0].Key = "scenario/nonexistent/observation"
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("orphan receipt index entry admitted")
	}
	index.Entries[0].Key = first.Key
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if err := os.Remove(rawPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("missing raw observation admitted")
	}
	if err := os.WriteFile(rawPath, originalRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		t.Fatalf("restored bundle rejected: %v", err)
	}
	secondKey := index.Entries[1].Key
	index.Entries[1].Key = first.Key
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("duplicated logical receipt identity admitted")
	}
	index.Entries[1].Key = secondKey
	originalPath := index.Entries[0].RawPath
	index.Entries[0].RawPath = "../outside.json"
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("receipt path traversal admitted")
	}
	index.Entries[0].RawPath = originalPath
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if err := os.Chmod(rawPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("public raw receipt admitted")
	}
	if err := os.Chmod(rawPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		t.Fatalf("restored private bundle rejected: %v", err)
	}
	scenarioIndex := -1
	for position, entry := range index.Entries {
		if strings.HasPrefix(entry.Key, "scenario/") {
			scenarioIndex = position
			break
		}
	}
	if scenarioIndex < 0 {
		t.Fatal("scenario receipt absent")
	}
	scenario := index.Entries[scenarioIndex]
	scenarioPath := filepath.Join(root, scenario.RawPath)
	originalScenarioRaw, err := os.ReadFile(scenarioPath)
	if err != nil {
		t.Fatal(err)
	}
	var scenarioValue slice6ScenarioRawReceipt
	if document, err := os.ReadFile(scenarioPath); err != nil || json.Unmarshal(document, &scenarioValue) != nil {
		t.Fatal("scenario fixture unreadable")
	}
	scenarioValue.Participants = []string{"unrelated"}
	writeSlice6ReceiptTestJSON(t, scenarioPath, scenarioValue)
	newScenarioDigest := fileSlice6ReceiptTestDigest(t, scenarioPath)
	index.Entries[scenarioIndex].RawDigest = newScenarioDigest
	setSlice6RunReceiptTestDigest(t, &evidence, scenario.Key, newScenarioDigest)
	scenarioEnvelopePath := filepath.Join(root, scenario.EnvelopePath)
	originalScenarioEnvelope, err := os.ReadFile(scenarioEnvelopePath)
	if err != nil {
		t.Fatal(err)
	}
	var scenarioEnvelope Slice6RunReceipt
	if document, err := os.ReadFile(scenarioEnvelopePath); err != nil || json.Unmarshal(document, &scenarioEnvelope) != nil {
		t.Fatal("scenario envelope fixture unreadable")
	}
	scenarioEnvelope.RawDigest = newScenarioDigest
	writeSlice6ReceiptTestJSON(t, scenarioEnvelopePath, scenarioEnvelope)
	index.Entries[scenarioIndex].EnvelopeDigest = fileSlice6ReceiptTestDigest(t, scenarioEnvelopePath)
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("scenario participant mismatch admitted after all digests were recomputed")
	}
	// The manifest's participant set is sorted; preserve that valid identity
	// while testing that the frozen assertion set cannot be silently changed.
	for _, item := range evidence.Scenarios {
		if item.Name == scenarioValue.Name {
			scenarioValue.Participants = append([]string(nil), item.Participants...)
			break
		}
	}
	scenarioValue.Measurements[0].Assertion = "unreviewed_assertion"
	writeSlice6ReceiptTestJSON(t, scenarioPath, scenarioValue)
	newScenarioDigest = fileSlice6ReceiptTestDigest(t, scenarioPath)
	index.Entries[scenarioIndex].RawDigest = newScenarioDigest
	setSlice6RunReceiptTestDigest(t, &evidence, scenario.Key, newScenarioDigest)
	scenarioEnvelope.RawDigest = newScenarioDigest
	writeSlice6ReceiptTestJSON(t, scenarioEnvelopePath, scenarioEnvelope)
	index.Entries[scenarioIndex].EnvelopeDigest = fileSlice6ReceiptTestDigest(t, scenarioEnvelopePath)
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("unreviewed scenario assertion admitted after all digests were recomputed")
	}
	if err := os.WriteFile(scenarioPath, originalScenarioRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scenarioEnvelopePath, originalScenarioEnvelope, 0o600); err != nil {
		t.Fatal(err)
	}
	index.Entries[scenarioIndex] = scenario
	setSlice6RunReceiptTestDigest(t, &evidence, scenario.Key, scenario.RawDigest)
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		t.Fatalf("restored scenario bundle rejected: %v", err)
	}
	cleanupIndex := -1
	for position, entry := range index.Entries {
		if strings.HasPrefix(entry.Key, "cleanup/") {
			cleanupIndex = position
			break
		}
	}
	if cleanupIndex < 0 {
		t.Fatal("cleanup receipt absent")
	}
	cleanup := index.Entries[cleanupIndex]
	cleanupPath := filepath.Join(root, cleanup.RawPath)
	var cleanupValue struct {
		RunID         string   `json:"run_id"`
		ResourceClass string   `json:"resource_class"`
		Remaining     int      `json:"remaining"`
		ResourceIDs   []string `json:"resource_ids"`
	}
	if document, err := os.ReadFile(cleanupPath); err != nil || json.Unmarshal(document, &cleanupValue) != nil {
		t.Fatal("cleanup fixture unreadable")
	}
	cleanupValue.RunID = strings.Repeat("e", 32)
	writeSlice6ReceiptTestJSON(t, cleanupPath, cleanupValue)
	newDigest := fileSlice6ReceiptTestDigest(t, cleanupPath)
	index.Entries[cleanupIndex].RawDigest = newDigest
	setSlice6RunReceiptTestDigest(t, &evidence, cleanup.Key, newDigest)
	cleanupEnvelopePath := filepath.Join(root, cleanup.EnvelopePath)
	var cleanupEnvelope Slice6RunReceipt
	if document, err := os.ReadFile(cleanupEnvelopePath); err != nil || json.Unmarshal(document, &cleanupEnvelope) != nil {
		t.Fatal("cleanup envelope fixture unreadable")
	}
	cleanupEnvelope.RawDigest = newDigest
	writeSlice6ReceiptTestJSON(t, cleanupEnvelopePath, cleanupEnvelope)
	index.Entries[cleanupIndex].EnvelopeDigest = fileSlice6ReceiptTestDigest(t, cleanupEnvelopePath)
	writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("cleanup belonging to another run admitted")
	}
}

func TestSlice6RunIDIsCanonicalFreshRandom(t *testing.T) {
	first, err := NewSlice6RunID()
	if err != nil || !slice6RunIDPattern.MatchString(first) {
		t.Fatalf("first run identity is unavailable: %q, %v", first, err)
	}
	second, err := NewSlice6RunID()
	if err != nil || !slice6RunIDPattern.MatchString(second) || first == second {
		t.Fatalf("fresh run identity is unavailable: %q, %v", second, err)
	}
}

func TestSlice6RecorderRefusesDuplicateCrossRunAndIncompleteFinalization(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	root := filepath.Join(t.TempDir(), "private-bundle")
	recorder, err := NewSlice6ReceiptRecorder(root, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSlice6ReceiptRecorder(root, evidence); err == nil {
		t.Fatal("existing private bundle root was overwritten")
	}
	key := slice6ProcessReceiptPrefix(evidence.Processes[0].DeploymentName, evidence.Processes[0].Sequence) + "/command"
	raw := []byte("unit-only process launch observation\n")
	digest := digestSlice6Receipt(raw)
	setSlice6RunReceiptTestDigest(t, &evidence, key, digest)
	observedAt, err := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Record(evidence, key, raw, observedAt); err != nil {
		t.Fatalf("first exact receipt rejected: %v", err)
	}
	if _, err := recorder.Record(evidence, key, raw, observedAt); err == nil {
		t.Fatal("duplicate logical receipt admitted")
	}
	other := evidence
	other.RunID = strings.Repeat("d", 32)
	if _, err := recorder.Record(other, slice6ProcessReceiptPrefix(evidence.Processes[1].DeploymentName, evidence.Processes[1].Sequence)+"/command", raw, observedAt); err == nil {
		t.Fatal("receipt from another run admitted")
	}
	if err := recorder.Finalize(&evidence); err == nil {
		t.Fatal("incomplete run finalized")
	}
	if _, err := os.Lstat(filepath.Join(root, "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("incomplete run wrote a manifest")
	}
}

func TestSlice6DescriptorReceiptDigestIsNotSemanticProof(t *testing.T) {
	evidence, _, root, manifest := validSlice6ReceiptBundleFixture(t)
	key := "container/" + evidence.Profile.Principals[0].Name + "/descriptor"
	proof := evidence.Observations.Containers[0].ImageDescriptorProofDigest
	content := evidence.DescriptorReceipts[0].ReceiptDigest
	if proof == content {
		t.Fatal("descriptor content digest was merged with semantic proof")
	}
	if _, err := ReadSlice6RunReceipts(root, evidence, []string{key, key}); err == nil {
		t.Fatal("duplicate raw-receipt request admitted")
	}
	if _, err := ReadSlice6RunReceipts(root, evidence, []string{"container/unknown/descriptor"}); err == nil {
		t.Fatal("unknown raw-receipt request admitted")
	}
	if raw, err := ReadSlice6RunReceipts(root, evidence, []string{key}); err != nil || digestSlice6Receipt(raw[key]) != content {
		t.Fatalf("indexed descriptor content unavailable: %v", err)
	}
	evidence.DescriptorReceipts[0].ReceiptDigest = proof
	evidence.ManifestDigest = slice6EvidenceDigest(evidence)
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		// On-disk manifest is intentionally unchanged; the in-memory mutation
		// must not rewrite the verified bundle. The next check is admission.
		t.Fatal(err)
	}
	if _, err := ReadSlice6RunReceipts(root, evidence, []string{key}); err == nil {
		t.Fatal("semantic proof substituted for raw-content digest")
	}
}

func TestSlice6RawReceiptReaderRechecksEnvelopeAfterBundleVerification(t *testing.T) {
	evidence, index, root, _ := validSlice6ReceiptBundleFixture(t)
	key := "container/" + evidence.Profile.Principals[0].Name + "/descriptor"
	for _, entry := range index.Entries {
		if entry.Key != key {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, entry.EnvelopePath), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSlice6RunReceipts(root, evidence, []string{key}); err == nil {
			t.Fatal("changed envelope admitted after initial bundle verification")
		}
		return
	}
	t.Fatal("descriptor envelope fixture missing")
}

func TestSlice6ScenarioRawReceiptRejectsUnmeasuredAndDriftedClaims(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	name := "browser_cdp_and_capacity_replay"
	baseline := validSlice6ScenarioRawFixture(t, evidence, name)
	encode := func(value any) []byte {
		t.Helper()
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	if !validSlice6ScenarioReceipt(encode(baseline), evidence, name) {
		t.Fatal("complete typed unit observation rejected")
	}
	old := struct {
		RunID        string   `json:"run_id"`
		Name         string   `json:"name"`
		Outcome      string   `json:"outcome"`
		Participants []string `json:"participants"`
		Assertions   []string `json:"assertions"`
	}{evidence.RunID, name, "passed", baseline.Participants, slice6RequiredAssertions[name]}
	if validSlice6ScenarioReceipt(encode(old), evidence, name) {
		t.Fatal("claim-only v1 raw receipt admitted")
	}
	for description, change := range map[string]func(*slice6ScenarioRawReceipt){
		"missing measurement": func(value *slice6ScenarioRawReceipt) {
			value.Measurements = value.Measurements[1:]
		},
		"wrong probe kind": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].ProbeKind = "unreviewed"
		},
		"wrong target": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Target = "provider-runtime"
		},
		"cross-run source instance": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].SourceInstance = strings.Repeat("d", 64)
		},
		"wrong source receipt digest": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].SourceReceiptDigest = testDigest("other")
		},
		"denial without healthy control": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].HealthyControl = nil
		},
		"control on wrong instance": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].HealthyControl.TargetInstance = strings.Repeat("d", 64)
		},
		"control after manifest": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].HealthyControl.ObservedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		},
		"unmeasured duration": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].DurationMillis = 0
		},
		"result instead of denial": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Result = "accepted"
		},
	} {
		t.Run(description, func(t *testing.T) {
			var candidate slice6ScenarioRawReceipt
			if err := json.Unmarshal(encode(baseline), &candidate); err != nil {
				t.Fatal(err)
			}
			change(&candidate)
			if validSlice6ScenarioReceipt(encode(candidate), evidence, name) {
				t.Fatal("drifted raw scenario measurement admitted")
			}
		})
	}
}

func TestSlice6RestartReceiptsRetainBothProcessInstances(t *testing.T) {
	evidence, index, root, manifest := validSlice6ReceiptBundleFixture(t)
	oldKey := "process/browser-executor-backend/1/inspect"
	newKey := "process/browser-executor-backend/2/inspect"
	var oldEntry, newEntry Slice6ReceiptIndexEntry
	oldIndex := -1
	for position, entry := range index.Entries {
		switch entry.Key {
		case oldKey:
			oldEntry, oldIndex = entry, position
		case newKey:
			newEntry = entry
		}
	}
	if oldIndex < 0 || newEntry.Key == "" || oldEntry.RawDigest == newEntry.RawDigest {
		t.Fatal("distinct historical and final process inspect receipts missing")
	}
	for _, sequence := range []int{1, 2} {
		prefix := slice6ProcessReceiptPrefix("browser-executor-backend", sequence)
		for _, suffix := range []string{"command", "inspect"} {
			if expectedSlice6RunReceipts(evidence)[prefix+"/"+suffix] == "" {
				t.Fatalf("historical process %d lacks %s receipt", sequence, suffix)
			}
		}
	}
	if _, err := ReadSlice6RunReceipts(root, evidence, []string{oldKey, newKey}); err != nil {
		t.Fatalf("historical process receipts cannot be independently reopened: %v", err)
	}
	oldRawPath := filepath.Join(root, oldEntry.RawPath)
	oldRaw, err := os.ReadFile(oldRawPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(oldRawPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
		t.Fatal("deleted old process inspect admitted by final-instance receipt")
	}
	if err := os.WriteFile(oldRawPath, oldRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var oldInspect []struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Running    bool   `json:"Running"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
		} `json:"State"`
	}
	if json.Unmarshal(oldRaw, &oldInspect) != nil || len(oldInspect) != 1 {
		t.Fatal("historical Docker inspect fixture invalid")
	}
	oldInspect[0].Config.Labels[slice6DockerRunLabel] = strings.Repeat("d", 32)
	otherRunRaw, err := json.Marshal(oldInspect)
	if err != nil {
		t.Fatal(err)
	}
	if validSlice6ProcessInspectRaw(otherRunRaw, evidence, oldKey) {
		t.Fatal("old-run Docker inspect admitted under current run")
	}
	oldInspect[0].Config.Labels[slice6DockerRunLabel] = evidence.RunID
	oldInspect[0].ID = strings.Repeat("d", 64)
	otherInstanceRaw, err := json.Marshal(oldInspect)
	if err != nil {
		t.Fatal(err)
	}
	if validSlice6ProcessInspectRaw(otherInstanceRaw, evidence, oldKey) {
		t.Fatal("wrong historical container inspect admitted")
	}
	oldEnvelopePath := filepath.Join(root, oldEntry.EnvelopePath)
	oldEnvelopeRaw, err := os.ReadFile(oldEnvelopePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope Slice6RunReceipt
	if err := json.Unmarshal(oldEnvelopeRaw, &envelope); err != nil {
		t.Fatal(err)
	}
	for label, mutate := range map[string]func(*Slice6RunReceipt){
		"wrong sequence": func(value *Slice6RunReceipt) { value.ProcessSequence = 2 },
		"wrong old instance": func(value *Slice6RunReceipt) {
			value.ProcessContainer = strings.Repeat("d", 64)
		},
		"wrong old config": func(value *Slice6RunReceipt) { value.ConfigDigest = testDigest("other-config") },
		"old run splice":   func(value *Slice6RunReceipt) { value.RunID = strings.Repeat("d", 32) },
	} {
		t.Run(label, func(t *testing.T) {
			candidate := envelope
			mutate(&candidate)
			writeSlice6ReceiptTestJSON(t, oldEnvelopePath, candidate)
			index.Entries[oldIndex].EnvelopeDigest = fileSlice6ReceiptTestDigest(t, oldEnvelopePath)
			writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
			if _, err := VerifySlice6EvidenceBundle(manifest, root); err == nil {
				t.Fatal("historical process envelope splice admitted with recalculated index and manifest")
			}
			if err := os.WriteFile(oldEnvelopePath, oldEnvelopeRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			index.Entries[oldIndex] = oldEntry
			writeSlice6ReceiptTestIndexAndManifest(t, root, manifest, &evidence, index)
		})
	}
	if _, err := VerifySlice6EvidenceBundle(manifest, root); err != nil {
		t.Fatalf("restored two-instance bundle rejected: %v", err)
	}
	if _, ok := slice6ProcessForReceipt(evidence, "process/browser-executor-backend/01/inspect"); ok {
		t.Fatal("noncanonical process sequence admitted")
	}
	if _, ok := slice6ProcessForReceipt(evidence, "process/browser-executor-backend/9/inspect"); ok {
		t.Fatal("out-of-range process sequence admitted")
	}
}

func TestSlice6RestartScenarioRejectsWrongHistoricalInstance(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	name := "provider_and_executor_restart"
	baseline := validSlice6ScenarioRawFixture(t, evidence, name)
	encode := func(value slice6ScenarioRawReceipt) []byte {
		t.Helper()
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	if !validSlice6ScenarioReceipt(encode(baseline), evidence, name) {
		t.Fatal("same-deployment restart pairs rejected")
	}
	for label, mutate := range map[string]func(*slice6ScenarioRawReceipt){
		"missing old instance": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts = value.Measurements[0].Restarts[1:]
		},
		"same instance": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts[0].Before = value.Measurements[0].Restarts[0].After
		},
		"wrong deployment": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts[0].Deployment = "provider-runtime"
		},
		"wrong old inspect": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts[0].Before.InspectDigest = testDigest("other-run-inspect")
		},
		"wrong old command key": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts[0].Before.CommandKey = "process/browser-executor-backend/2/command"
		},
		"wrong final instance": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[0].Restarts[0].After.ContainerID = strings.Repeat("d", 64)
		},
		"restart pair on unrelated assertion": func(value *slice6ScenarioRawReceipt) {
			value.Measurements[1].Restarts = nil
		},
	} {
		t.Run(label, func(t *testing.T) {
			var candidate slice6ScenarioRawReceipt
			if err := json.Unmarshal(encode(baseline), &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if validSlice6ScenarioReceipt(encode(candidate), evidence, name) {
				t.Fatal("wrong historical process relationship admitted")
			}
		})
	}
}

func validSlice6ReceiptBundleFixture(t *testing.T) (Slice6Evidence, Slice6ReceiptIndex, string, string) {
	return validSlice6ReceiptBundleFixtureWithOverrides(t, nil, nil)
}

func validSlice6ReceiptBundleFixtureWithOverrides(t *testing.T, customize func(*Slice6Evidence), overrides map[string][]byte) (Slice6Evidence, Slice6ReceiptIndex, string, string) {
	t.Helper()
	evidence := validSlice6EvidenceFixture(t)
	if customize != nil {
		customize(&evidence)
	}
	root := filepath.Join(t.TempDir(), "bundle")
	recorder, err := NewSlice6ReceiptRecorder(root, evidence)
	if err != nil {
		t.Fatalf("construct private receipt recorder: %v", err)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range sortedSlice6RunReceiptKeys(evidence) {
		kind, subject, _ := strings.Cut(key, "/")
		subject, _, _ = strings.Cut(subject, "/")
		raw := []byte("unit-only observation: " + key + "\n")
		if kind == "container" && strings.HasSuffix(key, "/inspect") {
			for _, process := range evidence.Processes {
				if process.DeploymentName == subject && process.Final {
					raw = syntheticSlice6ProcessInspect(t, evidence.RunID, process)
				}
			}
		}
		if kind == "process" && strings.HasSuffix(key, "/inspect") {
			process, ok := slice6ProcessForReceipt(evidence, key)
			if !ok {
				t.Fatal("invalid process fixture receipt key")
			}
			raw = syntheticSlice6ProcessInspect(t, evidence.RunID, process)
		}
		if replacement, ok := overrides[key]; ok {
			raw = replacement
		}
		if kind == "scenario" {
			value := validSlice6ScenarioRawFixture(t, evidence, subject)
			var err error
			raw, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		} else if kind == "cleanup" {
			value := struct {
				RunID         string   `json:"run_id"`
				ResourceClass string   `json:"resource_class"`
				Remaining     int      `json:"remaining"`
				ResourceIDs   []string `json:"resource_ids"`
			}{RunID: evidence.RunID, ResourceClass: subject, ResourceIDs: []string{}}
			var err error
			raw, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		rawDigest := digestSlice6Receipt(raw)
		setSlice6RunReceiptTestDigest(t, &evidence, key, rawDigest)
		if _, err := recorder.Record(evidence, key, raw, observedAt); err != nil {
			t.Fatalf("record %s: %v", key, err)
		}
	}
	manifest := filepath.Join(root, "manifest.json")
	if err := recorder.Finalize(&evidence); err != nil {
		t.Fatalf("finalize complete unit fixture bundle: %v", err)
	}
	indexDocument, err := os.ReadFile(filepath.Join(root, "receipt-index.json"))
	var index Slice6ReceiptIndex
	if err != nil || json.Unmarshal(indexDocument, &index) != nil {
		t.Fatal("read finalized receipt index")
	}
	return evidence, index, root, manifest
}

func syntheticSlice6ProcessInspect(t *testing.T, runID string, process Slice6ProcessEvidence) []byte {
	t.Helper()
	value := []struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Running    bool   `json:"Running"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
		} `json:"State"`
	}{{ID: process.ContainerID}}
	value[0].Config.Labels = map[string]string{slice6DockerRunLabel: runID}
	value[0].State.Running = process.Final
	value[0].State.StartedAt = process.StartedAt
	if process.Final {
		value[0].State.FinishedAt = "0001-01-01T00:00:00Z"
	} else {
		value[0].State.FinishedAt = process.FinishedAt
	}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func validSlice6ScenarioRawFixture(t *testing.T, evidence Slice6Evidence, name string) slice6ScenarioRawReceipt {
	t.Helper()
	if !validSlice6ScenarioSpecInventory() {
		t.Fatal("closed scenario probe inventory drifted")
	}
	var participants []string
	for _, scenario := range evidence.Scenarios {
		if scenario.Name == name {
			participants = scenario.Participants
		}
	}
	value := slice6ScenarioRawReceipt{Protocol: slice6ScenarioReceiptProtocol, Version: 2,
		RunID: evidence.RunID, Name: name, Participants: participants}
	observedAt, err := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, assertion := range slice6RequiredAssertions[name] {
		spec := slice6ProbeSpecs[assertion]
		sourceKey, sourceDigest, sourceInstance, sourceOK := slice6SubjectReceipt(evidence, spec.Source)
		targetKey, targetDigest, targetInstance, targetOK := slice6SubjectReceipt(evidence, spec.Target)
		if !sourceOK || !targetOK {
			t.Fatalf("fixture probe %s source/target not in run inventory", assertion)
		}
		start := observedAt.Add(-2 * time.Second)
		finish := observedAt.Add(-time.Second)
		probe := slice6ScenarioMeasurement{Assertion: assertion, ProbeKind: spec.Kind,
			Source: spec.Source, Target: spec.Target, SourceInstance: sourceInstance,
			TargetInstance: targetInstance, SourceReceiptKey: sourceKey, SourceReceiptDigest: sourceDigest,
			TargetReceiptKey: targetKey, TargetReceiptDigest: targetDigest,
			StartedAt: start.Format(time.RFC3339Nano), FinishedAt: finish.Format(time.RFC3339Nano),
			DurationMillis: finish.Sub(start).Milliseconds()}
		switch spec.Criterion {
		case "deny", "drain10s", "restart_denial":
			probe.Result = "denied"
			probe.HealthyControl = &slice6ScenarioControl{ObservedAt: start.Format(time.RFC3339Nano),
				Result: "accepted", ProbeKind: spec.Kind, SourceInstance: sourceInstance,
				TargetInstance: targetInstance, SourceReceipt: sourceKey, TargetReceipt: targetKey}
		case "allow", "bounded":
			probe.Result = "accepted"
		case "nonzero":
			probe.Result, probe.Count = "observed", 1
		case "zero":
			probe.Result = "observed"
		case "count82":
			probe.Result, probe.Count = "observed", int64(len(Slice6DesiredDeploymentNames()))
		case "distinct":
			probe.Result, probe.IdentityBefore, probe.IdentityAfter = "observed", testDigest("before"), testDigest("after")
		case "stable":
			probe.Result, probe.IdentityBefore, probe.IdentityAfter = "observed", testDigest("same"), testDigest("same")
		case "restart_instances":
			probe.Result, probe.Count = "observed", int64(len(slice6RestartSubjects))
		case "restart_authority":
			probe.Result, probe.Count = "observed", int64(len(slice6RestartSubjects))
			probe.IdentityBefore, probe.IdentityAfter = testDigest("retained-authority"), testDigest("retained-authority")
		case "uid_gid":
			probe.Result = "observed"
			for _, principal := range evidence.Profile.Principals {
				if principal.Name == spec.Source {
					probe.UID, probe.GID = principal.UID, principal.GID
				}
			}
		default:
			t.Fatalf("missing scenario criterion for %s", assertion)
		}
		if spec.Criterion == "restart_instances" || spec.Criterion == "restart_authority" || spec.Criterion == "restart_denial" {
			if spec.Criterion == "restart_denial" {
				probe.Count = int64(len(slice6RestartSubjects))
			}
			for _, deployment := range slice6RestartSubjects {
				var before, after Slice6ProcessEvidence
				for _, process := range evidence.Processes {
					if process.DeploymentName == deployment {
						if process.Sequence == 1 {
							before = process
						}
						if process.Final {
							after = process
						}
					}
				}
				if before.ContainerID == "" || after.Sequence < 2 {
					t.Fatalf("restart fixture missing two process instances for %s", deployment)
				}
				probe.Restarts = append(probe.Restarts, slice6RestartPair{Deployment: deployment,
					Before: slice6ProcessTestRef(before), After: slice6ProcessTestRef(after)})
			}
		}
		value.Measurements = append(value.Measurements, probe)
	}
	return value
}

func slice6ProcessTestRef(process Slice6ProcessEvidence) slice6ProcessReceiptRef {
	prefix := slice6ProcessReceiptPrefix(process.DeploymentName, process.Sequence)
	return slice6ProcessReceiptRef{Sequence: process.Sequence, ContainerID: process.ContainerID,
		CommandKey: prefix + "/command", CommandDigest: process.CommandDigest,
		InspectKey: prefix + "/inspect", InspectDigest: process.InspectDigest,
		ConfigDigest: process.ConfigDigest, StartedAt: process.StartedAt, FinishedAt: process.FinishedAt}
}

func setSlice6RunReceiptTestDigest(t *testing.T, e *Slice6Evidence, key, digest string) {
	t.Helper()
	parts := strings.Split(key, "/")
	if len(parts) != 3 && !(len(parts) == 4 && parts[0] == "process") {
		t.Fatalf("invalid fixture key %s", key)
	}
	switch parts[0] {
	case "container":
		if parts[2] == "descriptor" {
			setSlice6DescriptorReceiptTestDigest(t, e, parts[0], parts[1], digest)
			return
		}
		for index := range e.Observations.Containers {
			value := &e.Observations.Containers[index]
			if value.DeploymentName == parts[1] {
				switch parts[2] {
				case "inspect":
					value.ContainerInspectDigest = digest
					for item := range e.Processes {
						if e.Processes[item].DeploymentName == parts[1] &&
							e.Processes[item].ContainerID == value.ContainerID {
							e.Processes[item].InspectDigest = digest
						}
					}
				case "image_inspect":
					value.ImageInspectDigest = digest
				default:
					t.Fatalf("unknown container receipt %s", key)
				}
				return
			}
		}
	case "network":
		for index := range e.Observations.Networks {
			if e.Observations.Networks[index].Name == parts[1] && parts[2] == "inspect" {
				e.Observations.Networks[index].InspectDigest = digest
				return
			}
		}
	case "process":
		sequence, err := strconv.Atoi(parts[2])
		if err != nil || len(parts) != 4 {
			t.Fatalf("invalid fixture process key %s", key)
		}
		for index := range e.Processes {
			if e.Processes[index].DeploymentName == parts[1] && e.Processes[index].Sequence == sequence {
				switch parts[3] {
				case "command":
					e.Processes[index].CommandDigest = digest
				case "inspect":
					e.Processes[index].InspectDigest = digest
				default:
					t.Fatalf("unknown fixture process key %s", key)
				}
				return
			}
		}
	case "component":
		for index := range e.Components {
			if e.Components[index].Name == parts[1] {
				for item := range e.Observations.Components {
					if e.Observations.Components[item].Name == parts[1] {
						switch parts[2] {
						case "process":
							e.Components[index].ProcessInspectDigest = digest
							e.Observations.Components[item].ProcessInspectDigest = digest
						case "socket":
							e.Components[index].SocketInspectDigest = digest
							e.Observations.Components[item].SocketInspectDigest = digest
						case "session":
							e.Components[index].SessionAssociationDigest = digest
							e.Observations.Components[item].SessionAssociationDigest = digest
						default:
							t.Fatalf("unknown component receipt %s", key)
						}
						return
					}
				}
			}
		}
	case "external":
		if parts[2] == "descriptor" {
			setSlice6DescriptorReceiptTestDigest(t, e, parts[0], parts[1], digest)
			return
		}
		for index := range e.External {
			value := &e.External[index]
			if value.Name != parts[1] {
				continue
			}
			switch parts[2] {
			case "inspect":
				value.ContainerInspectDigest = digest
			case "image_inspect":
				value.ImageInspectDigest = digest
			case "tls":
				value.TLSProbeDigest = digest
			case "reachability":
				value.ReachabilityProbeDigest = digest
			case "postgres_mount":
				value.PostgresServerAuth.ReadOnlyMountInspectDigest = digest
			case "postgres_settings":
				value.PostgresServerAuth.ServerSettingsProbeDigest = digest
			case "postgres_rules":
				value.PostgresServerAuth.OrderedParsedRulesDigest = digest
			case "postgres_reload":
				value.PostgresServerAuth.StartupOrReloadResultDigest = digest
			case "postgres_connections":
				value.PostgresServerAuth.NewConnectionResultsDigest = digest
			case "postgres_restart":
				value.PostgresServerAuth.RestartReconcileResultDigest = digest
			default:
				t.Fatalf("unknown external receipt %s", key)
			}
			return
		}
	case "scenario":
		for index := range e.Scenarios {
			if e.Scenarios[index].Name == parts[1] && parts[2] == "observation" {
				e.Scenarios[index].EvidenceDigest = digest
				return
			}
		}
	case "cleanup":
		for index := range e.Cleanup {
			if e.Cleanup[index].Name == parts[1] && parts[2] == "inventory" {
				e.Cleanup[index].InspectorDigest = digest
				return
			}
		}
	}
	t.Fatalf("unknown manifest receipt reference %s", key)
}

func setSlice6DescriptorReceiptTestDigest(t *testing.T, e *Slice6Evidence, kind, subject, digest string) {
	t.Helper()
	for index := range e.DescriptorReceipts {
		value := &e.DescriptorReceipts[index]
		if value.Kind == kind && value.Subject == subject {
			value.ReceiptDigest = digest
			return
		}
	}
	t.Fatalf("unknown descriptor receipt %s/%s", kind, subject)
}

func writeSlice6ReceiptTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, document, 0o600) != nil {
		t.Fatal("write private receipt fixture")
	}
}

func fileSlice6ReceiptTestDigest(t *testing.T, path string) string {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digestSlice6Receipt(document)
}

func writeSlice6ReceiptTestIndexAndManifest(t *testing.T, root, manifest string, e *Slice6Evidence, index Slice6ReceiptIndex) {
	t.Helper()
	writeSlice6ReceiptTestJSON(t, filepath.Join(root, "receipt-index.json"), index)
	e.ReceiptIndexDigest = fileSlice6ReceiptTestDigest(t, filepath.Join(root, "receipt-index.json"))
	e.ManifestDigest = slice6EvidenceDigest(*e)
	writeSlice6ReceiptTestJSON(t, manifest, e)
}
