package phase6security

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	var scenarioValue struct {
		RunID        string   `json:"run_id"`
		Name         string   `json:"name"`
		Outcome      string   `json:"outcome"`
		Participants []string `json:"participants"`
		Assertions   []string `json:"assertions"`
	}
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
	scenarioValue.Assertions = []string{"unreviewed_assertion"}
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
	key := "process/" + evidence.Processes[0].DeploymentName + "/command"
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
	if _, err := recorder.Record(other, "process/"+evidence.Processes[1].DeploymentName+"/command", raw, observedAt); err == nil {
		t.Fatal("receipt from another run admitted")
	}
	if err := recorder.Finalize(&evidence); err == nil {
		t.Fatal("incomplete run finalized")
	}
	if _, err := os.Lstat(filepath.Join(root, "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("incomplete run wrote a manifest")
	}
}

func validSlice6ReceiptBundleFixture(t *testing.T) (Slice6Evidence, Slice6ReceiptIndex, string, string) {
	t.Helper()
	evidence := validSlice6EvidenceFixture(t)
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
		if kind == "scenario" {
			var participants []string
			for _, scenario := range evidence.Scenarios {
				if scenario.Name == subject {
					participants = scenario.Participants
					break
				}
			}
			value := struct {
				RunID        string   `json:"run_id"`
				Name         string   `json:"name"`
				Outcome      string   `json:"outcome"`
				Participants []string `json:"participants"`
				Assertions   []string `json:"assertions"`
			}{RunID: evidence.RunID, Name: subject, Outcome: "passed", Participants: participants,
				Assertions: append([]string(nil), slice6RequiredAssertions[subject]...)}
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

func setSlice6RunReceiptTestDigest(t *testing.T, e *Slice6Evidence, key, digest string) {
	t.Helper()
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		t.Fatalf("invalid fixture key %s", key)
	}
	switch parts[0] {
	case "container":
		for index := range e.Observations.Containers {
			value := &e.Observations.Containers[index]
			if value.DeploymentName == parts[1] {
				switch parts[2] {
				case "inspect":
					value.ContainerInspectDigest = digest
					for item := range e.Processes {
						if e.Processes[item].DeploymentName == parts[1] {
							e.Processes[item].InspectDigest = digest
						}
					}
				case "image_inspect":
					value.ImageInspectDigest = digest
				case "descriptor":
					value.ImageDescriptorProofDigest = digest
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
		for index := range e.Processes {
			if e.Processes[index].DeploymentName == parts[1] && parts[2] == "command" {
				e.Processes[index].CommandDigest = digest
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
		for index := range e.External {
			value := &e.External[index]
			if value.Name != parts[1] {
				continue
			}
			switch parts[2] {
			case "descriptor":
				value.DescriptorProofDigest = digest
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
