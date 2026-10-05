//go:build integration

package dockercontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

// This opt-in diagnostic only re-reads the exact retained Unknown effect.
// It never opens the mutable Docker API, changes a receipt, or retries a
// physical create. The trace contains stable stage/category/status only.
func TestCodingExistingUnknownReadOnlyDiagnosis(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_DIAGNOSE_UNKNOWN") != "1" {
		t.Skip("retained Unknown read-only diagnosis not enabled")
	}
	path := os.Getenv("SANDBOX_RUNTIME_CODING_DIAGNOSE_LEDGER")
	effect := os.Getenv("SANDBOX_RUNTIME_CODING_DIAGNOSE_EFFECT")
	host := os.Getenv("SANDBOX_RUNTIME_CODING_DIAGNOSE_UNIX_ENDPOINT")
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!controlDigest.MatchString(effect) || !strings.HasPrefix(host, "unix:///") {
		t.Fatal("exact retained ledger/effect/Unix endpoint required")
	}
	socket := strings.TrimPrefix(host, "unix://")
	if filepath.Clean(socket) != socket || len(socket) > 100 {
		t.Fatal("noncanonical test Unix endpoint")
	}
	socketInfo, err := os.Lstat(socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixed test Unix endpoint changed")
	}
	document, err := os.ReadFile(path)
	if err != nil || len(document) < 1 || len(document) > MaxReceiptStateBytes {
		t.Fatal("private receipt ledger unavailable")
	}
	var stored CodingReceiptState
	if json.Unmarshal(document, &stored) != nil || len(stored.Records) != 1 ||
		stored.Records[0].Status != ReceiptUnknown || stored.Records[0].Authority.EffectID != effect ||
		stored.EndpointScopeDigest != testControlDigest("7") || stored.RuntimePlatform != "linux/arm64/v8" {
		t.Fatal("retained Unknown ledger does not match exact approved effect")
	}
	receipt := stored.Records[0]
	runID := strings.TrimSuffix(strings.TrimPrefix(receipt.Authority.SlotID, "coding-"), "-a")
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(runID) ||
		receipt.Authority.SlotID != "coding-"+runID+"-a" {
		t.Fatal("noncanonical retained slot")
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "security", "originals",
		"moby-default-seccomp-836ae4d3.json"))
	policySum := sha256.Sum256(policy)
	if err != nil || "sha256:"+hex.EncodeToString(policySum[:]) !=
		"sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("pinned seccomp source unavailable")
	}
	slots := []codingidentity.Slot{
		{ID: "coding-" + runID + "-a", WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: "coding-" + runID + "-a-inputs", WorkspaceVolume: "coding-" + runID + "-a-workspace",
			OutputsVolume: "coding-" + runID + "-a-outputs"},
		{ID: "coding-" + runID + "-b", WorkloadUID: 57001, WorkloadGID: 58001,
			InputsVolume: "coding-" + runID + "-b-inputs", WorkspaceVolume: "coding-" + runID + "-b-workspace",
			OutputsVolume: "coding-" + runID + "-b-outputs"},
	}
	limits := codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}
	template, err := phase6security.NewCodingRuntimeTemplateV2("linux/arm64/v8",
		codingimage.PublishedARM64ConfigDigest, codingimage.PublishedDescriptorSize,
		testControlDigest("f"), "sha256:"+hex.EncodeToString(policySum[:]), slots, limits)
	if err != nil {
		t.Fatal(err)
	}
	templateDigest, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testControlDigest("d"), OwnerDeployment: template.OwnerDeployment,
		OwnerPrincipalDigest: template.OwnerPrincipalDigest, Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: templateDigest, ImageDigest: template.Image.Descriptor.Digest,
		ImageConfigDigest: template.Image.ConfigDigest, NetworkMode: "none", Limits: limits,
		Capacity: codingidentity.LocalCandidateCapacity, Slots: slots}
	planDigest, err := plan.Digest()
	if err != nil || planDigest != stored.PlanDigest || template.BindPlan(plan) != nil {
		t.Fatal("recovered template/plan differs from durable Unknown")
	}
	binding := CodingReceiptBinding{Plan: plan,
		SpecBySlot:    map[string]string{slots[0].ID: receipt.Authority.SpecDigest, slots[1].ID: testControlDigest("d")},
		ProfileDigest: stored.ProfileDigest, PlanDigest: stored.PlanDigest,
		DaemonDigest: stored.DaemonDigest, DaemonEnvironmentDigest: stored.DaemonEnvironmentDigest,
		EndpointScopeDigest: stored.EndpointScopeDigest, RuntimePlatform: stored.RuntimePlatform,
		ControlPolicyDigest: stored.ControlPolicyDigest, PeerPrincipalDigest: stored.PeerPrincipalDigest,
		Capacity: stored.Capacity}
	validated, err := readReceiptState(path, binding)
	if err != nil || validated.Revision != stored.Revision || len(validated.Records) != 1 {
		t.Fatal("retained Unknown failed full ledger validation")
	}
	set, err := NewCodingResourceSet(binding, receipt.Authority)
	if err != nil {
		t.Fatal(err)
	}
	documents := testCodingRawDocuments(t)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		current, err := os.Lstat(socket)
		if err != nil || !os.SameFile(socketInfo, current) || current.Mode()&os.ModeSocket == 0 {
			return nil, ErrInvalidCodingObservationTransport
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	base := newCodingObservationHTTPTransport(dial)
	defer base.CloseIdleConnections()
	var trace []codingDiagnosticTraceItem
	counting := codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		entry := codingDiagnosticTraceItem{Seq: len(trace) + 1,
			Category: codingDiagnosticRequestCategory(request)}
		response, err := base.RoundTrip(request)
		if response != nil {
			entry.Status = response.StatusCode
		}
		entry.Error = err != nil
		trace = append(trace, entry)
		return response, err
	})
	bounded := &codingObservationTransport{base: counting, set: set,
		endpointHost: socket, requestHost: client.DummyHost,
		imageRef: template.Image.Reference, platform: template.Image.Platform,
		archiveUID: int(slots[0].WorkloadUID), archiveGID: int(slots[0].WorkloadGID),
		archiveMode: int64(template.VolumePrepMode)}
	api, err := client.New(client.WithHost(host), client.WithHTTPClient(&http.Client{
		Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport },
	}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	observer := &codingUnixObserver{gate: gate, api: api, bounded: bounded,
		binding: binding, authority: receipt.Authority, template: template,
		documents: documents, policy: policy}
	proof, observeErr := observer.observeCompleted(t.Context(), receipt, stored.Revision)
	traceDocument, _ := json.Marshal(trace)
	t.Logf("retained effect read-only observation: stage=%s GET=%d trace=%s", observer.stage, len(trace), traceDocument)
	if observeErr != nil {
		t.Fatalf("retained effect failed at stable stage %s: %v", observer.stage, observeErr)
	}
	if proof.recheck(binding, receipt.Authority, template, documents, policy) != nil {
		t.Fatal("retained physical proof did not recheck")
	}
	current, err := readReceiptState(path, binding)
	if err != nil || current.Revision != stored.Revision {
		t.Fatal("durable Unknown changed after source observation")
	}
	record := newCodingPrivateProofRecord(proof, trace, time.Now())
	privateDir := filepath.Dir(path)
	proofPath := filepath.Join(privateDir, "private-completion-observation-retained.json")
	decoded, err := writeAndReadCodingPrivateProof(proofPath, record)
	if err != nil || decoded.recheck(binding, receipt.Authority, template, documents, policy, current) != nil {
		t.Fatalf("current physical proof did not persist/reload/recheck; resources retained: %v", err)
	}
	if os.Getenv("SANDBOX_RUNTIME_CODING_CLEANUP_RETAINED") != "1" {
		t.Logf("retained effect proof digest=%s persisted privately; no mutation or receipt transition",
			proof.CompletionDigest)
		return
	}
	if os.Getenv("SANDBOX_RUNTIME_CODING_CLEANUP_EFFECT") != effect ||
		os.Getenv("SANDBOX_RUNTIME_CODING_CLEANUP_RUNTIME_ID") !=
			"59453b2d12080d2a75f30a77103e2ede50a3535e7bf862ee29698ca182f8d256" ||
		proof.RuntimeID != os.Getenv("SANDBOX_RUNTIME_CODING_CLEANUP_RUNTIME_ID") ||
		os.Getenv("SANDBOX_RUNTIME_CODING_PRIOR_PROOF_DIGEST") != decoded.PreviousReadOnlyProof {
		t.Fatal("cleanup does not match the exact retained effect/runtime/prior observation")
	}
	current, err = readReceiptState(path, binding)
	if err != nil || decoded.recheck(binding, receipt.Authority, template, documents, policy, current) != nil {
		t.Fatal("durable Unknown/revision changed before cleanup intent")
	}
	volumeNames := [3]string{}
	for index, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		volumeNames[index], _ = set.VolumeName(role)
	}
	intent := struct {
		Schema            string    `json:"schema"`
		EffectID          string    `json:"effect_id"`
		RuntimeID         string    `json:"runtime_id"`
		VolumeNames       [3]string `json:"volume_names"`
		ReceiptRevision   uint64    `json:"receipt_revision"`
		CurrentProof      string    `json:"current_proof"`
		DaemonIdentity    string    `json:"daemon_identity"`
		DaemonEnvironment string    `json:"daemon_environment"`
		At                time.Time `json:"at"`
	}{"sandbox-runtime.test-only-coding-cleanup-intent.v1", effect,
		proof.RuntimeID, volumeNames, current.Revision, proof.CompletionDigest,
		proof.Daemon.IdentityDigest, proof.Daemon.EnvironmentDigest, time.Now().UTC()}
	if _, err := writeAndReadCodingPrivateJSON(filepath.Join(privateDir, "private-cleanup-intent.json"), intent); err != nil {
		t.Fatalf("cleanup intent could not persist before deletion: %v", err)
	}
	mutatingTransport := newCodingObservationHTTPTransport(dial)
	defer mutatingTransport.CloseIdleConnections()
	mutator, err := client.New(client.WithHost(host), client.WithHTTPClient(&http.Client{
		Transport: mutatingTransport, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport },
	}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer mutator.Close()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	absent, err := cleanupCodingObservedEffect(cleanupCtx, mutator, observer, set,
		decoded.Proof, template, documents, policy)
	if err != nil {
		t.Fatalf("exact retained-effect cleanup stopped without retry; Unknown preserved: %v", err)
	}
	stillUnknown, err := readReceiptState(path, binding)
	if err != nil || stillUnknown.Revision != current.Revision ||
		len(stillUnknown.Records) != 1 || stillUnknown.Records[0].Status != ReceiptUnknown {
		t.Fatal("durable Unknown changed unexpectedly after test-only exact cleanup")
	}
	result := struct {
		Schema          string                     `json:"schema"`
		EffectID        string                     `json:"effect_id"`
		RuntimeID       string                     `json:"runtime_id"`
		VolumeNames     [3]string                  `json:"volume_names"`
		ProofDigest     string                     `json:"proof_digest"`
		ReceiptRevision uint64                     `json:"receipt_revision"`
		ReceiptStatus   ReceiptStatus              `json:"receipt_status"`
		Absent          [2]CodingResourceInventory `json:"absent"`
		At              time.Time                  `json:"at"`
	}{"sandbox-runtime.test-only-coding-cleanup-result.v1", effect, proof.RuntimeID,
		volumeNames, proof.CompletionDigest, stillUnknown.Revision,
		stillUnknown.Records[0].Status, absent, time.Now().UTC()}
	if _, err := writeAndReadCodingPrivateJSON(filepath.Join(privateDir, "private-cleanup-result.json"), result); err != nil {
		t.Fatalf("physical cleanup succeeded but private result persistence failed: %v", err)
	}
	t.Logf("same-effect snapshot proof=%s persisted; exact one runtime/three volume cleanup and two 2+3 zero inventories passed; durable receipt remains Unknown",
		proof.CompletionDigest)
}

func codingDiagnosticRequestCategory(request *http.Request) string {
	if request == nil || request.URL == nil {
		return "invalid"
	}
	path := request.URL.Path
	switch {
	case path == "/v1.55/info":
		return "info"
	case path == "/v1.55/containers/json":
		return "container-list"
	case path == "/v1.55/volumes":
		return "volume-list"
	case strings.HasPrefix(path, "/v1.55/images/"):
		if request.URL.RawQuery == "" {
			return "image-index"
		}
		return "image-selected"
	case strings.HasSuffix(path, "/archive"):
		switch request.URL.Query().Get("path") {
		case "/inputs":
			return "archive-inputs"
		case "/workspace":
			return "archive-workspace"
		case "/outputs":
			return "archive-outputs"
		}
		return "archive-other"
	case strings.HasPrefix(path, "/v1.55/containers/"):
		return "container-inspect"
	case strings.HasPrefix(path, "/v1.55/volumes/"):
		return "volume-inspect"
	default:
		return "unreviewed"
	}
}
