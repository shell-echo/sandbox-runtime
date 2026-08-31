// Package platform contains a small Agent Platform candidate caller.
//
// It deliberately depends only on the black-box caller package and standard
// library. The package models platform policy for candidate evidence; it does
// not become the Provider's source of WorkOrder, Run, or authorization truth.
package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
)

const (
	contractNamespace = "urn:shell-echo:sandbox-runtime:provider-v1"
	contractVersion   = "1.0.0"
	capabilityIDExec  = "sandbox.exec"
	capabilityIDTTY   = "sandbox.terminal"
	capabilityProfile = "sandbox-runtime-coding-shell-v1"
	runtimeProfile    = "sandbox-runtime-coding-shell-v1"
	stateVersion      = 1
	maxResponseBytes  = 2 << 20
	maxStateBytes     = 64 << 10
	platformRunID     = "platform-candidate-coding-shell-run"
	platformPolicyID  = "platform-candidate-policy-v1"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	errCompletedRun   = errors.New("completed candidate run cannot reopen")
)

// Revision is the candidate's immutable ProviderRevision identity.
type Revision struct {
	ID                   string `json:"id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	RuntimeProfileID     string `json:"runtime_profile_id"`
	ContractNamespace    string `json:"contract_namespace"`
	ContractVersion      string `json:"contract_version"`
	ImageDigest          string `json:"image_digest"`
	SecurityPolicyDigest string `json:"security_policy_digest"`
}

func (r Revision) Validate() error {
	if !identifierPattern.MatchString(r.ID) || !identifierPattern.MatchString(r.CapabilityProfileID) ||
		!identifierPattern.MatchString(r.RuntimeProfileID) || r.ContractNamespace != contractNamespace ||
		r.ContractVersion != contractVersion || !digestPattern.MatchString(r.ImageDigest) ||
		!digestPattern.MatchString(r.SecurityPolicyDigest) {
		return errors.New("invalid platform ProviderRevision")
	}
	return nil
}

type runState string

const (
	runActive    runState = "active"
	runDraining  runState = "draining"
	runCompleted runState = "completed"
)

type binding struct {
	RunID            string    `json:"run_id"`
	ProviderRevision Revision  `json:"provider_revision"`
	State            runState  `json:"state"`
	BoundAt          time.Time `json:"bound_at"`
	StateChangedAt   time.Time `json:"state_changed_at"`
}

// router is a candidate-local run binding ledger. It intentionally has no
// Provider or platform database dependency; the candidate harness owns this
// bounded test state only.
type router struct {
	mu            sync.RWMutex
	clock         func() time.Time
	stable        Revision
	canary        *Revision
	canaryPercent uint8
	bindings      map[string]binding
}

func newRouter(stable Revision, canary *Revision, canaryPercent uint8, now func() time.Time) (*router, error) {
	if err := stable.Validate(); err != nil || now == nil || canaryPercent > 100 {
		return nil, errors.New("invalid candidate routing policy")
	}
	if canary != nil {
		if err := canary.Validate(); err != nil || canary.ID == stable.ID ||
			canary.CapabilityProfileID != stable.CapabilityProfileID || canary.RuntimeProfileID != stable.RuntimeProfileID ||
			canary.ContractNamespace != stable.ContractNamespace || canary.ContractVersion != stable.ContractVersion {
			return nil, errors.New("invalid candidate canary policy")
		}
	} else if canaryPercent != 0 {
		return nil, errors.New("canary percentage requires a canary revision")
	}
	return &router{clock: now, stable: stable, canary: canary, canaryPercent: canaryPercent, bindings: make(map[string]binding)}, nil
}

func (r *router) bind(runID string) (binding, error) {
	if r == nil || !identifierPattern.MatchString(runID) {
		return binding{}, errors.New("invalid candidate run identity")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.bindings[runID]; ok {
		return previous, nil
	}
	revision := r.stable
	if r.canary != nil && canaryBucket(runID) < r.canaryPercent {
		revision = *r.canary
	}
	now := r.clock().UTC()
	result := binding{RunID: runID, ProviderRevision: revision, State: runActive, BoundAt: now, StateChangedAt: now}
	r.bindings[runID] = result
	return result, nil
}

func (r *router) rollback(stable Revision) error {
	if r == nil {
		return errors.New("invalid candidate rollback")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if stable.Validate() != nil || stable.CapabilityProfileID != r.stable.CapabilityProfileID ||
		stable.RuntimeProfileID != r.stable.RuntimeProfileID || stable.ContractNamespace != r.stable.ContractNamespace ||
		stable.ContractVersion != r.stable.ContractVersion {
		return errors.New("invalid candidate rollback")
	}
	r.stable, r.canary, r.canaryPercent = stable, nil, 0
	return nil
}

func (r *router) setState(runID string, state runState) error {
	if r == nil || !identifierPattern.MatchString(runID) || (state != runActive && state != runDraining && state != runCompleted) {
		return errors.New("invalid candidate run state")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.bindings[runID]
	if !ok {
		return errors.New("candidate run binding not found")
	}
	if current.State == runCompleted && state != runCompleted {
		return errCompletedRun
	}
	current.State, current.StateChangedAt = state, r.clock().UTC()
	r.bindings[runID] = current
	return nil
}

func (r *router) get(runID string) (binding, error) {
	if r == nil || !identifierPattern.MatchString(runID) {
		return binding{}, errors.New("invalid candidate run identity")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result, ok := r.bindings[runID]
	if !ok {
		return binding{}, errors.New("candidate run binding not found")
	}
	return result, nil
}

func canaryBucket(runID string) uint8 {
	sum := sha256.Sum256([]byte(runID))
	return sum[0] % 100
}

// Metrics is a bounded candidate observation summary. It is not a platform
// accounting ledger and must not be interpreted as production telemetry.
type Metrics struct {
	LifecycleSamples      uint64 `json:"lifecycle_samples"`
	ExecAttempts          uint64 `json:"exec_attempts"`
	ExecSuccesses         uint64 `json:"exec_successes"`
	SessionObservations   uint64 `json:"session_observations"`
	StableSessions        uint64 `json:"stable_sessions"`
	ResourceObservations  uint64 `json:"resource_observations"`
	ResourceEvidence      uint64 `json:"resource_evidence"`
	ReconciliationSamples uint64 `json:"reconciliation_samples"`
	ReconciliationBacklog uint64 `json:"reconciliation_backlog"`
}

// Evidence is embedded in the caller report and contains candidate-only
// policy and observation facts. It deliberately contains no paths, tokens, or
// backend identifiers.
type Evidence struct {
	Kind                    string  `json:"kind"`
	RunID                   string  `json:"run_id"`
	ProviderRevisionID      string  `json:"provider_revision_id"`
	CapabilityProfileID     string  `json:"capability_profile_id"`
	RuntimeProfileID        string  `json:"runtime_profile_id"`
	ContractNamespace       string  `json:"contract_namespace"`
	ContractVersion         string  `json:"contract_version"`
	ShadowCapabilities      bool    `json:"shadow_capabilities"`
	ShadowRequest           bool    `json:"shadow_request"`
	SelectedRevisionID      string  `json:"selected_revision_id"`
	CanaryProbeRevisionID   string  `json:"canary_probe_revision_id"`
	CanaryRollbackPreserved bool    `json:"canary_rollback_preserved"`
	OldRunState             string  `json:"old_run_state"`
	RunState                string  `json:"run_state"`
	Metrics                 Metrics `json:"metrics"`
	EvidenceBoundary        string  `json:"evidence_boundary"`
}

type Report struct {
	Phase       string                  `json:"phase"`
	Scenarios   []caller.ScenarioResult `json:"scenarios"`
	CompletedAt string                  `json:"completed_at"`
	Platform    Evidence                `json:"platform"`
}

type persistedState struct {
	SchemaVersion           int       `json:"schema_version"`
	RunID                   string    `json:"run_id"`
	ProviderRevisionID      string    `json:"provider_revision_id"`
	SelectedRevisionID      string    `json:"selected_revision_id"`
	BindingState            string    `json:"binding_state"`
	CanaryProbeRevisionID   string    `json:"canary_probe_revision_id"`
	CanaryRollbackPreserved bool      `json:"canary_rollback_preserved"`
	OldRunState             string    `json:"old_run_state"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// Run performs candidate policy checks and then invokes the already-tested
// network caller. The state file is intentionally colocated with the ephemeral
// PKI directory created by the E2E orchestrator and is removed with that root.
func Run(ctx context.Context, config caller.Config) (Report, error) {
	if ctx == nil {
		return Report{}, context.Canceled
	}
	if err := config.Validate(); err != nil {
		return Report{}, err
	}
	stable := revisionFromConfig(config)
	if err := stable.Validate(); err != nil {
		return Report{}, err
	}
	capabilities, err := shadowCapabilities(ctx, config, stable)
	if err != nil {
		return Report{}, fmt.Errorf("capability shadow: %w", err)
	}
	request, err := buildCreateRequest(config, stable)
	if err != nil {
		return Report{}, fmt.Errorf("build shadow request: %w", err)
	}
	if err := shadowRequest(request, capabilities, stable); err != nil {
		return Report{}, fmt.Errorf("request shadow: %w", err)
	}

	now := time.Now
	canary := stable
	canary.ID = stable.ID + "-candidate"
	canary.SecurityPolicyDigest = sha256Digest([]byte(platformPolicyID + ":canary"))
	policyRouter, err := newRouter(stable, &canary, 100, now)
	if err != nil {
		return Report{}, err
	}
	old, err := policyRouter.bind("platform-old-run")
	if err != nil || old.ProviderRevision.ID != canary.ID {
		return Report{}, errors.New("candidate canary did not bind the old run")
	}
	if err := policyRouter.setState(old.RunID, runDraining); err != nil {
		return Report{}, err
	}
	if err := policyRouter.rollback(stable); err != nil {
		return Report{}, err
	}
	preserved, err := policyRouter.get(old.RunID)
	if err != nil {
		return Report{}, err
	}
	newRun, err := policyRouter.bind("platform-new-run")
	if err != nil || newRun.ProviderRevision.ID != stable.ID {
		return Report{}, errors.New("candidate rollback changed new-run selection")
	}
	if err := policyRouter.setState(old.RunID, runCompleted); err != nil {
		return Report{}, err
	}

	statePath := filepath.Join(filepath.Dir(config.CAFile), "platform-candidate-state.json")
	if config.Phase == caller.PhaseResume {
		state, err := readState(statePath)
		if err != nil {
			return Report{}, fmt.Errorf("read candidate resume state: %w", err)
		}
		if state.RunID != platformRunID || state.ProviderRevisionID != stable.ID || state.SelectedRevisionID != stable.ID || state.BindingState != string(runCompleted) {
			return Report{}, errors.New("candidate resume state identity drift")
		}
	}
	if err := writeState(statePath, persistedState{
		SchemaVersion: stateVersion, RunID: platformRunID, ProviderRevisionID: stable.ID,
		SelectedRevisionID: stable.ID, BindingState: string(runActive), CanaryProbeRevisionID: preserved.ProviderRevision.ID,
		CanaryRollbackPreserved: preserved.ProviderRevision.ID == canary.ID, OldRunState: string(runCompleted), UpdatedAt: now().UTC(),
	}); err != nil {
		return Report{}, fmt.Errorf("persist candidate run binding: %w", err)
	}

	callerReport, err := caller.Run(ctx, config)
	if err != nil {
		return Report{}, err
	}
	for _, scenario := range callerReport.Scenarios {
		if scenario.Status != "passed" {
			return Report{}, fmt.Errorf("candidate caller scenario %q has status %q", scenario.Name, scenario.Status)
		}
	}
	if err := writeState(statePath, persistedState{
		SchemaVersion: stateVersion, RunID: platformRunID, ProviderRevisionID: stable.ID,
		SelectedRevisionID: stable.ID, BindingState: string(runCompleted), CanaryProbeRevisionID: preserved.ProviderRevision.ID,
		CanaryRollbackPreserved: preserved.ProviderRevision.ID == canary.ID, OldRunState: string(runCompleted), UpdatedAt: now().UTC(),
	}); err != nil {
		return Report{}, fmt.Errorf("persist candidate completion: %w", err)
	}
	return Report{
		Phase: callerReport.Phase, Scenarios: callerReport.Scenarios,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Platform: Evidence{
			Kind: "agent-platform-candidate-integration-v1", RunID: platformRunID,
			ProviderRevisionID: stable.ID, CapabilityProfileID: stable.CapabilityProfileID,
			RuntimeProfileID: stable.RuntimeProfileID, ContractNamespace: stable.ContractNamespace,
			ContractVersion: stable.ContractVersion, ShadowCapabilities: true, ShadowRequest: true,
			SelectedRevisionID: newRun.ProviderRevision.ID, CanaryProbeRevisionID: preserved.ProviderRevision.ID,
			CanaryRollbackPreserved: preserved.ProviderRevision.ID == canary.ID,
			OldRunState:             string(runCompleted), RunState: string(runCompleted),
			Metrics:          candidateMetrics(callerReport),
			EvidenceBoundary: "Agent Platform candidate integration only; not Veronica production, aggregate conformance, multi-controller, hostile multi-tenant, deployment, or production readiness",
		},
	}, nil
}

func revisionFromConfig(config caller.Config) Revision {
	return Revision{
		ID: config.ProviderRevisionID, CapabilityProfileID: capabilityProfile, RuntimeProfileID: runtimeProfile,
		ContractNamespace: contractNamespace, ContractVersion: contractVersion, ImageDigest: config.RuntimeImageDigest,
		SecurityPolicyDigest: sha256Digest([]byte(platformPolicyID + ":stable")),
	}
}

func candidateMetrics(report caller.Report) Metrics {
	var result Metrics
	for _, scenario := range report.Scenarios {
		name := strings.ToLower(scenario.Name)
		if strings.Contains(name, "lifecycle") {
			result.LifecycleSamples = 1
		}
		if strings.Contains(name, "exec") {
			result.ExecAttempts++
			if scenario.Status == "passed" && strings.Contains(name, "result") {
				result.ExecSuccesses++
			}
		}
		if strings.Contains(name, "terminal") || strings.Contains(name, "gateway") {
			result.SessionObservations++
			if scenario.Status == "passed" {
				result.StableSessions++
			}
		}
		if strings.Contains(name, "artifact") || strings.Contains(name, "usage") {
			result.ResourceObservations++
			if scenario.Status == "passed" {
				result.ResourceEvidence++
			}
		}
	}
	result.ReconciliationSamples = 1
	return result
}

func shadowCapabilities(ctx context.Context, config caller.Config, revision Revision) (caller.Capabilities, error) {
	client, err := newMTLSClient(config.CAFile, config.ControllerA.CertificateFile, config.ControllerA.PrivateKeyFile)
	if err != nil {
		return caller.Capabilities{}, err
	}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.ProviderBaseURL+"/v1/capabilities", nil)
	if err != nil {
		return caller.Capabilities{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return caller.Capabilities{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return caller.Capabilities{}, fmt.Errorf("status = %d, want 200", response.StatusCode)
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return caller.Capabilities{}, errors.New("capability response is not JSON")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return caller.Capabilities{}, err
	}
	if len(body) > maxResponseBytes {
		return caller.Capabilities{}, errors.New("capability response exceeds bound")
	}
	var capabilities caller.Capabilities
	if err := decodeStrict(body, &capabilities); err != nil {
		return caller.Capabilities{}, err
	}
	if err := validateCapabilities(capabilities, revision); err != nil {
		return caller.Capabilities{}, err
	}
	return capabilities, nil
}

func newMTLSClient(caFile, certificateFile, privateKeyFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("candidate CA bundle is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}},
		MaxIdleConns:    4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
	}, Timeout: 20 * time.Second}, nil
}

func validateCapabilities(capabilities caller.Capabilities, revision Revision) error {
	if capabilities.ProviderRevisionID != revision.ID || capabilities.APIVersion != "v1" || len(capabilities.Capabilities) != 2 || len(capabilities.RuntimeProfiles) != 1 {
		return errors.New("capability identity or shape does not match the candidate profile")
	}
	seen := map[string]bool{}
	for _, capability := range capabilities.Capabilities {
		if len(capability.Versions) != 1 || capability.Versions[0] != contractVersion || len(capability.Profiles) != 1 {
			return errors.New("capability version/profile mismatch")
		}
		seen[capability.ID] = capability.Profiles[0] == "exec-v1" && capability.ID == capabilityIDExec || capability.Profiles[0] == "terminal-v1" && capability.ID == capabilityIDTTY
	}
	if !seen[capabilityIDExec] || !seen[capabilityIDTTY] {
		return errors.New("coding/shell capability pair is incomplete")
	}
	profile := capabilities.RuntimeProfiles[0]
	if profile.ID != runtimeProfile || profile.IsolationClass != "container" || len(profile.Architecture) != 1 || profile.Architecture[0] != "amd64" || len(profile.CapabilityProfileIDs) != 2 || profile.CapabilityProfileIDs[0] != "exec-v1" || profile.CapabilityProfileIDs[1] != "terminal-v1" {
		return errors.New("runtime profile does not match coding/shell")
	}
	return nil
}

func buildCreateRequest(config caller.Config, revision Revision) ([]byte, error) {
	deadline := time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339Nano)
	document := map[string]any{
		"protocol_version": "v1", "operation_id": "platform-shadow-create-1", "attempt_id": "platform-shadow-attempt-1",
		"fencing_token": 1, "idempotency_key": "platform-shadow-idempotency-1", "request_digest": sha256Digest([]byte("platform-shadow-create-request-v1")), "deadline_at": deadline,
		"spec": map[string]any{
			"sandbox_id": "platform-shadow-sandbox-1", "tenant_id": config.ControllerA.TenantID, "work_order_id": config.ControllerA.WorkOrderID,
			"workspace_id": "platform-shadow-workspace-1", "branch_id": "platform-shadow-branch-1", "provider_resolution_id": "platform-shadow-resolution-1",
			"provider_revision_id": revision.ID, "image": map[string]any{"reference": config.RuntimeImageReference, "digest": config.RuntimeImageDigest, "architecture": "amd64"},
			"runtime_profile": runtimeProfile, "resources": map[string]any{"cpu_millis": 500, "memory_bytes": 268435456, "ephemeral_storage_bytes": 268435456, "pids_limit": 64},
			"required_capabilities": []any{map[string]any{"id": capabilityIDExec, "version": contractVersion, "profile": "exec-v1"}, map[string]any{"id": capabilityIDTTY, "version": contractVersion, "profile": "terminal-v1"}},
			"network":               map[string]any{"mode": "none"}, "workspace": map[string]any{"mode": "ephemeral", "base_revision_id": "platform-shadow-base-1", "base_revision_digest": sha256Digest([]byte("platform-shadow-base-v1")), "base_workspace_head_version": 0, "commit_mode": "read_only", "mount_path": "/workspace"},
			"lease":            map[string]any{"expires_at": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano), "max_extension_seconds": 3600},
			"security":         map[string]any{"privilege_level": "unprivileged", "root_filesystem": "read_only", "service_account_mode": "none", "allow_privilege_escalation": false, "host_namespace_access": false, "seccomp_profile": "runtime-default"},
			"sandbox_slot_key": "platform-shadow-slot",
		},
	}
	return json.Marshal(document)
}

func shadowRequest(document []byte, capabilities caller.Capabilities, revision Revision) error {
	var root map[string]json.RawMessage
	if err := decodeStrict(document, &root); err != nil {
		return err
	}
	if err := validateObjectFields("create", root,
		[]string{"operation_id", "attempt_id", "fencing_token", "idempotency_key", "request_digest", "deadline_at", "protocol_version", "spec", "trace_context"},
		[]string{"operation_id", "attempt_id", "fencing_token", "idempotency_key", "request_digest", "deadline_at", "protocol_version", "spec"}); err != nil {
		return err
	}
	if err := stringPatternField(root, "operation_id", identifierPattern, "create operation_id"); err != nil {
		return err
	}
	if err := stringPatternField(root, "attempt_id", identifierPattern, "create attempt_id"); err != nil {
		return err
	}
	if err := stringPatternField(root, "request_digest", digestPattern, "create request_digest"); err != nil {
		return err
	}
	var protocol string
	if err := json.Unmarshal(root["protocol_version"], &protocol); err != nil || protocol != "v1" {
		return errors.New("shadow request protocol version is invalid")
	}
	var fencingToken int64
	if err := json.Unmarshal(root["fencing_token"], &fencingToken); err != nil || fencingToken < 1 {
		return errors.New("shadow request fencing token is invalid")
	}
	var deadline string
	if err := json.Unmarshal(root["deadline_at"], &deadline); err != nil {
		return errors.New("shadow request deadline is invalid")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, deadline); err != nil || !parsed.After(time.Now()) {
		return errors.New("shadow request deadline is expired or invalid")
	}
	spec, err := objectField(root, "spec")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec", spec,
		[]string{"sandbox_id", "tenant_id", "work_order_id", "workspace_id", "branch_id", "provider_resolution_id", "provider_revision_id", "image", "runtime_profile", "resources", "required_capabilities", "optional_capabilities", "network", "workspace", "lease", "placement_constraints", "security", "labels", "sandbox_slot_key", "agent_run_id"},
		[]string{"sandbox_id", "tenant_id", "work_order_id", "workspace_id", "branch_id", "provider_resolution_id", "provider_revision_id", "image", "runtime_profile", "resources", "required_capabilities", "network", "workspace", "lease", "security", "sandbox_slot_key"}); err != nil {
		return err
	}
	image, err := objectField(spec, "image")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.image", image, []string{"reference", "digest", "architecture"}, []string{"reference", "digest"}); err != nil {
		return err
	}
	resources, err := objectField(spec, "resources")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.resources", resources, []string{"cpu_millis", "memory_bytes", "ephemeral_storage_bytes", "workspace_bytes", "gpu_count", "pids_limit"}, []string{"cpu_millis", "memory_bytes", "ephemeral_storage_bytes", "pids_limit"}); err != nil {
		return err
	}
	network, err := objectField(spec, "network")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.network", network, []string{"mode", "policy_reference", "egress_gateway_required"}, []string{"mode"}); err != nil {
		return err
	}
	workspace, err := objectField(spec, "workspace")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.workspace", workspace, []string{"mode", "base_revision_id", "base_revision_digest", "base_workspace_head_version", "commit_mode", "snapshot_reference", "mount_path"}, []string{"mode", "base_revision_id", "base_revision_digest", "base_workspace_head_version", "commit_mode"}); err != nil {
		return err
	}
	lease, err := objectField(spec, "lease")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.lease", lease, []string{"expires_at", "max_extension_seconds"}, []string{"expires_at", "max_extension_seconds"}); err != nil {
		return err
	}
	security, err := objectField(spec, "security")
	if err != nil {
		return err
	}
	if err := validateObjectFields("spec.security", security, []string{"privilege_level", "root_filesystem", "service_account_mode", "allow_privilege_escalation", "host_namespace_access", "seccomp_profile"}, []string{"privilege_level", "root_filesystem", "service_account_mode", "allow_privilege_escalation", "host_namespace_access"}); err != nil {
		return err
	}
	var providerRevision, profile string
	if err := json.Unmarshal(spec["provider_revision_id"], &providerRevision); err != nil || providerRevision != revision.ID {
		return errors.New("shadow request ProviderRevision mismatch")
	}
	if err := json.Unmarshal(spec["runtime_profile"], &profile); err != nil || profile != runtimeProfile {
		return errors.New("shadow request runtime profile mismatch")
	}
	if err := stringPatternField(image, "digest", digestPattern, "spec.image.digest"); err != nil {
		return err
	}
	if err := stringPatternField(workspace, "base_revision_digest", digestPattern, "spec.workspace.base_revision_digest"); err != nil {
		return err
	}
	var required []struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Profile string `json:"profile"`
	}
	capabilityRaw, ok := spec["required_capabilities"]
	if !ok {
		return errors.New("shadow request required_capabilities is required")
	}
	if err := decodeStrict(capabilityRaw, &required); err != nil || len(required) != 2 {
		return errors.New("shadow request capability requirements are invalid")
	}
	seenRequirements := map[string]bool{}
	for _, requirement := range required {
		if requirement.Version != contractVersion || (requirement.ID != capabilityIDExec && requirement.ID != capabilityIDTTY) || requirement.Profile == "" || seenRequirements[requirement.ID] {
			return errors.New("shadow request capability requirement is not locked")
		}
		seenRequirements[requirement.ID] = true
		found := false
		for _, capability := range capabilities.Capabilities {
			if capability.ID == requirement.ID && len(capability.Versions) == 1 && capability.Versions[0] == requirement.Version && len(capability.Profiles) == 1 && capability.Profiles[0] == requirement.Profile {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("Provider does not advertise required capability %q", requirement.ID)
		}
	}
	if !seenRequirements[capabilityIDExec] || !seenRequirements[capabilityIDTTY] {
		return errors.New("shadow request capability pair is incomplete")
	}
	return nil
}

func validateObjectFields(name string, object map[string]json.RawMessage, allowed, required []string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("unknown %s field %q", name, key)
		}
	}
	for _, key := range required {
		value, ok := object[key]
		if !ok || len(value) == 0 || string(value) == "null" {
			return fmt.Errorf("required %s field %q is missing", name, key)
		}
	}
	return nil
}

func objectField(parent map[string]json.RawMessage, name string) (map[string]json.RawMessage, error) {
	value, ok := parent[name]
	if !ok {
		return nil, fmt.Errorf("required object field %q is missing", name)
	}
	var object map[string]json.RawMessage
	if err := decodeStrict(value, &object); err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return object, nil
}

func stringPatternField(object map[string]json.RawMessage, name string, pattern *regexp.Regexp, label string) error {
	value, ok := object[name]
	if !ok {
		return fmt.Errorf("required field %q is missing", label)
	}
	var stringValue string
	if err := json.Unmarshal(value, &stringValue); err != nil || !pattern.MatchString(stringValue) {
		return fmt.Errorf("field %q is invalid", label)
	}
	return nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("candidate document has trailing input")
	}
	return nil
}

func readState(path string) (persistedState, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return persistedState{}, err
	}
	if len(content) > maxStateBytes {
		return persistedState{}, errors.New("candidate state exceeds bound")
	}
	var state persistedState
	if err := decodeStrict(content, &state); err != nil {
		return persistedState{}, err
	}
	if state.SchemaVersion != stateVersion || state.UpdatedAt.IsZero() || state.RunID != platformRunID || !identifierPattern.MatchString(state.ProviderRevisionID) || !identifierPattern.MatchString(state.SelectedRevisionID) || (state.BindingState != string(runActive) && state.BindingState != string(runDraining) && state.BindingState != string(runCompleted)) || !identifierPattern.MatchString(state.CanaryProbeRevisionID) || !state.CanaryRollbackPreserved {
		return persistedState{}, errors.New("candidate state identity is invalid")
	}
	return state, nil
}

func writeState(path string, state persistedState) error {
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if len(content) > maxStateBytes {
		return errors.New("candidate state exceeds bound")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".platform-candidate-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
