package qualificationoperator

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strings"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

type providerDocumentValidator interface {
	Validate(string, []byte) error
}

func providerEvidenceGroups(expected []qualificationprofile.InteractionObservationRequirement, progress map[string]qualificationharness.InteractionProgress, raw []HTTPObservation) (map[string][]HTTPObservation, error) {
	result := make(map[string][]HTTPObservation, len(expected))
	offset := 0
	for _, requirement := range expected {
		attempts := progress[requirement.InteractionID].WireAttempts
		if attempts < 1 || offset+attempts > len(raw) || result[requirement.InteractionID] != nil {
			return nil, ErrObservationProjection
		}
		result[requirement.InteractionID] = append([]HTTPObservation(nil), raw[offset:offset+attempts]...)
		offset += attempts
	}
	if offset != len(raw) {
		return nil, ErrObservationProjection
	}
	return result, nil
}

func validateProviderEvidence(groups map[string][]HTTPObservation, contract providerDocumentValidator, limits qualificationprofile.RuntimeLimits) (*qualificationharness.SandboxResourceObservation, error) {
	if len(groups) != 34 || contract == nil {
		return nil, ErrObservationProjection
	}
	valid := map[string]bool{}
	for id, group := range groups {
		valid[id] = validateProviderSubject(id, group, contract)
		if !valid[id] {
			return nil, fmt.Errorf("%w: provider-subject-%s", ErrObservationProjection, id)
		}
	}
	if !allTrue(valid) {
		return nil, fmt.Errorf("%w: provider-subject-coverage", ErrObservationProjection)
	}
	if !validateProviderCrossBindings(groups) {
		return nil, fmt.Errorf("%w: provider-cross-bindings", ErrObservationProjection)
	}
	resources, ok := observedSandboxResources(groups, limits)
	if !ok {
		return nil, fmt.Errorf("%w: provider-create-resources", ErrObservationProjection)
	}
	return resources, nil
}

func validateProviderSubject(id string, group []HTTPObservation, contract providerDocumentValidator) bool {
	if len(group) == 0 {
		return false
	}
	last := group[len(group)-1]
	schema := func(name string, value map[string]any) bool {
		document, err := json.Marshal(value)
		return err == nil && contract.Validate(name, document) == nil
	}
	operation := func(operationType, status string) bool {
		return last.StatusCode >= 200 && last.StatusCode < 300 && schema("provider-operation.schema.json", last.ResponseJSON) &&
			stringValue(last.ResponseJSON, "type") == operationType && stringValue(last.ResponseJSON, "status") == status && correlationFieldsPresent(last.ResponseJSON)
	}
	standardError := func() bool {
		return last.StatusCode >= 400 && schema("standard-error.schema.json", last.ResponseJSON) && stringValue(last.ResponseJSON, "code") != ""
	}
	switch id {
	case "controller-a-capabilities", "controller-b-capabilities", "reconstructed-capabilities":
		return last.StatusCode == http.StatusOK && schema("provider-capabilities.schema.json", last.ResponseJSON) && validCodingShellCapabilities(last.ResponseJSON)
	case "same-ca-unadmitted-capabilities":
		return (last.Transport == "tls-rejected" || last.StatusCode == http.StatusForbidden) && stringValue(last.ResponseJSON, "provider_revision_id") == ""
	case "create-sandbox", "new-jti-idempotency-replay":
		return last.MutationWriteObserved && operation("create", "accepted")
	case "exact-jti-replay", "start-stale-fence-exec", "cross-tenant-stage-artifact", "cross-tenant-read-artifact-operation", "wrong-mtls-caller-read-sandbox":
		return standardError()
	case "read-create-operation", "read-reconstructed-create-operation":
		return operation("create", "succeeded")
	case "read-sandbox-status", "read-reconstructed-sandbox":
		return last.StatusCode == http.StatusOK && schema("sandbox-status.schema.json", last.ResponseJSON) &&
			stringValue(last.ResponseJSON, "observed_state") == "ready" && integerValue(last.ResponseJSON, "generation") == 1
	case "start-output-exec", "start-cancellable-exec":
		return last.MutationWriteObserved && operation("exec", "accepted")
	case "read-output-exec-operation":
		return operation("exec", "succeeded")
	case "read-exec-result", "read-retained-exec-result":
		return last.StatusCode == http.StatusOK && schema("exec-result.schema.json", last.ResponseJSON) &&
			stringValue(last.ResponseJSON, "status") == "completed" && integerValue(last.ResponseJSON, "exit_code") == 0 &&
			opaqueReference(stringValue(last.ResponseJSON, "stdout_reference")) && opaqueReference(stringValue(last.ResponseJSON, "stderr_reference"))
	case "read-exec-usage", "read-retained-usage":
		status := stringValue(last.ResponseJSON, "reconciliation_status")
		entries, ok := last.ResponseJSON["entries"].([]any)
		return last.StatusCode == http.StatusOK && schema("usage-evidence.schema.json", last.ResponseJSON) && ok && len(entries) > 0 && (status == "complete" || status == "partial")
	case "cancel-exec":
		return last.MutationWriteObserved && operation("cancel_exec", "accepted")
	case "read-cancel-operation":
		return operation("cancel_exec", "succeeded")
	case "read-cancelled-operation":
		return operation("exec", "cancelled")
	case "read-cancelled-result":
		return last.StatusCode == http.StatusOK && schema("exec-result.schema.json", last.ResponseJSON) && stringValue(last.ResponseJSON, "status") == "cancelled"
	case "open-terminal-session":
		return last.MutationWriteObserved && operation("open_runtime_session", "accepted")
	case "read-terminal-operation":
		return operation("open_runtime_session", "succeeded")
	case "read-terminal-handoff", "read-retained-terminal-handoff":
		return last.StatusCode == http.StatusOK && schema("runtime-session-handoff.schema.json", last.ResponseJSON) &&
			stringValue(last.ResponseJSON, "protocol") == "websocket" && strings.HasPrefix(stringValue(last.ResponseJSON, "internal_endpoint_reference"), "ref:session:") &&
			integerValue(last.ResponseJSON, "connection_generation") > 0 && stringValue(last.ResponseJSON, "runtime_session_id") != ""
	case "stage-artifact":
		return last.MutationWriteObserved && operation("artifact_stage", "accepted")
	case "read-artifact-operation":
		return operation("artifact_stage", "succeeded")
	case "read-artifact-evidence", "read-retained-artifact-evidence":
		return last.StatusCode == http.StatusOK && schema("artifact-staging-evidence.schema.json", last.ResponseJSON) &&
			stringValue(last.ResponseJSON, "status") == "staged" && opaqueReference(stringValue(last.ResponseJSON, "staging_reference"))
	default:
		return false
	}
}

func validateProviderCrossBindings(groups map[string][]HTTPObservation) bool {
	final := func(id string) HTTPObservation {
		group := groups[id]
		return group[len(group)-1]
	}
	capA, capB, capReconstructed := final("controller-a-capabilities"), final("controller-b-capabilities"), final("reconstructed-capabilities")
	if capA.ResponseDigest == "" || capA.ResponseDigest != capB.ResponseDigest || capA.ResponseDigest != capReconstructed.ResponseDigest ||
		stringValue(capA.ResponseJSON, "provider_revision_id") != ProviderRevision {
		return false
	}
	create, exact, fresh := final("create-sandbox"), final("exact-jti-replay"), final("new-jti-idempotency-replay")
	if create.RequestDigest == "" || create.RequestDigest != exact.RequestDigest || create.RequestDigest != fresh.RequestDigest ||
		create.AdmissionDigest == "" || create.AdmissionDigest != exact.AdmissionDigest || create.AdmissionDigest == fresh.AdmissionDigest ||
		!sameFields(create.ResponseJSON, fresh.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") {
		return false
	}
	createRead, createReconstructed := final("read-create-operation"), final("read-reconstructed-create-operation")
	if !sameFields(create.ResponseJSON, createRead.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		!sameFields(createRead.ResponseJSON, createReconstructed.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") {
		return false
	}
	sandbox, sandboxReconstructed := final("read-sandbox-status"), final("read-reconstructed-sandbox")
	createSpec := nestedMap(create.RequestJSON, "spec")
	if createSpec == nil || stringValue(createSpec, "tenant_id") == "" || stringValue(createSpec, "tenant_id") != stringValue(sandbox.ResponseJSON, "tenant_id") ||
		!sameFields(sandbox.ResponseJSON, sandboxReconstructed.ResponseJSON, "sandbox_id", "tenant_id", "generation", "provider_revision_id") {
		return false
	}
	outputExec, outputOperation := final("start-output-exec"), final("read-output-exec-operation")
	if !sameFields(outputExec.ResponseJSON, outputOperation.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") {
		return false
	}
	execResult, retainedResult := final("read-exec-result"), final("read-retained-exec-result")
	usage, retainedUsage := final("read-exec-usage"), final("read-retained-usage")
	if execResult.ResponseDigest == "" || execResult.ResponseDigest != retainedResult.ResponseDigest || usage.ResponseDigest == "" || usage.ResponseDigest != retainedUsage.ResponseDigest ||
		!sameFields(outputExec.ResponseJSON, execResult.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		!sameFields(execResult.ResponseJSON, usage.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") {
		return false
	}
	stale, cancellable := final("start-stale-fence-exec"), final("start-cancellable-exec")
	if integerValue(stale.RequestJSON, "fencing_token") >= integerValue(cancellable.RequestJSON, "fencing_token") {
		return false
	}
	cancel, cancelOperation, cancelledOperation, cancelledResult := final("cancel-exec"), final("read-cancel-operation"), final("read-cancelled-operation"), final("read-cancelled-result")
	if !sameFields(cancel.ResponseJSON, cancelOperation.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		stringValue(cancel.RequestJSON, "target_operation_id") != stringValue(cancelledOperation.ResponseJSON, "operation_id") ||
		!sameFields(cancelledOperation.ResponseJSON, cancelledResult.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") {
		return false
	}
	terminal, terminalOperation, handoff, retainedHandoff := final("open-terminal-session"), final("read-terminal-operation"), final("read-terminal-handoff"), final("read-retained-terminal-handoff")
	if !sameFields(terminal.ResponseJSON, terminalOperation.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		!sameFields(terminal.ResponseJSON, handoff.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		!sameFields(handoff.ResponseJSON, retainedHandoff.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token", "runtime_session_id", "internal_endpoint_reference") {
		return false
	}
	stage, stageOperation, evidence, retainedEvidence := final("stage-artifact"), final("read-artifact-operation"), final("read-artifact-evidence"), final("read-retained-artifact-evidence")
	if !sameFields(stage.ResponseJSON, stageOperation.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") ||
		!sameFields(stage.ResponseJSON, evidence.ResponseJSON, "operation_id", "sandbox_id", "attempt_id", "fencing_token") || evidence.ResponseDigest == "" || evidence.ResponseDigest != retainedEvidence.ResponseDigest ||
		stringValue(stage.RequestJSON, "expected_digest") != stringValue(evidence.ResponseJSON, "content_digest") || integerValue(evidence.ResponseJSON, "size_bytes") < 1 ||
		integerValue(evidence.ResponseJSON, "size_bytes") > integerValue(stage.RequestJSON, "max_bytes") {
		return false
	}
	return true
}

func observedSandboxResources(groups map[string][]HTTPObservation, limits qualificationprofile.RuntimeLimits) (*qualificationharness.SandboxResourceObservation, bool) {
	ids := []string{"create-sandbox", "exact-jti-replay", "new-jti-idempotency-replay"}
	var observed *qualificationharness.SandboxResourceObservation
	for _, id := range ids {
		group := groups[id]
		if len(group) == 0 {
			return nil, false
		}
		for _, event := range group {
			resources := nestedMap(nestedMap(event.RequestJSON, "spec"), "resources")
			value := &qualificationharness.SandboxResourceObservation{
				CPUMillis: int(integerValue(resources, "cpu_millis")), MemoryBytes: int(integerValue(resources, "memory_bytes")),
				EphemeralStorageBytes: int(integerValue(resources, "ephemeral_storage_bytes")), PIDs: int(integerValue(resources, "pids_limit")),
			}
			if value.CPUMillis < 1 || value.MemoryBytes < 1 || value.EphemeralStorageBytes < 1 || value.PIDs < 1 ||
				(value.CPUMillis != limits.SandboxCPUMillis || value.MemoryBytes != limits.SandboxMemoryBytes || value.EphemeralStorageBytes != limits.SandboxEphemeralStorageBytes || value.PIDs != limits.SandboxPIDs) {
				return nil, false
			}
			if observed != nil && *observed != *value {
				return nil, false
			}
			observed = value
		}
	}
	return observed, observed != nil
}

func gatewayFactObserved(requirement qualificationprofile.ObservationRequirement, projected []qualificationharness.ObservedInteraction, raw []GatewayObservation, challenge string) bool {
	byID := make(map[string]qualificationharness.ObservedInteraction, len(projected))
	for _, interaction := range projected {
		byID[interaction.InteractionID] = interaction
	}
	interaction, ok := byID[requirement.Subject]
	if !ok || interaction.FinalOutcome.Transport == "" {
		return false
	}
	switch requirement.Subject {
	case "gateway-terminal-round-trip", "gateway-same-shell-reconnect":
		return interaction.FinalOutcome.Transport == "authorized-byte-round-trip" && challenge != ""
	case "gateway-missing-caller-credential":
		return interaction.FinalOutcome.Transport == "gateway-upgrade-rejected" && gatewayRawFact(raw, "", "gateway-upgrade-rejected", true)
	case "gateway-cross-tenant":
		return interaction.FinalOutcome.Transport == "gateway-upgrade-rejected" && gatewayRawFact(raw, "controller_b", "gateway-upgrade-rejected", true)
	case "gateway-expiring-grant":
		return interaction.FinalOutcome.Transport == "gateway-closed-at-grant-expiry" && gatewayRawFact(raw, "controller_a", "authorized-byte-round-trip", false)
	case "gateway-revocable-grant", "gateway-revoke-grant":
		return interaction.FinalOutcome.Transport == map[string]string{"gateway-revocable-grant": "authorized-byte-round-trip", "gateway-revoke-grant": "revocation-acknowledged"}[requirement.Subject]
	default:
		return false
	}
}

func gatewayRawFact(events []GatewayObservation, actor, transport string, requireNoBytes bool) bool {
	for _, event := range events {
		if event.Actor == actor && event.Transport == transport {
			if requireNoBytes {
				return event.BytesToGateway == 0 && event.BytesFromGateway == 0
			}
			return event.BytesToGateway > 0 && event.BytesFromGateway > 0
		}
	}
	return false
}

func processFactObserved(requirement qualificationprofile.ObservationRequirement, counts map[string]int, executor *PhaseExecutor, transcript protocol.TranscriptProjection) bool {
	initial, reconstruction := executor.PlannedProcesses("initial"), executor.PlannedProcesses("reconstruction")
	fresh := func(component string) bool {
		return initial[component] != "" && reconstruction[component] != "" && initial[component] != reconstruction[component] && counts[component] >= 2
	}
	switch requirement.ObservationID {
	case "caller-and-adapter-startup-identities-observed":
		return fresh("external_caller") && fresh("qualification_adapter")
	case "new-provider-process":
		return fresh("provider")
	case "new-caller-process":
		return fresh("external_caller")
	case "new-adapter-process":
		return fresh("qualification_adapter")
	case "new-gateway-process":
		return fresh("caller_gateway") && counts["caller_gateway"] >= 5
	case "caller-correlation-load-without-harness-reinjection-observed", "adapter-invocation-transcript-excludes-forbidden-correlations":
		return transcript.Digest != "" && len(transcript.Document) > 0 && transcriptContainsOnlySanitizedBindings(transcript.Document)
	default:
		return false
	}
}

func transcriptContainsOnlySanitizedBindings(document []byte) bool {
	var value any
	if json.Unmarshal(document, &value) != nil {
		return false
	}
	forbidden := map[string]struct{}{
		"sandbox_id": {}, "operation_id": {}, "attempt_id": {}, "idempotency_key": {}, "fencing_token": {},
		"runtime_session_id": {}, "handoff_reference": {}, "credential": {}, "authorization": {},
	}
	return !containsForbiddenKey(value, forbidden)
}

func containsForbiddenKey(value any, forbidden map[string]struct{}) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, found := forbidden[strings.ToLower(key)]; found || containsForbiddenKey(child, forbidden) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsForbiddenKey(child, forbidden) {
				return true
			}
		}
	}
	return false
}

func validCodingShellCapabilities(value map[string]any) bool {
	if stringValue(value, "provider_revision_id") != ProviderRevision || stringValue(value, "api_version") != "v1" {
		return false
	}
	profiles, ok := value["runtime_profiles"].([]any)
	if !ok {
		return false
	}
	for _, raw := range profiles {
		profile, _ := raw.(map[string]any)
		if stringValue(profile, "id") != "sandbox-runtime-coding-shell-v1" {
			continue
		}
		ids := stringSlice(profile["capability_profile_ids"])
		sort.Strings(ids)
		return reflect.DeepEqual(ids, []string{"exec-v1", "terminal-connect-v1", "terminal-v1"})
	}
	return false
}

func sameFields(left, right map[string]any, fields ...string) bool {
	if left == nil || right == nil {
		return false
	}
	for _, field := range fields {
		if left[field] == nil || !reflect.DeepEqual(left[field], right[field]) {
			return false
		}
	}
	return true
}

func correlationFieldsPresent(value map[string]any) bool {
	return stringValue(value, "operation_id") != "" && stringValue(value, "attempt_id") != "" && stringValue(value, "sandbox_id") != "" && integerValue(value, "fencing_token") > 0
}

func opaqueReference(value string) bool { return strings.HasPrefix(value, "ref:") && len(value) <= 400 }

func nestedMap(value map[string]any, key string) map[string]any {
	if value == nil {
		return nil
	}
	result, _ := value[key].(map[string]any)
	return result
}

func stringValue(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	result, _ := value[key].(string)
	return result
}

func integerValue(value map[string]any, key string) int64 {
	if value == nil {
		return math.MinInt64
	}
	number, ok := value[key].(float64)
	if !ok || math.Trunc(number) != number || number < math.MinInt64 || number > math.MaxInt64 {
		return math.MinInt64
	}
	return int64(number)
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil
		}
		result = append(result, text)
	}
	return result
}

func allTrue(values map[string]bool) bool {
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}
