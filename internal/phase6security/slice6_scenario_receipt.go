package phase6security

import "time"

// Scenario receipts are private, run-scoped observations. This closed v2
// shape replaces the old list of asserted labels. It still cannot attest
// origin: only the trusted live harness may populate these measurements.
const slice6ScenarioReceiptProtocol = "sandbox-runtime.phase6-slice6-scenario-raw.v2"

type slice6ScenarioRawReceipt struct {
	Protocol     string                      `json:"protocol"`
	Version      int                         `json:"version"`
	RunID        string                      `json:"run_id"`
	Name         string                      `json:"name"`
	Participants []string                    `json:"participants"`
	Measurements []slice6ScenarioMeasurement `json:"measurements"`
}

type slice6ScenarioMeasurement struct {
	Assertion           string                 `json:"assertion"`
	ProbeKind           string                 `json:"probe_kind"`
	Source              string                 `json:"source"`
	Target              string                 `json:"target"`
	SourceInstance      string                 `json:"source_instance"`
	TargetInstance      string                 `json:"target_instance"`
	SourceReceiptKey    string                 `json:"source_receipt_key"`
	SourceReceiptDigest string                 `json:"source_receipt_digest"`
	TargetReceiptKey    string                 `json:"target_receipt_key"`
	TargetReceiptDigest string                 `json:"target_receipt_digest"`
	StartedAt           string                 `json:"started_at"`
	FinishedAt          string                 `json:"finished_at"`
	Result              string                 `json:"result"`
	DurationMillis      int64                  `json:"duration_millis"`
	Count               int64                  `json:"count"`
	IdentityBefore      string                 `json:"identity_before"`
	IdentityAfter       string                 `json:"identity_after"`
	UID                 uint32                 `json:"uid"`
	GID                 uint32                 `json:"gid"`
	HealthyControl      *slice6ScenarioControl `json:"healthy_control,omitempty"`
	Restarts            []slice6RestartPair    `json:"restarts,omitempty"`
}

type slice6RestartPair struct {
	Deployment string                  `json:"deployment"`
	Before     slice6ProcessReceiptRef `json:"before"`
	After      slice6ProcessReceiptRef `json:"after"`
}

type slice6ProcessReceiptRef struct {
	Sequence      int    `json:"sequence"`
	ContainerID   string `json:"container_id"`
	CommandKey    string `json:"command_key"`
	CommandDigest string `json:"command_digest"`
	InspectKey    string `json:"inspect_key"`
	InspectDigest string `json:"inspect_digest"`
	ConfigDigest  string `json:"config_digest"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
}

type slice6ScenarioControl struct {
	ObservedAt     string `json:"observed_at"`
	Result         string `json:"result"`
	ProbeKind      string `json:"probe_kind"`
	SourceInstance string `json:"source_instance"`
	TargetInstance string `json:"target_instance"`
	SourceReceipt  string `json:"source_receipt"`
	TargetReceipt  string `json:"target_receipt"`
}

type slice6ProbeSpec struct {
	Source, Target, Kind, Criterion string
}

// Each row is a reviewed assertion, concrete source/target and probe family.
// A new label is not an invitation to accept an arbitrary probe DSL.
var slice6ProbeSpecs = map[string]slice6ProbeSpec{
	"finite_capacity":                 {"browser-runtime-role", "browser-executor-backend", "executor_capacity", "deny"},
	"real_cdp_version":                {"browser-runtime-role", "browser-executor-backend", "cdp_version", "nonzero"},
	"same_authority_replay_denied":    {"browser-runtime-role", "browser-executor-backend", "executor_replay", "deny"},
	"distinct_external_identities":    {"browser-action-ingress-runtime", "action-history-postgres", "external_identity", "distinct"},
	"grant_isolation":                 {"browser-action-ingress-runtime", "action-history-postgres", "postgres_grant", "deny"},
	"restore_domain_isolation":        {"browser-action-ingress-runtime", "capacity-valkey", "restore_domain", "distinct"},
	"cross_tenant_denied":             {"gateway-runtime", "provider-browser-runtime", "tenant_authority", "deny"},
	"wrong_peer_denied":               {"gateway-runtime", "provider-browser-runtime", "tls_peer", "deny"},
	"wrong_route_denied":              {"gateway-runtime", "provider-browser-runtime", "route_authority", "deny"},
	"broker_in_parent_observed":       {"desktop-runtime-role", "desktop-broker", "process_parent", "nonzero"},
	"exact_dynamic_cleanup":           {"desktop-runtime-role", "desktop-broker", "docker_cleanup", "zero"},
	"real_rtp_and_input":              {"desktop-runtime-role", "desktop-executor-backend", "rtp_input", "nonzero"},
	"alias_only_egress":               {"product-runtime", "egress-broker-product", "egress_alias", "allow"},
	"metadata_denied":                 {"product-runtime", "egress-broker-product", "metadata_route", "deny"},
	"role_direct_ip_denied":           {"product-runtime", "egress-broker-product", "direct_ip", "deny"},
	"alternate_path_denied":           {"egress-broker-product", "dns", "dns_alternate_path", "deny"},
	"dns_receipt_observed":            {"egress-broker-product", "dns", "dns_receipt", "nonzero"},
	"rebinding_denied":                {"egress-broker-product", "dns", "dns_rebinding", "deny"},
	"bounded_recovery":                {"browser-action-ingress-runtime", "capacity-valkey", "dependency_recovery", "bounded"},
	"capacity_loss_closes_admission":  {"browser-action-ingress-runtime", "capacity-valkey", "capacity_loss", "deny"},
	"witness_loss_closes_admission":   {"browser-action-ingress-runtime", "action-history-postgres", "witness_loss", "deny"},
	"binding_revoke_denied":           {"guest-runtime", "product-runtime", "guest_binding", "deny"},
	"signed_challenge_welcome":        {"guest-runtime", "product-runtime", "guest_challenge", "nonzero"},
	"upgraded_socket_drain":           {"guest-runtime", "product-runtime", "websocket_drain", "deny"},
	"complete_container_inventory":    {"product-runtime", "gateway-runtime", "docker_inventory", "count82"},
	"effective_uid_gid":               {"product-runtime", "gateway-runtime", "docker_user", "uid_gid"},
	"seccomp_capability_mount_limits": {"product-runtime", "gateway-runtime", "docker_security", "zero"},
	"legacy_downgrade_denied":         {"gateway-runtime", "provider-runtime", "legacy_downgrade", "deny"},
	"plaintext_denied":                {"gateway-runtime", "provider-runtime", "plaintext", "deny"},
	"wrong_certificate_denied":        {"gateway-runtime", "provider-runtime", "tls_certificate", "deny"},
	"authority_loss_closes_egress":    {"egress-broker-product", "egress-policy-authority-product", "policy_loss", "deny"},
	"fresh_state_required":            {"egress-broker-product", "egress-policy-authority-product", "policy_freshness", "deny"},
	"revoked_policy_denied":           {"egress-broker-product", "egress-policy-authority-product", "policy_revocation", "deny"},
	"distinct_process_instances":      {"provider-runtime", "browser-executor-backend", "process_restart", "restart_instances"},
	"retained_authority":              {"provider-runtime", "browser-executor-backend", "authority_restart", "restart_authority"},
	"stale_admission_denied":          {"provider-runtime", "browser-executor-backend", "stale_admission", "restart_denial"},
	"bounded_gateway_connections":     {"gateway-runtime", "provider-runtime", "connection_capacity", "deny"},
	"bounded_product_requests":        {"product-runtime", "provider-runtime", "request_capacity", "deny"},
	"bounded_workers":                 {"product-runtime", "provider-runtime", "worker_capacity", "deny"},
	"active_socket_drain":             {"gateway-runtime", "provider-runtime", "revoked_socket", "drain10s"},
	"crl_rollback_denied":             {"gateway-runtime", "provider-runtime", "crl_rollback", "deny"},
	"vault_revoked_leaf_denied":       {"gateway-runtime", "provider-runtime", "vault_revoked_leaf", "deny"},
	"active_socket_close":             {"browser-runtime-role", "desktop-runtime-role", "role_socket_close", "deny"},
	"bounded_sigterm":                 {"browser-runtime-role", "desktop-runtime-role", "role_sigterm", "bounded"},
	"exact_lease_socket_cleanup":      {"certificate-controller", "vault", "lease_socket_cleanup", "zero"},
	"fresh_issue_and_overlap":         {"certificate-controller", "vault", "vault_issue_overlap", "distinct"},
	"live_rotation":                   {"certificate-controller", "vault", "vault_rotation", "distinct"},
	"loss_closes_admission":           {"certificate-controller", "vault", "vault_loss", "deny"},
}

var slice6RestartSubjects = []string{
	"browser-executor-backend", "desktop-executor-backend", "provider-runtime",
}

func slice6SubjectReceipt(e Slice6Evidence, subject string) (key, digest, instance string, ok bool) {
	for _, item := range e.Observations.Containers {
		if item.DeploymentName == subject {
			return "container/" + subject + "/inspect", item.ContainerInspectDigest, item.ContainerID, true
		}
	}
	for _, item := range e.External {
		if item.Name == subject {
			return "external/" + subject + "/inspect", item.ContainerInspectDigest, item.ContainerID, true
		}
	}
	for _, item := range e.Components {
		if item.Name == subject {
			return "component/" + subject + "/process", item.ProcessInspectDigest, item.ParentContainerID, true
		}
	}
	return "", "", "", false
}

func validSlice6ScenarioReceipt(document []byte, evidence Slice6Evidence, name string) bool {
	var value slice6ScenarioRawReceipt
	if decodeCanonicalSlice6Receipt(document, &value) != nil || value.Protocol != slice6ScenarioReceiptProtocol ||
		value.Version != 2 || value.RunID != evidence.RunID || value.Name != name ||
		len(value.Measurements) != len(slice6RequiredAssertions[name]) {
		return false
	}
	var participants []string
	for _, scenario := range evidence.Scenarios {
		if scenario.Name == name {
			participants = scenario.Participants
			break
		}
	}
	if !exactStrings(value.Participants, participants) {
		return false
	}
	manifestTime, _ := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	for index, measurement := range value.Measurements {
		if measurement.Assertion != slice6RequiredAssertions[name][index] {
			return false
		}
		spec, ok := slice6ProbeSpecs[measurement.Assertion]
		if !ok || measurement.ProbeKind != spec.Kind || measurement.Source != spec.Source || measurement.Target != spec.Target {
			return false
		}
		sourceKey, sourceDigest, sourceInstance, sourceOK := slice6SubjectReceipt(evidence, spec.Source)
		targetKey, targetDigest, targetInstance, targetOK := slice6SubjectReceipt(evidence, spec.Target)
		if !sourceOK || !targetOK || measurement.SourceReceiptKey != sourceKey ||
			measurement.SourceReceiptDigest != sourceDigest || measurement.SourceInstance != sourceInstance ||
			measurement.TargetReceiptKey != targetKey || measurement.TargetReceiptDigest != targetDigest ||
			measurement.TargetInstance != targetInstance {
			return false
		}
		start, startErr := time.Parse(time.RFC3339Nano, measurement.StartedAt)
		finish, finishErr := time.Parse(time.RFC3339Nano, measurement.FinishedAt)
		if startErr != nil || finishErr != nil || !start.Before(finish) || finish.After(manifestTime) ||
			measurement.DurationMillis != finish.Sub(start).Milliseconds() || measurement.DurationMillis < 1 ||
			measurement.DurationMillis > 30000 {
			return false
		}
		if !validSlice6ScenarioCriterion(measurement, spec, evidence) {
			return false
		}
	}
	return true
}

func validSlice6ScenarioCriterion(m slice6ScenarioMeasurement, spec slice6ProbeSpec, e Slice6Evidence) bool {
	restart := spec.Criterion == "restart_instances" || spec.Criterion == "restart_authority" ||
		spec.Criterion == "restart_denial"
	if restart {
		if !validSlice6RestartPairs(m, e) {
			return false
		}
	} else if len(m.Restarts) != 0 {
		return false
	}
	if spec.Criterion == "deny" || spec.Criterion == "drain10s" || spec.Criterion == "restart_denial" {
		if m.Result != "denied" || m.HealthyControl == nil ||
			m.HealthyControl.Result != "accepted" || !validSlice6Time(m.HealthyControl.ObservedAt) ||
			m.HealthyControl.ProbeKind != spec.Kind ||
			m.HealthyControl.SourceInstance != m.SourceInstance ||
			m.HealthyControl.TargetInstance != m.TargetInstance ||
			m.HealthyControl.SourceReceipt != m.SourceReceiptKey ||
			m.HealthyControl.TargetReceipt != m.TargetReceiptKey {
			return false
		}
		controlAt, _ := time.Parse(time.RFC3339Nano, m.HealthyControl.ObservedAt)
		start, _ := time.Parse(time.RFC3339Nano, m.StartedAt)
		finish, _ := time.Parse(time.RFC3339Nano, m.FinishedAt)
		manifestAt, _ := time.Parse(time.RFC3339Nano, e.ObservedAt)
		if controlAt.Before(start.Add(-30*time.Second)) || controlAt.After(finish.Add(30*time.Second)) ||
			controlAt.After(manifestAt) ||
			(spec.Criterion == "drain10s" && m.DurationMillis > 10000) {
			return false
		}
	} else if m.HealthyControl != nil {
		return false
	}
	switch spec.Criterion {
	case "deny", "drain10s":
		return m.Count == 0 && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "restart_denial":
		return m.Count == int64(len(slice6RestartSubjects)) && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "restart_instances":
		return m.Result == "observed" && m.Count == int64(len(slice6RestartSubjects)) &&
			m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "restart_authority":
		return m.Result == "observed" && m.Count == int64(len(slice6RestartSubjects)) &&
			digestPattern.MatchString(m.IdentityBefore) && m.IdentityBefore == m.IdentityAfter && m.UID == 0 && m.GID == 0
	case "allow", "bounded":
		return m.Result == "accepted" && m.Count == 0 && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "nonzero":
		return m.Result == "observed" && m.Count > 0 && m.Count <= 1<<30 && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "zero":
		return m.Result == "observed" && m.Count == 0 && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "count82":
		return m.Result == "observed" && m.Count == int64(len(Slice6DesiredDeploymentNames())) && m.IdentityBefore == "" && m.IdentityAfter == "" && m.UID == 0 && m.GID == 0
	case "distinct":
		return m.Result == "observed" && m.Count == 0 &&
			digestPattern.MatchString(m.IdentityBefore) && digestPattern.MatchString(m.IdentityAfter) &&
			m.IdentityBefore != m.IdentityAfter && m.UID == 0 && m.GID == 0
	case "stable":
		return m.Result == "observed" && m.Count == 0 &&
			digestPattern.MatchString(m.IdentityBefore) && m.IdentityBefore == m.IdentityAfter && m.UID == 0 && m.GID == 0
	case "uid_gid":
		for _, principal := range e.Profile.Principals {
			if principal.Name == m.Source {
				return m.Result == "observed" && m.Count == 0 && m.IdentityBefore == "" && m.IdentityAfter == "" &&
					m.UID == principal.UID && m.GID == principal.GID
			}
		}
	}
	return false
}

func validSlice6RestartPairs(m slice6ScenarioMeasurement, e Slice6Evidence) bool {
	if len(m.Restarts) != len(slice6RestartSubjects) {
		return false
	}
	measurementFinish, _ := time.Parse(time.RFC3339Nano, m.FinishedAt)
	for index, pair := range m.Restarts {
		if pair.Deployment != slice6RestartSubjects[index] || pair.Before.Sequence != 1 ||
			pair.After.Sequence <= pair.Before.Sequence || pair.After.Sequence > 8 ||
			pair.Before.ContainerID == pair.After.ContainerID ||
			!validSlice6ProcessReceiptRef(pair.Deployment, pair.Before, e) ||
			!validSlice6ProcessReceiptRef(pair.Deployment, pair.After, e) {
			return false
		}
		beforeFinish, _ := time.Parse(time.RFC3339Nano, pair.Before.FinishedAt)
		afterStart, _ := time.Parse(time.RFC3339Nano, pair.After.StartedAt)
		if afterStart.Before(beforeFinish) || afterStart.After(measurementFinish) {
			return false
		}
		final := false
		for _, observed := range e.Observations.Containers {
			if observed.DeploymentName == pair.Deployment && observed.ContainerID == pair.After.ContainerID &&
				observed.ContainerInspectDigest == pair.After.InspectDigest {
				final = true
			}
		}
		if !final {
			return false
		}
	}
	return true
}

func validSlice6ProcessReceiptRef(deployment string, ref slice6ProcessReceiptRef, e Slice6Evidence) bool {
	prefix := slice6ProcessReceiptPrefix(deployment, ref.Sequence)
	if ref.CommandKey != prefix+"/command" || ref.InspectKey != prefix+"/inspect" ||
		!validSlice6Time(ref.StartedAt) || !validSlice6Time(ref.FinishedAt) {
		return false
	}
	for _, process := range e.Processes {
		if process.DeploymentName == deployment && process.Sequence == ref.Sequence {
			return process.ContainerID == ref.ContainerID && process.CommandDigest == ref.CommandDigest &&
				process.InspectDigest == ref.InspectDigest && process.ConfigDigest == ref.ConfigDigest &&
				process.StartedAt == ref.StartedAt && process.FinishedAt == ref.FinishedAt
		}
	}
	return false
}

func validSlice6ScenarioSpecInventory() bool {
	seen := make(map[string]bool)
	for _, assertions := range slice6RequiredAssertions {
		for _, assertion := range assertions {
			if assertion == "" || seen[assertion] {
				return false
			}
			seen[assertion] = true
		}
	}
	if len(seen) != len(slice6ProbeSpecs) {
		return false
	}
	for assertion, spec := range slice6ProbeSpecs {
		if !seen[assertion] || spec.Source == "" || spec.Target == "" || spec.Kind == "" || spec.Criterion == "" {
			return false
		}
	}
	return true
}
