//go:build phase6slicegate

package productphase6gate

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	slice5evidence "github.com/shell-echo/sandbox-runtime/internal/productphase6slice5evidence"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

func observeRoleMaterialEvidence(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	ledger, err := readGateCredentialLedger(environment.paths.credentialLedger)
	if err != nil {
		t.Fatal(err)
	}
	agentNames := []string{"product-migration", "provider-migration", "product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"}
	agents := make([]slice5evidence.AgentEvidence, 0, len(agentNames))
	for _, name := range agentNames {
		agentID := gateCredentialAgentID(name)
		value := slice5evidence.AgentEvidence{AgentID: agentID, Role: environment.materials[name][0].Binding.Role,
			IdentityDigest: evidenceDigest("sandbox-runtime/phase6-slice5/agent-identity/v1", environment.credentialKeys[name].Public().(ed25519.PublicKey)),
			BindingDigest:  environment.credentialBindings[name].Digest(), Migration: strings.HasSuffix(name, "-migration"),
			Renewable: !strings.HasSuffix(name, "-migration")}
		for _, lease := range ledger.Leases {
			if lease.AgentID != agentID {
				continue
			}
			if lease.Role != value.Role || lease.BindingDigest != value.BindingDigest || lease.Migration != value.Migration || lease.Renewable != value.Renewable {
				t.Fatalf("credential lease scope drift for %s", agentID)
			}
			value.LeaseRecords++
			value.MaxRevision = max(value.MaxRevision, lease.Revision)
			switch lease.State {
			case "active":
				value.ActiveLeases++
			case "revoked":
				value.RevokedLeases++
			case "expired":
			default:
				t.Fatalf("unknown credential state for %s", agentID)
			}
			if !value.Migration && lease.Revision >= 2 {
				value.RotationObserved = true
			}
		}
		agents = append(agents, value)
	}

	scenarios := make([]slice5evidence.Scenario, 0, 5)
	for _, name := range slice5evidence.ScenarioNames("material") {
		observation, ok := environment.scenarios[name]
		if !ok || observation.StartedAt.IsZero() || observation.FinishedAt.Before(observation.StartedAt) {
			t.Fatalf("missing Slice 5 material scenario %s", name)
		}
		scenarios = append(scenarios, slice5evidence.Scenario{Name: name, Outcome: "passed",
			EvidenceDigest: evidenceDigest("sandbox-runtime/phase6-slice5/material-scenario/v1", observation)})
	}
	breakGlass := observeBreakGlassEvidence(t, environment)
	plaintext := observePlaintextExclusion(t, environment)
	controllerCount := namedProcessCount(environment.dependencies, "workload-credential-controller")
	value := slice5evidence.RoleMaterialAndCredentials{
		Harness: slice5evidence.RoleMaterialHarness,
		CommandDigest: evidenceDigest("sandbox-runtime/phase6-slice5/material-command/v1", struct {
			Controller, Agent, BreakGlass, Vault string
		}{fileDigest(t, environment.paths.credentialControllerBin), fileDigest(t, environment.paths.materialAgentBin), fileDigest(t, environment.paths.breakGlassControllerBin), gateVaultImage}),
		ConfigDigest: gateConfigDigest(t, environment), VaultImage: gateVaultImage, VaultTLS: true,
		WorkloadMaterialProtocol: "sandbox-runtime.workload-material.v1", WorkloadCredentialProtocol: workloadcredential.ProtocolID,
		BreakGlassProtocol: breakglass.ProtocolID, ManagementCredentialTransport: "inherited_fd_3", CredentialPayloadPersisted: false,
		CredentialControllerProcesses: controllerCount, WorkloadMaterialAgentProcesses: len(environment.materialAgentHistory),
		CredentialTTLSeconds: 30, CredentialOverlapSeconds: 3, Agents: agents, Scenarios: scenarios, BreakGlass: breakGlass, PlaintextExclusion: plaintext,
	}
	value.EvidenceDigest = slice5evidence.RoleMaterialEvidenceDigest(value)
	environment.roleMaterialEvidence = value
}

func observeBreakGlassEvidence(t *testing.T, environment *gateEnvironment) slice5evidence.BreakGlassEvidence {
	t.Helper()
	document, err := os.ReadFile(environment.paths.breakGlassLedger)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	if bytes.Contains(document, []byte("phase6 emergency reason")) || bytes.Contains(document, []byte("phase6-ticket")) {
		t.Fatal("break-glass ledger retained raw reason or ticket")
	}
	auditDocument, err := os.ReadFile(environment.paths.breakGlassAudit)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditDocument, []byte("phase6 emergency reason")) || bytes.Contains(auditDocument, []byte("phase6-ticket")) {
		clear(auditDocument)
		t.Fatal("break-glass audit retained raw reason or ticket")
	}
	clear(auditDocument)
	var ledger breakglass.Ledger
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil {
		t.Fatal("decode break-glass evidence ledger")
	}
	value := slice5evidence.BreakGlassEvidence{ControllerProcesses: namedProcessCount(environment.dependencies, "break-glass-controller"),
		PersistentAuthority: true, DistinctApproversRequired: 2, MaxTTLSeconds: 900, MaxUses: 1,
		RequestRecords: len(ledger.Requests), AuditEntries: ledger.AuditCount, AuditHead: ledger.AuditHead,
		LedgerDigest: fileDigest(t, environment.paths.breakGlassLedger), AuditDigest: fileDigest(t, environment.paths.breakGlassAudit),
		HashChainedAudit: true, ReasonTicketDigestOnly: true, TargetAgentBound: true, OnlineAtomicConsume: true, MigrationDenied: true}
	for _, record := range ledger.Requests {
		if len(record.ApproverIDs) != 2 || record.Request.ReasonDigest == "" || record.Request.TicketDigest == "" || record.Request.RequesterID == record.Request.TargetAgentID {
			t.Fatal("invalid break-glass evidence record")
		}
		switch record.State {
		case breakglass.StateConsumed:
			value.ConsumedRecords++
		case breakglass.StateRevoked:
			value.RevokedRecords++
		case breakglass.StateExpired:
			value.ExpiredRecords++
		default:
			t.Fatalf("unexpected break-glass record state %s", record.State)
		}
	}
	verifyBreakGlassAudit(t, environment.paths.breakGlassAudit, ledger.AuditCount, ledger.AuditHead)
	return value
}

func verifyBreakGlassAudit(t *testing.T, path string, wantCount int64, wantHead string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4<<10), 32<<10)
	var count int64
	head := ""
	for scanner.Scan() {
		var entry breakglass.AuditEntry
		document := append([]byte(nil), scanner.Bytes()...)
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&entry) != nil || entry.Sequence != count+1 || entry.PreviousHash != head {
			clear(document)
			t.Fatal("invalid break-glass audit chain")
		}
		want := entry.EntryHash
		entry.EntryHash = ""
		if want != slice5evidence.Digest("sandbox-runtime/break-glass/audit/v1", entry) {
			clear(document)
			t.Fatal("invalid break-glass audit hash")
		}
		clear(document)
		count, head = entry.Sequence, want
	}
	if scanner.Err() != nil || count != wantCount || head != wantHead {
		t.Fatal("incomplete break-glass audit chain")
	}
}

func observePlaintextExclusion(t *testing.T, environment *gateEnvironment) slice5evidence.PlaintextExclusionEvidence {
	t.Helper()
	forbidden := make([][]byte, 0, 128)
	add := func(value []byte) {
		if len(value) >= 16 {
			forbidden = append(forbidden, append([]byte(nil), value...))
		}
	}
	add([]byte(environment.vaultRootToken))
	add(environment.admissionKey)
	add(environment.productToken)
	add(environment.breakGlassControllerKey)
	for _, key := range environment.credentialKeys {
		add(key)
	}
	for _, key := range environment.breakGlassKeys {
		add(key)
	}
	for _, materials := range environment.materials {
		for _, material := range materials {
			add(material.Bytes)
		}
	}
	type scannedItem struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
	}
	items := make([]scannedItem, 0, 64)
	matches := 0
	scan := func(name string, document []byte) {
		for _, secret := range forbidden {
			if bytes.Contains(document, secret) {
				matches++
			}
		}
		items = append(items, scannedItem{Name: name, Digest: evidenceDigest("sandbox-runtime/phase6-slice5/plaintext-item/v1", document)})
	}
	err := filepath.WalkDir(environment.paths.directory, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() || (filepath.Ext(path) != ".toml" && filepath.Ext(path) != ".json" && filepath.Ext(path) != ".log") {
			return nil
		}
		document, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(document)
		relative, _ := filepath.Rel(environment.paths.directory, path)
		scan("gate/"+filepath.ToSlash(relative), document)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"credential-ledger": environment.paths.credentialLedger, "break-glass-ledger": environment.paths.breakGlassLedger, "break-glass-audit": environment.paths.breakGlassAudit} {
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scan(name, document)
		clear(document)
	}
	processLines := 0
	processes := append([]*gateProcess(nil), environment.dependencies...)
	for _, history := range environment.roleHistory {
		processes = append(processes, history...)
	}
	processes = append(processes, environment.materialAgentHistory...)
	for index, process := range processes {
		if process == nil || process.cmd == nil || process.cmd.Process == nil {
			continue
		}
		document, err := exec.Command("ps", "-ww", "-o", "command=", "-p", strconv.Itoa(process.cmd.Process.Pid)).Output()
		if err != nil || len(bytes.TrimSpace(document)) == 0 {
			clear(document)
			continue
		}
		processLines++
		scan(fmt.Sprintf("process/%d/%s", index, process.name), document)
		clear(document)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if matches != 0 {
		t.Fatalf("plaintext exclusion found %d managed secret matches", matches)
	}
	value := slice5evidence.PlaintextExclusionEvidence{Scope: "role_configs_process_arguments_logs_control_ledgers_and_manifest",
		KnownSecretValues: len(forbidden), FilesScanned: len(items) - processLines, ProcessCommandLinesScanned: processLines,
		ForbiddenMatches: matches, DistinctOSUIDEstablished: false}
	value.ScanDigest = evidenceDigest("sandbox-runtime/phase6-slice5/plaintext-scan/v1", struct {
		Scope   string        `json:"scope"`
		Secrets int           `json:"secrets"`
		Items   []scannedItem `json:"items"`
	}{value.Scope, value.KnownSecretValues, items})
	for _, secret := range forbidden {
		clear(secret)
	}
	return value
}

func namedProcessCount(processes []*gateProcess, name string) int {
	count := 0
	for _, process := range processes {
		if process != nil && process.name == name {
			count++
		}
	}
	return count
}
