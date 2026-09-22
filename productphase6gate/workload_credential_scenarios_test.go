//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

func runWorkloadCredentialScenarios(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	waitFor(t, 30*time.Second, "six runtime credential renewals and migration revocation", func() bool {
		ledger, err := readGateCredentialLedger(environment.paths.credentialLedger)
		if err != nil {
			return false
		}
		runtimeRenewed := make(map[string]bool)
		migrationRevoked := make(map[string]bool)
		for _, lease := range ledger.Leases {
			if lease.Migration {
				migrationRevoked[lease.PolicyID] = lease.State == "revoked" && !lease.Renewable && lease.Revision >= 2
			} else if lease.State == "active" && lease.Renewable && lease.Revision >= 2 {
				runtimeRenewed[lease.PolicyID] = true
			}
		}
		return len(runtimeRenewed) == 6 && migrationRevoked[gateCredentialPolicyID("product-migration")] && migrationRevoked[gateCredentialPolicyID("provider-migration")]
	})

	stopGateProcess(t, environment.materialAgents["gateway"], 10*time.Second)
	waitHTTPStatus(t, environment.roles["gateway"], http.DefaultClient, gateProbeURL(environment.ports.gatewayProbe), http.StatusServiceUnavailable, 10*time.Second)
	restartedGatewayAgent := startGateMaterialAgent(t, ctx, environment, "gateway", 0)
	environment.dependencies = append(environment.dependencies, restartedGatewayAgent)
	t.Cleanup(func() { bestEffortStopGateProcess(restartedGatewayAgent) })
	waitHTTPStatus(t, environment.roles["gateway"], http.DefaultClient, gateProbeURL(environment.ports.gatewayProbe), http.StatusNoContent, 15*time.Second)

	gatewayRevisionBefore := int64(0)
	if ledger, err := readGateCredentialLedger(environment.paths.credentialLedger); err == nil {
		for _, lease := range ledger.Leases {
			if lease.PolicyID == gateCredentialPolicyID("gateway") && lease.State == "active" {
				gatewayRevisionBefore = lease.Revision
			}
		}
	}
	stopGateProcess(t, environment.credentialController, 10*time.Second)
	if _, err := os.Lstat(environment.paths.credentialSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential controller socket retained after restart stop: %v", err)
	}
	startGateCredentialController(t, ctx, environment)
	waitFor(t, 25*time.Second, "credential renewal after controller restart", func() bool {
		ledger, err := readGateCredentialLedger(environment.paths.credentialLedger)
		if err != nil {
			return false
		}
		for _, lease := range ledger.Leases {
			if lease.PolicyID == gateCredentialPolicyID("gateway") && lease.State == "active" && lease.Revision > gatewayRevisionBefore {
				return true
			}
		}
		return false
	})

	pauseContainer(t, ctx, environment.vaultContainer, true)
	waitHTTPStatus(t, environment.roles["gateway"], http.DefaultClient, gateProbeURL(environment.ports.gatewayProbe), http.StatusServiceUnavailable, 12*time.Second)
	pauseContainer(t, ctx, environment.vaultContainer, false)
	waitHTTPStatus(t, environment.roles["gateway"], http.DefaultClient, gateProbeURL(environment.ports.gatewayProbe), http.StatusNoContent, 15*time.Second)

	ledger, err := readGateCredentialLedger(environment.paths.credentialLedger)
	if err != nil {
		t.Fatal(err)
	}
	var browserLease workloadcredential.LeaseRecord
	for _, lease := range ledger.Leases {
		if lease.PolicyID == gateCredentialPolicyID("browser") && lease.State == "active" {
			browserLease = lease
		}
	}
	if browserLease.LeaseID == "" {
		t.Fatal("active Browser workload credential lease unavailable")
	}
	client, err := workloadcredential.NewProductionClient(workloadcredential.ClientConfig{
		SocketPath: environment.paths.credentialSocket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		AgentID: gateCredentialAgentID("browser"), Role: secretref.RoleBrowser, Purpose: secretref.PurposeWorkloadCredential,
		PolicyID: gateCredentialPolicyID("browser"), BindingDigest: environment.credentialBindings["browser"].Digest(), BackendID: "vault-primary",
		PrivateKey: environment.credentialKeys["browser"], OperationTimeout: 3 * time.Second, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, workloadcredential.Lease{ID: browserLease.LeaseID, Revision: browserLease.Revision}); err != nil {
		client.Close()
		t.Fatal(err)
	}
	client.Close()
	waitHTTPStatus(t, environment.roles["browser"], http.DefaultClient, gateProbeURL(environment.ports.browserProbe), http.StatusServiceUnavailable, 12*time.Second)
	stopGateProcess(t, environment.materialAgents["browser"], 10*time.Second)
	restartedBrowserAgent := startGateMaterialAgent(t, ctx, environment, "browser", 0)
	environment.dependencies = append(environment.dependencies, restartedBrowserAgent)
	t.Cleanup(func() { bestEffortStopGateProcess(restartedBrowserAgent) })
	waitHTTPStatus(t, environment.roles["browser"], http.DefaultClient, gateProbeURL(environment.ports.browserProbe), http.StatusNoContent, 15*time.Second)
}

func readGateCredentialLedger(path string) (workloadcredential.Ledger, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return workloadcredential.Ledger{}, err
	}
	defer clear(document)
	var ledger workloadcredential.Ledger
	if json.Unmarshal(document, &ledger) != nil {
		return workloadcredential.Ledger{}, errors.New("invalid credential ledger")
	}
	return ledger, nil
}

func gateProbeURL(port int) string {
	return "http://127.0.0.1:" + fmt.Sprint(port) + "/readyz"
}
