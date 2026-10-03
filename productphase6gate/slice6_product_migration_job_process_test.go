//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductMigrationJobEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MIGRATION_JOB"
const slice6ProductMigrationPreDDLFailureEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MIGRATION_PRE_DDL_FAILURE"

type slice6MigrationNetworkEndpoint struct {
	NetworkID  string
	IPAMConfig struct{ IPv4Address string }
}

// A separate, non-restarting core PID1 owns the first business DDL. The
// operator supplies no SQL password or migration SQL to this container.
func slice6RunProductMigrationJob(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, postgresID string, socketVolumes, anchorFiles map[string]string) (resultErr error) {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(socketVolumes) != 73 || len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return errors.New("Product migration job has no same-run PostgreSQL or private inputs")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-migration-job")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-migration-job")
	if err != nil || materialErr != nil || authority.Network != "service-product-migration-job-postgres" ||
		authority.SourceAddress == "" || authority.Signer.SubjectDeployment != "product-migration-job" ||
		material.OwnerDeployment != "product-migration-job" {
		return errors.New("Product migration job network or socket authority drift")
	}
	var job phase6security.Principal
	var dedicated, service phase6security.Network
	for _, principal := range profile.Principals {
		if principal.Name == "product-migration-job" {
			job = principal
		}
	}
	for _, network := range profile.Networks {
		switch network.Name {
		case "network-product-migration-job":
			dedicated = network
		case authority.Network:
			service = network
		}
	}
	if job.Name != "product-migration-job" || job.Kind != "migration_job" ||
		job.ImageLocation != "local" || job.ImageReference != job.ImageDigest ||
		job.UID == 0 || job.GID == 0 || !job.ReadOnlyRootFilesystem || !job.NoNewPrivileges ||
		!slices.Equal(job.DroppedCapabilities, []string{"ALL"}) ||
		!slices.Equal(job.Networks, []string{dedicated.Name, service.Name}) ||
		dedicated.Name != "network-product-migration-job" || !dedicated.Internal ||
		!slices.Equal(dedicated.Principals, []string{job.Name}) || len(dedicated.ExternalServices) != 0 ||
		service.Name != authority.Network || !service.Internal ||
		!slices.Equal(service.Principals, []string{job.Name}) ||
		!slices.Equal(service.ExternalServices, []string{"postgres"}) {
		return errors.New("Product migration PID1 identity or isolated topology drift")
	}
	serviceDocument, err := run.docker(parent, "network", "inspect", service.Name)
	if err != nil {
		return errors.New("Product migration PostgreSQL bridge unavailable")
	}
	var serviceMeta []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if json.Unmarshal(serviceDocument, &serviceMeta) != nil || len(serviceMeta) != 1 ||
		serviceMeta[0].Labels[slice6RunLabel] != run.id || len(serviceMeta[0].ID) != 64 {
		return errors.New("Product migration bridge is not owned by this run")
	}
	serviceWithPostgres := service
	serviceWithPostgres.Principals = nil
	postgresIP, addressErr := phase6security.Slice6DesiredServiceEndpointAddress(service.Name, "postgres")
	if addressErr != nil || slice6VerifyMigrationPostgresBridge(serviceDocument, serviceWithPostgres,
		serviceMeta[0].ID, postgresID, postgresIP) != nil {
		return errors.New("Product migration bridge does not contain the same-run PostgreSQL process")
	}
	if os.Getenv(slice6ProductMigrationPreDDLFailureEnv) == "1" {
		return errors.New("controlled pre-DDL Product migration failure")
	}
	createdDedicated, err := createSlice6ProfileNetwork(parent, run, dedicated)
	if err != nil {
		return errors.New("create Product migration dedicated network")
	}
	dedicatedIP, err := phase6security.Slice6DesiredEndpointAddress(dedicated.Name, job.Name)
	if err != nil {
		return errors.New("Product migration dedicated endpoint unavailable")
	}
	privateMount, needed := phase6security.Slice6PrivateConfigMount(job.Name)
	if !needed || privateMount.Target != phase6security.Slice6PrivateConfigDirectory ||
		!slices.Equal(strings.Split(privateMount.PrivateFiles, ","),
			[]string{phase6security.Slice6PostgresPeerCRLRoleFile, phase6security.Slice6ProfileConfigFile,
				phase6security.Slice6StartupConfigFile}) {
		return errors.New("Product migration job private startup file purpose unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return errors.New("Product migration source checkout unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompBytes, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || job.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return errors.New("Product migration job seccomp source drift")
	}
	name := "sr-p6-product-migrate-live-" + run.id
	args := []string{"create", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", serviceMeta[0].ID, "--ip", authority.SourceAddress,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", job.UID, job.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(job.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(job.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(job.Resources.PIDs, 10),
		"--mount", "type=volume,src=sr-p6-config-" + job.Name + "-" + run.id + ",dst=" + privateMount.Target + ",readonly"}
	anchors, err := slice6AnchorMountArguments(profile, job.Name, anchorFiles)
	if err != nil {
		return errors.New("Product migration trust-anchor mounts unavailable")
	}
	args = append(args, anchors...)
	allowedSockets := map[string]bool{material.SocketStorageID: true,
		authority.Signer.SocketStorageID: true}
	privateSocketCount := 0
	for _, mount := range job.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		volume := socketVolumes[mount.StorageID]
		if !allowedSockets[mount.StorageID] || volume == "" || !mount.ReadOnly {
			return errors.New("Product migration job private socket mount drift")
		}
		args = append(args, "--mount", "type=volume,src="+volume+",dst="+mount.Target+",readonly")
		privateSocketCount++
	}
	if privateSocketCount != 2 || len(allowedSockets) != 2 {
		return errors.New("Product migration job private socket count drift")
	}
	args = append(args, job.ImageReference, "--config", phase6security.Slice6PrivateConfigDirectory+"/"+
		phase6security.Slice6StartupConfigFile, "product", "migrate")
	created, err := run.docker(parent, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return errors.New("create independent Product migration PID1")
	}
	defer func() {
		cleanup := &slice6CleanupSequence{stages: []slice6CleanupStage{
			{"remove-product-migration-job", func(ctx context.Context) error {
				if _, err := run.docker(ctx, "rm", "-f", id); err != nil {
					return errors.New("Product migration PID1 removal unconfirmed")
				}
				return nil
			}},
		}}
		resultErr = errors.Join(resultErr, cleanup.Run())
	}()
	if _, err := run.docker(parent, "network", "connect", "--ip", dedicatedIP,
		createdDedicated.NetworkID, id); err != nil {
		return errors.New("attach Product migration PID1 to dedicated network before DDL")
	}
	inspection, err := run.docker(parent, "inspect", id)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			Image, User string
			Entrypoint  []string
			Cmd         []string
		} `json:"Config"`
		HostConfig struct {
			ReadonlyRootfs, Privileged  bool
			Memory, NanoCpus, PidsLimit int64
			NetworkMode                 string
			CapDrop                     []string
			SecurityOpt                 []string
			RestartPolicy               struct{ Name string }
			LogConfig                   struct{ Type string }
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]slice6MigrationNetworkEndpoint
		}
	}
	if err != nil || json.Unmarshal(inspection, &observed) != nil || len(observed) != 1 ||
		observed[0].Image != job.ImageDigest || observed[0].Config.Image != job.ImageReference ||
		observed[0].Config.User != fmt.Sprintf("%d:%d", job.UID, job.GID) ||
		!slices.Equal(observed[0].Config.Entrypoint, []string{"/usr/local/bin/phase6-role"}) ||
		!slices.Equal(observed[0].Config.Cmd, []string{"--config", phase6security.Slice6PrivateConfigDirectory + "/" +
			phase6security.Slice6StartupConfigFile, "product", "migrate"}) ||
		!observed[0].HostConfig.ReadonlyRootfs || observed[0].HostConfig.Privileged ||
		observed[0].HostConfig.Memory != job.Resources.MemoryBytes ||
		observed[0].HostConfig.NanoCpus != job.Resources.CPUMillis*1_000_000 ||
		observed[0].HostConfig.PidsLimit != job.Resources.PIDs ||
		observed[0].HostConfig.NetworkMode != serviceMeta[0].ID ||
		!slices.Contains(observed[0].HostConfig.CapDrop, "ALL") ||
		!slices.Contains(observed[0].HostConfig.SecurityOpt, "no-new-privileges:true") ||
		observed[0].HostConfig.RestartPolicy.Name != "no" ||
		observed[0].HostConfig.LogConfig.Type != "none" ||
		len(observed[0].NetworkSettings.Networks) != 2 {
		return errors.New("Product migration created-container identity or isolation drift")
	}
	if slice6ValidateMigrationCreatedNetworks(observed[0].NetworkSettings.Networks,
		serviceMeta[0].ID, service.Name, authority.SourceAddress,
		createdDedicated.NetworkID, dedicated.Name, dedicatedIP) != nil {
		return errors.New("Product migration pre-start static network bindings drift")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	output, startErr, overflow := slice6DockerBounded(ctx, 16<<10, nil, "start", "-a", id)
	if startErr != nil {
		category := slice6MigrationFailureCategory(output)
		metadata := slice6MigrationOutputMetadata(output)
		var commandExit *exec.ExitError
		if category == "unknown" && !errors.As(startErr, &commandExit) {
			category = "docker-transport"
		}
		if overflow {
			category = "output-limit"
		} else if ctx.Err() != nil {
			category = "start-timeout-or-cancel"
		}
		clear(output)
		return slice6ProductMigrationUnknownOutcome(run, id, postgresID, category, metadata)
	}
	metadata := slice6MigrationOutputMetadata(output)
	if bytes.Contains(output, []byte("postgres://")) ||
		bytes.Contains(output, []byte("PRIVATE KEY")) {
		clear(output)
		return slice6ProductMigrationUnknownOutcome(run, id, postgresID, "private-output", metadata)
	}
	clear(output)
	state, err, overflow := slice6DockerBounded(parent, 128, nil, "inspect", "-f",
		"{{.State.Running}}|{{.State.ExitCode}}|{{.RestartCount}}", id)
	stateValue := strings.TrimSpace(string(state))
	clear(state)
	if err != nil || overflow || stateValue != "false|0|0" {
		return slice6ProductMigrationUnknownOutcome(run, id, postgresID, "exit-state", metadata)
	}
	observedState, ledgerStatus, observeErr := slice6ObserveFailedProductMigration(run, id, postgresID)
	if observeErr != nil || observedState != "exited|0|false|0|started-set|finished-set|state-error-none" ||
		ledgerStatus != "ledger-and-catalog-exact" {
		return fmt.Errorf("Product migration PID1 successful exit lacks exact read-only ledger: state=%s ledger=%s", observedState, ledgerStatus)
	}
	t.Log("real independent Product migrate v2 PID1 exited once after Profile-bound material, PostgreSQL signer and guarded DDL; exact removal and operator ledger/ownership readback remain separate")
	return nil
}

func slice6ProductMigrationUnknownOutcome(run slice6DockerRun, id, postgresID, category, metadata string) error {
	state, ledger, observeErr := slice6ObserveFailedProductMigration(run, id, postgresID)
	if observeErr != nil {
		return fmt.Errorf("Product migration PID1 lacks confirmed DDL: category=%s output=%s state=%s ledger=%s observation=unconfirmed", category, metadata, state, ledger)
	}
	return fmt.Errorf("Product migration PID1 lacks confirmed DDL: category=%s output=%s state=%s ledger=%s", category, metadata, state, ledger)
}

// Never retain process text, even when its category is unknown. These finite
// shape/length buckets distinguish a duplicated CLI line from a closed stage
// mismatch without projecting any content or permitting a first-line parse.
func slice6MigrationOutputMetadata(output []byte) string {
	length := "1-64"
	switch {
	case len(output) == 0:
		length = "0"
	case len(output) > 512:
		length = "513-plus"
	case len(output) > 256:
		length = "257-512"
	case len(output) > 128:
		length = "129-256"
	case len(output) > 64:
		length = "65-128"
	}
	shape := "one-no-lf"
	switch {
	case len(output) == 0:
		shape = "empty"
	case bytes.ContainsAny(output, "\r\x00"):
		shape = "control"
	case bytes.Count(output, []byte{'\n'}) == 1 && output[len(output)-1] == '\n':
		shape = "one-lf"
	case bytes.Contains(output, []byte{'\n'}):
		shape = "multi-line"
	}
	return shape + "/" + length
}

// Never print the CLI's raw output: it could contain DSNs or key material.
// The exact allowlist and read-only SQL summary separate a pre-DDL failure
// from an unknown/partial transaction without automatically replaying DDL.
func slice6MigrationFailureCategory(output []byte) string {
	if len(output) == 0 || len(output) > 512 {
		return "unknown"
	}
	line := bytes.TrimSuffix(output, []byte{'\n'})
	if bytes.ContainsAny(line, "\n\r\x00") {
		return "unknown"
	}
	const peerPrefix = "migration v2 PostgreSQL connection is unavailable: stage=peer-bootstrap: class="
	if bytes.HasPrefix(line, []byte(peerPrefix)) {
		for _, class := range []string{
			"local-guard", "parent-canceled", "parent-deadline", "internal-deadline",
			"agent-request-build", "agent-socket-peer", "agent-transport", "agent-response",
			"guard-binding", "crl-semantic", "unknown",
		} {
			if string(line) == peerPrefix+class {
				return "migration-connect-peer-bootstrap-" + class
			}
		}
		return "unknown"
	}
	const pingPrefix = "migration v2 PostgreSQL readiness is unavailable: stage=ping: class="
	if bytes.HasPrefix(line, []byte(pingPrefix)) {
		for _, class := range []string{
			"caller-canceled", "caller-deadline", "before-connect", "exact-dial",
			"tls-or-guard", "after-connect-sql", "server-rejected", "pool-acquire",
			"ping-query", "unknown",
		} {
			if string(line) == pingPrefix+class {
				return "migration-ping-" + class
			}
		}
		for _, class := range []string{
			"local-guard", "parent-canceled", "parent-deadline", "internal-deadline",
			"agent-request-build", "agent-socket-peer", "agent-transport", "agent-response",
			"guard-binding", "crl-semantic",
		} {
			if string(line) == pingPrefix+"peer-crl-"+class {
				return "migration-ping-peer-crl-" + class
			}
		}
		return "unknown"
	}
	for _, candidate := range []struct{ marker, category string }{
		{"Phase 6 core startup Profile is unavailable", "core-profile"},
		{"Phase 6 core startup configuration is unavailable", "core-config"},
		{"Phase 6 core startup environment overrides are forbidden", "core-env"},
		{"Phase 6 core application section is missing", "core-application"},
		{"Phase 6 core role section is missing", "core-role"},
		{"Phase 6 core config contains another role or unknown section", "core-extra-role"},
		{"Phase 6 core config section is malformed", "core-malformed"},
		{"Phase 6 core role schema or application mode is invalid", "core-schema"},
		{"Phase 6 core startup file is not owned by this process", "core-file-owner"},
		{"Phase 6 core startup file is not private and regular", "core-file-mode"},
		{"Phase 6 core startup file owner mismatch", "core-file-uid"},
		{"Phase 6 core startup file is unavailable", "core-file-read"},
		{"Phase 6 core command does not match its process identity", "core-command"},
		{"migration v2 security profile mismatch", "migration-profile"},
		{"migration v2 PostgreSQL target does not match profile", "migration-target"},
		{"migration v2 PostgreSQL peer CRL role does not match profile", "migration-peer-crl"},
		{"migration v2 material registry is unavailable", "migration-material"},
		{"migration v2 PostgreSQL connection is unavailable", "migration-connect"},
		{"migration v2 PostgreSQL connection is unavailable: stage=authority", "migration-connect-authority"},
		{"migration v2 PostgreSQL connection is unavailable: stage=signer-client", "migration-connect-signer-client"},
		{"migration v2 PostgreSQL connection is unavailable: stage=peer-role", "migration-connect-peer-role"},
		{"migration v2 PostgreSQL connection is unavailable: stage=peer-guard-construction", "migration-connect-peer-guard-construction"},
		{"migration v2 PostgreSQL connection is unavailable: stage=TLS-client", "migration-connect-TLS-client"},
		{"migration v2 PostgreSQL connection is unavailable: stage=material-resolve", "migration-connect-material-resolve"},
		{"migration v2 PostgreSQL connection is unavailable: stage=DSN-binding", "migration-connect-DSN-binding"},
		{"migration v2 PostgreSQL connection is unavailable: stage=pool-binding", "migration-connect-pool-binding"},
		{"migration v2 PostgreSQL connection is unavailable: stage=own-guard-construction", "migration-connect-own-guard-construction"},
		{"migration v2 PostgreSQL connection is unavailable: stage=own-refresh", "migration-connect-own-refresh"},
		{"migration v2 PostgreSQL connection is unavailable: stage=pool-create", "migration-connect-pool-create"},
		{"migration v2 PostgreSQL connection is unavailable: stage=monitor-start", "migration-connect-monitor-start"},
		{"migration v2 PostgreSQL readiness is unavailable", "migration-ping"},
		{"Product migration v2 requires a distinct profile-bound PostgreSQL signer", "migration-signer-config"},
		{"Product migration must contain exactly one material binding", "migration-material-config"},
		{"Product migration DSN binding is invalid", "migration-dsn-config"},
		{"Product migration PostgreSQL bounds are invalid", "migration-pg-config"},
		{"product_migration.enabled must be true", "migration-disabled"},
		{"Product migration and runtime authorities cannot share one command", "migration-role-collision"},
	} {
		if string(line) == candidate.marker {
			return candidate.category
		}
	}
	return "unknown"
}

func slice6VerifyMigrationPostgresBridge(raw []byte, expected phase6security.Network,
	networkID, postgresID, postgresIP string) error {
	if !slices.Equal(expected.ExternalServices, []string{"postgres"}) || len(postgresID) != 64 ||
		!lowerHexSlice6(postgresID) || len(networkID) != 64 || !lowerHexSlice6(networkID) {
		return errors.New("Product migration PostgreSQL bridge authority invalid")
	}
	observed, err := phase6security.ObserveDockerNetworkWithExternal(raw, expected,
		nil, map[string]string{"postgres": postgresID})
	if err != nil || observed.NetworkID != networkID || len(observed.Endpoints) != 1 ||
		observed.Endpoints[0].ContainerID != postgresID || observed.Endpoints[0].IPv4Address != postgresIP {
		return errors.New("Product migration PostgreSQL bridge observation invalid")
	}
	return nil
}

// Docker's never-started container shows requested IPAM addresses, not live
// NetworkID/IPAddress. This proves a closed pre-start request only; the
// formal effective endpoint remains a separate running-container receipt.
func slice6ValidateMigrationCreatedNetworks(networks map[string]slice6MigrationNetworkEndpoint,
	serviceID, serviceName, serviceIP, dedicatedID, dedicatedName, dedicatedIP string) error {
	if len(networks) != 2 || serviceID == dedicatedID || serviceName == dedicatedName ||
		serviceID == "" || dedicatedID == "" || serviceIP == dedicatedIP {
		return errors.New("Product migration requested network inventory invalid")
	}
	resolve := func(id, name string) (slice6MigrationNetworkEndpoint, bool) {
		byID, hasID := networks[id]
		byName, hasName := networks[name]
		if hasID == hasName {
			return slice6MigrationNetworkEndpoint{}, false
		}
		if hasID {
			return byID, true
		}
		return byName, true
	}
	service, foundService := resolve(serviceID, serviceName)
	dedicated, foundDedicated := resolve(dedicatedID, dedicatedName)
	if !foundService || !foundDedicated ||
		service.IPAMConfig.IPv4Address != serviceIP || dedicated.IPAMConfig.IPv4Address != dedicatedIP ||
		service.NetworkID != "" && service.NetworkID != serviceID ||
		dedicated.NetworkID != "" && dedicated.NetworkID != dedicatedID {
		return errors.New("Product migration requested static endpoint invalid")
	}
	return nil
}
