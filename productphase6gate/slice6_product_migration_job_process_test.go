//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductMigrationJobEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_MIGRATION_JOB"

// A separate, non-restarting core PID1 owns the first business DDL. The
// operator supplies no SQL password or migration SQL to this container.
func slice6RunProductMigrationJob(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, postgresID string, socketVolumes, anchorFiles map[string]string) {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(socketVolumes) != 73 || len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		t.Fatal("Product migration job has no same-run PostgreSQL or private inputs")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-migration-job")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-migration-job")
	if err != nil || materialErr != nil || authority.Network != "service-product-migration-job-postgres" ||
		authority.SourceAddress == "" || authority.Signer.SubjectDeployment != "product-migration-job" ||
		material.OwnerDeployment != "product-migration-job" {
		t.Fatal("Product migration job network or socket authority drift")
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
		t.Fatal("Product migration PID1 identity or isolated topology drift")
	}
	serviceDocument, err := run.docker(parent, "network", "inspect", service.Name)
	if err != nil {
		t.Fatal("Product migration PostgreSQL bridge unavailable")
	}
	var serviceMeta []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if json.Unmarshal(serviceDocument, &serviceMeta) != nil || len(serviceMeta) != 1 ||
		serviceMeta[0].Labels[slice6RunLabel] != run.id || len(serviceMeta[0].ID) != 64 {
		t.Fatal("Product migration bridge is not owned by this run")
	}
	serviceWithPostgres := service
	serviceWithPostgres.Principals = nil
	if _, err := observeSlice6ProfileNetworkWithExternal(parent, run, serviceMeta[0].ID,
		serviceWithPostgres, postgresID); err != nil {
		t.Fatal("Product migration bridge does not contain the same-run PostgreSQL process")
	}
	createdDedicated, err := createSlice6ProfileNetwork(parent, run, dedicated)
	if err != nil {
		t.Fatal("create Product migration dedicated network")
	}
	dedicatedIP, err := phase6security.Slice6DesiredEndpointAddress(dedicated.Name, job.Name)
	if err != nil {
		t.Fatal("Product migration dedicated endpoint unavailable")
	}
	privateMount, needed := phase6security.Slice6PrivateConfigMount(job.Name)
	if !needed || privateMount.Target != phase6security.Slice6PrivateConfigDirectory ||
		!slices.Equal(strings.Split(privateMount.PrivateFiles, ","),
			[]string{phase6security.Slice6PostgresPeerCRLRoleFile, phase6security.Slice6ProfileConfigFile,
				phase6security.Slice6StartupConfigFile}) {
		t.Fatal("Product migration job private startup file purpose unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompBytes, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || job.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("Product migration job seccomp source drift")
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
		t.Fatal("Product migration trust-anchor mounts unavailable")
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
			t.Fatal("Product migration job private socket mount drift")
		}
		args = append(args, "--mount", "type=volume,src="+volume+",dst="+mount.Target+",readonly")
		privateSocketCount++
	}
	if privateSocketCount != 2 || len(allowedSockets) != 2 {
		t.Fatal("Product migration job private socket count drift")
	}
	args = append(args, job.ImageReference, "--config", phase6security.Slice6PrivateConfigDirectory+"/"+
		phase6security.Slice6StartupConfigFile, "product", "migrate")
	created, err := run.docker(parent, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create independent Product migration PID1")
	}
	if _, err := run.docker(parent, "network", "connect", "--ip", dedicatedIP,
		createdDedicated.NetworkID, id); err != nil {
		t.Fatal("attach Product migration PID1 to dedicated network before DDL")
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
			Networks map[string]struct {
				NetworkID, IPAddress string
			}
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
		len(observed[0].NetworkSettings.Networks) != 2 ||
		observed[0].NetworkSettings.Networks[service.Name].NetworkID != serviceMeta[0].ID ||
		observed[0].NetworkSettings.Networks[service.Name].IPAddress != authority.SourceAddress ||
		observed[0].NetworkSettings.Networks[dedicated.Name].NetworkID != createdDedicated.NetworkID ||
		observed[0].NetworkSettings.Networks[dedicated.Name].IPAddress != dedicatedIP {
		t.Fatal("Product migration created-container identity or isolation drift")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	output, startErr := run.docker(ctx, "start", "-a", id)
	if startErr != nil {
		clear(output)
		t.Fatal("Product migration PID1 exited without a confirmed successful DDL result")
	}
	if len(output) > 64<<10 || bytes.Contains(output, []byte("postgres://")) ||
		bytes.Contains(output, []byte("PRIVATE KEY")) {
		clear(output)
		t.Fatal("Product migration PID1 emitted oversized or private output")
	}
	clear(output)
	state, err := run.docker(parent, "inspect", "-f", "{{.State.Running}}|{{.State.ExitCode}}|{{.RestartCount}}", id)
	if err != nil || strings.TrimSpace(string(state)) != "false|0|0" {
		t.Fatal("Product migration PID1 did not exit exactly once")
	}
	if _, err := run.docker(parent, "rm", id); err != nil {
		t.Fatal("remove completed Product migration PID1")
	}
	t.Log("real independent Product migrate v2 PID1 exited once after Profile-bound material, PostgreSQL signer and guarded DDL; operator ledger/ownership readback remains separate")
}
