//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

type slice6PostgresEndpoint struct {
	Network phase6security.Network
	ID      string
	IP      string
}

var slice6PostgresPrivateFiles = []string{
	"bootstrap-password", "client-ca.pem", "pg_hba.conf",
	"server-ca.pem", "server-key.pem", "server.pem",
}

// The Vault root has already been revoked when this starts. The separate
// provisioning container exits before the PostgreSQL server can use its
// exclusive read-only key/config volume. This is service-start component
// evidence until actual fixed-source SQL callers and v2 terminal cleanup run.
func slice6RunPostgresServer(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, leaf slice6PostgresServerLeaf,
	work func(phase6terminalcleanup.ExternalPostgresRecord)) {
	t.Helper()
	if work == nil || phase6security.VerifySlice6DesiredFinalExternalProfile(composed.Profile) != nil ||
		leaf.Record.RunID != run.id || leaf.Record.ProfileDigest != composed.Profile.ProfileDigest ||
		leaf.Record.Digest != "" || leaf.Record.MountedLeafDigest != "" {
		t.Fatal("unreviewed PostgreSQL service startup input")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	var service phase6security.ExternalService
	for _, candidate := range composed.Profile.External {
		if candidate.Name == "postgres" {
			service = candidate
		}
	}
	if service.ImageReference == "" || service.URI != slice6PostgresServerURI ||
		!slices.Equal(service.DNSNames, []string{slice6PostgresServerDNS}) {
		t.Fatal("external PostgreSQL image or identity unavailable")
	}
	hba, err := composed.Profile.PostgresServerAuth.RenderApprovedHBA(composed.Profile.ProviderDatabases)
	if err != nil {
		t.Fatal("exact final PostgreSQL HBA unavailable")
	}
	var clientCA phase6security.TrustAnchor
	for _, anchor := range composed.Profile.TrustAnchors {
		if anchor.ID == composed.Profile.PostgresServerAuth.ClientCAAnchorID {
			clientCA = anchor
		}
	}
	clientCAPath := composed.AnchorPaths[clientCA.ID]
	clientCABytes, err := os.ReadFile(clientCAPath)
	if err != nil || composed.Profile.PostgresServerAuth.VerifyRawServerArtifacts(
		composed.Profile.ProviderDatabases, clientCA, hba, clientCABytes, time.Now().UTC()) != nil {
		t.Fatal("PostgreSQL HBA/client CA differ from source-bound Profile")
	}
	privateDir := filepath.Dir(leaf.KeyPath)
	if privateDir == "" || filepath.Dir(leaf.CertificatePath) != privateDir ||
		filepath.Dir(leaf.IssuerPath) != privateDir {
		t.Fatal("PostgreSQL key/certificate supply is not a single exact private directory")
	}
	for name, contents := range map[string][]byte{
		"pg_hba.conf": hba, "client-ca.pem": clientCABytes,
	} {
		if err := os.WriteFile(filepath.Join(privateDir, name), contents, 0o600); err != nil {
			t.Fatal("prepare exact PostgreSQL server configuration")
		}
	}
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal("generate run-owned PostgreSQL bootstrap password")
	}
	passwordHex := []byte(hex.EncodeToString(password))
	clear(password)
	if err := os.WriteFile(filepath.Join(privateDir, "bootstrap-password"), passwordHex, 0o600); err != nil {
		clear(passwordHex)
		t.Fatal("write run-private PostgreSQL bootstrap password")
	}
	clear(passwordHex)
	uid, gid := slice6PostgresImageIdentity(t, ctx, run, service.ImageReference)
	endpoints := slice6PostgresDesiredEndpoints(t, ctx, run, composed.Profile)
	configVolume, dataVolume := slice6ProvisionPostgresVolumes(t, ctx, run, privateDir, uid, gid)
	owner := fmt.Sprintf("%d:%d", uid, gid)
	for _, path := range []string{leaf.KeyPath, filepath.Join(privateDir, "bootstrap-password")} {
		if err := os.Remove(path); err != nil {
			t.Fatal("remove exact transient PostgreSQL bootstrap secret")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("transient PostgreSQL secret remained on host after volume supply")
		}
	}
	serverName := "sr-p6-postgres-" + run.id
	server, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", serverName,
		"--label", run.label(), "--network", endpoints[0].ID, "--ip", endpoints[0].IP,
		"--network-alias", slice6PostgresServerDNS, "--user", owner,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory=512m", "--cpus=1", "--pids-limit=128", "--restart=no",
		"--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=16m,uid="+strconv.Itoa(uid)+",gid="+strconv.Itoa(gid),
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,uid="+strconv.Itoa(uid)+",gid="+strconv.Itoa(gid),
		"--mount", "type=volume,src="+configVolume+",dst=/pg,readonly",
		"--mount", "type=volume,src="+dataVolume+",dst=/var/lib/postgresql/data",
		"-e", "POSTGRES_PASSWORD_FILE=/pg/bootstrap-password",
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata", service.ImageReference,
		"postgres", "-c", "listen_addresses=*", "-c", "ssl=on",
		"-c", "ssl_min_protocol_version=TLSv1.3", "-c", "ssl_cert_file=/pg/server.pem",
		"-c", "ssl_key_file=/pg/server-key.pem", "-c", "ssl_ca_file=/pg/client-ca.pem",
		"-c", "hba_file=/pg/pg_hba.conf")
	serverID := strings.TrimSpace(string(server))
	if err != nil || len(serverID) != 64 || !lowerHexSlice6(serverID) {
		t.Fatal("start exact run-owned PostgreSQL server")
	}
	serverStopped := false
	defer func() {
		if serverStopped {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if _, err := run.docker(cleanup, "stop", "-t", "10", serverID); err != nil {
			t.Errorf("failure-path PostgreSQL stop was not confirmed: %v", err)
		}
		if _, err := run.docker(cleanup, "rm", "-f", "-v", serverID); err != nil {
			t.Errorf("failure-path exact PostgreSQL container removal was not confirmed: %v", err)
		}
	}()
	for _, endpoint := range endpoints[1:] {
		if _, err := run.docker(ctx, "network", "connect", "--ip", endpoint.IP,
			"--alias", slice6PostgresServerDNS, endpoint.ID, serverID); err != nil {
			t.Fatal("attach PostgreSQL to one exact isolated service bridge")
		}
	}
	for _, endpoint := range endpoints {
		network := endpoint.Network
		network.Principals = nil
		raw, err := run.docker(ctx, "network", "inspect", endpoint.ID)
		observed, observeErr := phase6security.ObserveDockerNetworkWithExternal(raw, network,
			nil, map[string]string{"postgres": serverID})
		if err != nil || observeErr != nil || observed.NetworkID != endpoint.ID ||
			len(observed.Endpoints) != 1 || observed.Endpoints[0].IPv4Address != endpoint.IP {
			t.Fatal("PostgreSQL service bridge or endpoint drifted")
		}
	}
	slice6WaitPostgresReady(t, ctx, run, serverID, owner)
	var mountedCertificate []byte
	for name, expected := range map[string][]byte{
		"pg_hba.conf": hba, "client-ca.pem": clientCABytes,
		"server.pem": leaf.Record.CertificatePEM, "server-ca.pem": leaf.Record.IssuerPEM,
	} {
		actual, err := run.docker(ctx, "exec", "-u", owner, serverID, "cat", "/pg/"+name)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("PostgreSQL server-mounted HBA/CA/certificate bytes drifted")
		}
		if name == "server.pem" {
			mountedCertificate = bytes.Clone(actual)
		}
	}
	privateFiles := slice6PostgresPrivateFiles
	entries, err := run.docker(ctx, "exec", "-u", owner, serverID, "ls", "-A", "/pg")
	observedEntries := strings.Fields(string(entries))
	slices.Sort(observedEntries)
	if err != nil || !slices.Equal(observedEntries, privateFiles) {
		t.Fatal("PostgreSQL private configuration contains an unknown file")
	}
	parentStat, err := run.docker(ctx, "exec", "-u", owner, serverID, "stat", "-c", "%u:%g:%a:%F", "/pg")
	if err != nil || strings.TrimSpace(string(parentStat)) != owner+":700:directory" {
		t.Fatal("PostgreSQL private configuration parent owner/mode drifted")
	}
	for _, name := range privateFiles {
		fileStat, err := run.docker(ctx, "exec", "-u", owner, serverID,
			"stat", "-c", "%u:%g:%a:%F", "/pg/"+name)
		if err != nil || strings.TrimSpace(string(fileStat)) != owner+":600:regular file" {
			t.Fatal("PostgreSQL private configuration file owner/mode/type drifted")
		}
	}
	mount, err := run.docker(ctx, "inspect", "-f",
		"{{range .Mounts}}{{if eq .Destination \"/pg\"}}{{.Name}}|{{.RW}}{{end}}{{end}}", serverID)
	if err != nil || strings.TrimSpace(string(mount)) != configVolume+"|false" {
		t.Fatal("PostgreSQL private configuration is not an exclusive read-only volume")
	}
	mountedLeaf := slice6VaultParsePEMCertificate(t, mountedCertificate)
	mountedDigest := sha256.Sum256(mountedLeaf.Raw)
	clear(mountedCertificate)
	record := leaf.Record
	record.MountedLeafDigest = "sha256:" + hex.EncodeToString(mountedDigest[:])
	record, err = phase6terminalcleanup.SealExternalPostgresRecord(record)
	if err != nil || record.Validate(composed.Profile, composed.PeerSources, time.Now().UTC()) != nil {
		t.Fatal("actual PostgreSQL mount cannot bind v2 terminal cleanup target")
	}
	t.Logf("same-run PostgreSQL PID1 started on nine isolated bridges with exact source-bound HBA, general-issuer server leaf, read-only PG-owned key and local SQL readiness; no client SQL gate yet; leaf=%s",
		record.LeafDigest)
	work(record)
	if _, err := run.docker(parent, "stop", "-t", "10", serverID); err != nil {
		t.Fatal("stop PostgreSQL before terminal certificate cleanup")
	}
	state, err := run.docker(parent, "inspect", "-f", "{{.State.Running}}", serverID)
	if err != nil || strings.TrimSpace(string(state)) != "false" {
		t.Fatal("PostgreSQL still serving before terminal certificate cleanup")
	}
	if _, err := run.docker(parent, "rm", "-v", serverID); err != nil {
		t.Fatal("remove stopped PostgreSQL container before terminal certificate cleanup")
	}
	serverStopped = true
	t.Log("same-run external PostgreSQL stopped and removed before v2 terminal certificate cleanup; named private/data volumes remain for final exact cleanup")
}

func slice6ProvisionPostgresVolumes(t *testing.T, ctx context.Context, run slice6DockerRun,
	privateDir string, uid, gid int) (string, string) {
	t.Helper()
	if uid != 70 || gid != 70 {
		t.Fatal("pinned external PostgreSQL image OS account changed from reviewed 70:70")
	}
	slice6ValidatePostgresHostSupply(t, privateDir)
	carrierID := slice6VerifyTerminalCarrier(t, ctx, run)
	configVolume, dataVolume := "sr-p6-postgres-config-"+run.id, "sr-p6-postgres-data-"+run.id
	for _, volume := range []string{configVolume, dataVolume} {
		if _, err := run.docker(ctx, "volume", "inspect", volume); err == nil {
			t.Fatal("run-owned PostgreSQL volume name already existed")
		}
		created, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume)
		if err != nil || strings.TrimSpace(string(created)) != volume {
			t.Fatal("create one exact fresh PostgreSQL volume")
		}
		inspection, err := run.docker(ctx, "volume", "inspect", volume)
		var observed []struct {
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
		}
		if err != nil || json.Unmarshal(inspection, &observed) != nil || len(observed) != 1 ||
			observed[0].Name != volume || observed[0].Labels[slice6RunLabel] != run.id {
			t.Fatal("new PostgreSQL volume ownership label drifted")
		}
	}
	preparerName := "sr-p6-postgres-prepare-" + run.id
	preparer, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", preparerName,
		"--label", run.label(), "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--read-only", "--log-driver=none", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+configVolume+",dst=/pg,volume-nocopy",
		"--mount", "type=volume,src="+dataVolume+",dst=/data,volume-nocopy",
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-c", "sleep 120")
	preparerID := strings.TrimSpace(string(preparer))
	if err != nil || len(preparerID) != 64 || !lowerHexSlice6(preparerID) {
		t.Fatal("start finite networkless PostgreSQL volume provisioner")
	}
	slice6VerifyPostgresProvisioner(t, ctx, run, preparerID, carrierID, configVolume, dataVolume)
	for _, directory := range []string{"/pg", "/data"} {
		contents, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "ls", "-A", directory)
		if err != nil || len(bytes.TrimSpace(contents)) != 0 {
			t.Fatal("fresh PostgreSQL volume was not empty before provision")
		}
	}
	if _, err := run.docker(ctx, "cp", privateDir+"/.", preparerID+":/pg/"); err != nil {
		t.Fatal("copy exact validated PostgreSQL material into private volume")
	}
	contents, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "ls", "-A", "/pg")
	observedNames := strings.Fields(string(contents))
	slices.Sort(observedNames)
	if err != nil || !slices.Equal(observedNames, slice6PostgresPrivateFiles) {
		t.Fatal("PostgreSQL provisioner copied an unexpected file")
	}
	for _, name := range slice6PostgresPrivateFiles {
		info, err := run.docker(ctx, "exec", "-u", "0:0", preparerID,
			"stat", "-c", "%u:%g:%F", "/pg/"+name)
		ownerType := strings.TrimSpace(string(info))
		hostOwnerType := fmt.Sprintf("%d:%d:regular file", os.Getuid(), os.Getgid())
		if err != nil || ownerType != "0:0:regular file" && ownerType != hostOwnerType {
			t.Fatalf("Docker copy file %s owner/type drifted: %q", name, strings.TrimSpace(string(info)))
		}
	}
	parentInfo, err := run.docker(ctx, "exec", "-u", "0:0", preparerID,
		"stat", "-c", "%u:%g:%F", "/pg")
	if err != nil || strings.TrimSpace(string(parentInfo)) != "0:0:directory" {
		t.Fatal("PostgreSQL private volume parent changed ownership during copy")
	}
	if _, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "chmod", "0700", "/pg", "/data"); err != nil {
		t.Fatal("set PostgreSQL volume parent mode before ownership transfer")
	}
	owner := fmt.Sprintf("%d:%d", uid, gid)
	for _, name := range slice6PostgresPrivateFiles {
		path := "/pg/" + name
		if _, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "chown", "0:0", path); err != nil {
			t.Fatal("normalize one exact Docker-copied file to provisioner ownership")
		}
		if _, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "chmod", "0600", path); err != nil {
			t.Fatal("set exact PostgreSQL file mode before ownership transfer")
		}
		if _, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "chown", owner, path); err != nil {
			t.Fatal("transfer one exact PostgreSQL file to pinned PG owner")
		}
	}
	if _, err := run.docker(ctx, "exec", "-u", "0:0", preparerID, "chown", owner, "/pg", "/data"); err != nil {
		t.Fatal("transfer exact PostgreSQL parent directories last")
	}
	slice6ObservePostgresSuppliedVolumes(t, ctx, run, configVolume, dataVolume, owner)
	if _, err := run.docker(ctx, "rm", "-f", "-v", preparerID); err != nil {
		t.Fatal("remove finite PostgreSQL provisioner")
	}
	if _, err := run.docker(ctx, "inspect", preparerID); err == nil {
		t.Fatal("PostgreSQL provisioner remained after material handoff")
	}
	return configVolume, dataVolume
}

func slice6ValidatePostgresHostSupply(t *testing.T, directory string) {
	t.Helper()
	parent, err := os.Lstat(directory)
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 || parent.Mode()&os.ModeSymlink != 0 {
		t.Fatal("PostgreSQL transient host directory is not private and ordinary")
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	root, rootErr := os.Lstat(filepath.Dir(directory))
	if !ok || parentStat.Uid != uint32(os.Getuid()) || parentStat.Gid != uint32(os.Getgid()) ||
		rootErr != nil || !root.IsDir() || root.Mode().Perm() != 0o700 || root.Mode()&os.ModeSymlink != 0 {
		t.Fatal("PostgreSQL transient host parent ownership or ancestor changed")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(slice6PostgresPrivateFiles) {
		t.Fatal("PostgreSQL transient host material inventory changed")
	}
	for index, entry := range entries {
		if entry.Name() != slice6PostgresPrivateFiles[index] {
			t.Fatal("PostgreSQL transient host material has an unexpected name")
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			info.Size() < 1 || info.Size() > 64<<10 {
			t.Fatal("PostgreSQL transient host material type, mode or size drifted")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) ||
			stat.Gid != uint32(os.Getgid()) {
			t.Fatal("PostgreSQL transient host material is not single-linked and owned by this run")
		}
	}
}

func slice6VerifyPostgresProvisioner(t *testing.T, ctx context.Context, run slice6DockerRun,
	id, carrierID, configVolume, dataVolume string) {
	t.Helper()
	document, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			User   string            `json:"User"`
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode, LogConfigType   string
			ReadonlyRootfs, Privileged   bool
			CapDrop, CapAdd, SecurityOpt []string
			Memory, NanoCPUs, PidsLimit  int64
			PortBindings                 map[string]any
			RestartPolicy                struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			LogConfig struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
			Mounts []struct {
				Type, Source, Target string
				VolumeOptions        struct {
					NoCopy bool `json:"NoCopy"`
				} `json:"VolumeOptions"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type, Name, Destination string
			RW                      bool `json:"RW"`
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(document, &observed) != nil || len(observed) != 1 {
		t.Fatal("PostgreSQL provisioner inspect unavailable")
	}
	value := observed[0]
	if value.Image != carrierID || value.Config.Image != slice6PinnedAlpineImage ||
		value.Config.User != "0:0" || value.Config.Labels[slice6RunLabel] != run.id ||
		value.HostConfig.NetworkMode != "none" || !value.HostConfig.ReadonlyRootfs ||
		value.HostConfig.Privileged || !slices.Equal(value.HostConfig.CapDrop, []string{"ALL"}) ||
		!slices.Equal(value.HostConfig.CapAdd, []string{"CAP_CHOWN"}) ||
		!slices.Contains(value.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		slices.Contains(value.HostConfig.SecurityOpt, "seccomp=unconfined") ||
		value.HostConfig.Memory != 64<<20 || value.HostConfig.NanoCPUs != 500000000 ||
		value.HostConfig.PidsLimit != 16 || len(value.HostConfig.PortBindings) != 0 ||
		value.HostConfig.LogConfig.Type != "none" || value.HostConfig.RestartPolicy.Name != "no" ||
		len(value.Mounts) != 2 || len(value.HostConfig.Mounts) != 2 {
		t.Fatalf("effective PostgreSQL provisioner boundary drifted: image_match=%t user=%q label_match=%t network=%q ro=%t privileged=%t drop=%v add=%v security=%v memory=%d nano_cpus=%d pids=%d ports=%d log=%q restart=%q mounts=%d declared=%d",
			value.Image == carrierID && value.Config.Image == slice6PinnedAlpineImage,
			value.Config.User, value.Config.Labels[slice6RunLabel] == run.id,
			value.HostConfig.NetworkMode, value.HostConfig.ReadonlyRootfs,
			value.HostConfig.Privileged, value.HostConfig.CapDrop, value.HostConfig.CapAdd,
			value.HostConfig.SecurityOpt, value.HostConfig.Memory, value.HostConfig.NanoCPUs,
			value.HostConfig.PidsLimit, len(value.HostConfig.PortBindings),
			value.HostConfig.LogConfig.Type, value.HostConfig.RestartPolicy.Name,
			len(value.Mounts), len(value.HostConfig.Mounts))
	}
	for index, expected := range []struct{ name, path string }{{configVolume, "/pg"}, {dataVolume, "/data"}} {
		mount := value.Mounts[index]
		declared := value.HostConfig.Mounts[index]
		if mount.Type != "volume" || mount.Name != expected.name ||
			mount.Destination != expected.path || !mount.RW ||
			declared.Type != "volume" || declared.Source != expected.name ||
			declared.Target != expected.path || !declared.VolumeOptions.NoCopy {
			t.Fatal("PostgreSQL provisioner received an unreviewed mount")
		}
	}
}

func slice6ObservePostgresSuppliedVolumes(t *testing.T, ctx context.Context, run slice6DockerRun,
	configVolume, dataVolume, owner string) {
	t.Helper()
	output, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network=none",
		"--label", run.label(), "--user", owner, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=32m",
		"--cpus=0.25", "--pids-limit=16",
		"--mount", "type=volume,src="+configVolume+",dst=/pg,readonly,volume-nocopy",
		"--mount", "type=volume,src="+dataVolume+",dst=/data,readonly,volume-nocopy",
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
		`test "$(stat -c '%u:%g:%a:%F' /pg)" = '70:70:700:directory' && `+
			`test "$(stat -c '%u:%g:%a:%F' /data)" = '70:70:700:directory' && `+
			`test -z "$(ls -A /data)" && `+
			`for f in bootstrap-password client-ca.pem pg_hba.conf server-ca.pem server-key.pem server.pem; do `+
			`test "$(stat -c '%u:%g:%a:%F' /pg/$f)" = '70:70:600:regular file' && test -r /pg/$f || exit 1; done; `+
			`test "$(ls -A /pg | wc -l)" -eq 6 && echo ok`)
	if err != nil || strings.TrimSpace(string(output)) != "ok" {
		t.Fatal("unprivileged PostgreSQL owner could not observe exact private volume handoff")
	}
}

func slice6PostgresImageIdentity(t *testing.T, ctx context.Context, run slice6DockerRun,
	image string) (int, int) {
	t.Helper()
	read := func(flag string) int {
		output, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network=none",
			"--label", run.label(), "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--memory=32m", "--cpus=0.25",
			"--pids-limit=16", "--mount", "type=tmpfs,dst=/var/lib/postgresql/data",
			"--entrypoint=id", image, flag, "postgres")
		if err != nil {
			t.Fatal("inspect actual pinned PostgreSQL OS account")
		}
		value, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
		if parseErr != nil || value < 1 || value > 65535 {
			t.Fatal("invalid pinned PostgreSQL OS account")
		}
		return value
	}
	return read("-u"), read("-g")
}

func slice6PostgresDesiredEndpoints(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile) []slice6PostgresEndpoint {
	t.Helper()
	byName := make(map[string]phase6security.Network, len(profile.Networks))
	for _, network := range profile.Networks {
		byName[network.Name] = network
	}
	endpoints := make([]slice6PostgresEndpoint, 0, 9)
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		network := byName[path.Network]
		ip, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
		if err != nil || network.Name != path.Network || !network.Internal ||
			network.GatewayModeIPv4 != "isolated" ||
			!slices.Equal(network.Principals, []string{path.Dialer}) ||
			!slices.Equal(network.ExternalServices, []string{"postgres"}) {
			t.Fatal("unreviewed PostgreSQL service bridge")
		}
		created, err := createSlice6ProfileNetwork(ctx, run, network)
		if err != nil {
			t.Fatal("create exact PostgreSQL service bridge")
		}
		endpoints = append(endpoints, slice6PostgresEndpoint{Network: network, ID: created.NetworkID, IP: ip})
	}
	if len(endpoints) != 9 {
		t.Fatal("final shared PostgreSQL must have exactly nine isolated source bridges")
	}
	return endpoints
}

func slice6WaitPostgresReady(t *testing.T, parent context.Context, run slice6DockerRun,
	serverID, owner string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		response, err := run.docker(ctx, "exec", "-u", owner, serverID, "psql", "-At",
			"-d", "postgres", "-c", "SELECT 1")
		if err == nil && strings.TrimSpace(string(response)) == "1" {
			for setting, want := range map[string]string{
				"ssl": "on", "hba_file": "/pg/pg_hba.conf",
				"ssl_min_protocol_version": "TLSv1.3", "listen_addresses": "*",
				"ssl_cert_file": "/pg/server.pem", "ssl_key_file": "/pg/server-key.pem",
				"ssl_ca_file": "/pg/client-ca.pem",
			} {
				actual, readErr := run.docker(ctx, "exec", "-u", owner, serverID, "psql", "-At",
					"-d", "postgres", "-c", "SHOW "+setting)
				if readErr != nil || strings.TrimSpace(string(actual)) != want {
					t.Fatal("PostgreSQL live SSL/HBA setting drifted")
				}
			}
			count, readErr := run.docker(ctx, "exec", "-u", owner, serverID, "psql", "-At",
				"-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")
			if readErr != nil || strings.TrimSpace(string(count)) != "0" {
				t.Fatal("PostgreSQL rejected source-bound HBA")
			}
			count, readErr = run.docker(ctx, "exec", "-u", owner, serverID, "psql", "-At",
				"-d", "postgres", "-c", "SELECT count(*) FROM pg_hba_file_rules")
			if readErr != nil || strings.TrimSpace(string(count)) != "12" {
				t.Fatal("PostgreSQL parsed an unexpected HBA rule count")
			}
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("run-owned PostgreSQL did not reach bounded local readiness")
}
