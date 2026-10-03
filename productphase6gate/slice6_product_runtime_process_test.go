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
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ProductRuntimeProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_RUNTIME_PROCESS"

type slice6ProductRuntimeEndpoint struct {
	Network phase6security.Network
	ID      string
	IP      string
}

// The component observer is deliberately outside the formal Profile. It has
// only ingress-product and observes one fixed Product IP, never a reserved
// relay identity or a guest/SQL/credential network.
func slice6RunProductRuntimePID1(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, postgresID string, socketVolumes, anchorFiles map[string]string,
	observer slice6ProductRuntimeObserver, receipts *slice6GuestReceiptPair,
	onReady func(string) error) (resultErr error) {
	t.Helper()
	budget := 4 * time.Minute
	if onReady != nil {
		// The live dependent chain includes Guest signers, break-glass
		// recovery and possibly Guest PID1; Product must outlive that chain.
		budget = 12 * time.Minute
	}
	runtimeContext, cancelRuntime := context.WithTimeout(parent, budget)
	defer cancelRuntime()
	parent = runtimeContext
	plan, err := slice6BuildProductRuntimeLaunchPlan(composed.Profile)
	if err != nil || len(socketVolumes) != 74 || len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return errors.New("Product runtime same-run authority unavailable")
	}
	var receiptConfigDigest string
	if composed.PrivateGuestReceipt {
		if receipts == nil || onReady == nil {
			return errors.New("Product private Guest receipt chain unavailable")
		}
		startup, configErr := slice6BuildProductRuntimeConfig(composed)
		if configErr != nil {
			return errors.New("Product private Guest receipt startup authority unavailable")
		}
		receiptConfigDigest = slice6ReceiptConfigDigest(startup)
		clear(startup)
	}
	if err := slice6VerifyApprovedProductRuntimeObserver(observer); err != nil {
		return err
	}
	profile := composed.Profile
	serviceRaw, err := run.docker(parent, "network", "inspect", plan.ServiceNetwork.Name)
	if err != nil {
		return errors.New("Product runtime PostgreSQL bridge unavailable")
	}
	var service []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	postgresIP, ipErr := phase6security.Slice6DesiredServiceEndpointAddress(plan.ServiceNetwork.Name, "postgres")
	serviceWithoutProduct := plan.ServiceNetwork
	serviceWithoutProduct.Principals = nil
	if json.Unmarshal(serviceRaw, &service) != nil || len(service) != 1 ||
		service[0].Labels[slice6RunLabel] != run.id || ipErr != nil ||
		slice6VerifyMigrationPostgresBridge(serviceRaw, serviceWithoutProduct,
			service[0].ID, postgresID, postgresIP) != nil {
		return errors.New("Product runtime bridge does not contain exact same-run PostgreSQL PID1")
	}
	endpoints := make([]slice6ProductRuntimeEndpoint, 0, len(plan.Networks))
	endpoints = append(endpoints, slice6ProductRuntimeEndpoint{Network: plan.ServiceNetwork,
		ID: service[0].ID, IP: plan.SourceAddress})
	for _, network := range plan.Networks {
		if network.Name == plan.ServiceNetwork.Name {
			continue
		}
		created, createErr := createSlice6ProfileNetwork(parent, run, network)
		ip, addressErr := phase6security.Slice6DesiredEndpointAddress(network.Name, plan.Principal.Name)
		if createErr != nil || addressErr != nil {
			return errors.New("Product runtime Profile network creation failed")
		}
		endpoints = append(endpoints, slice6ProductRuntimeEndpoint{Network: network,
			ID: created.NetworkID, IP: ip})
	}
	if len(endpoints) != 7 {
		return errors.New("Product runtime network count drift")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return errors.New("Product runtime source checkout unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompBytes, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return errors.New("Product runtime seccomp source drift")
	}
	privateMount, present := phase6security.Slice6PrivateConfigMount(plan.Principal.Name)
	if !present {
		return errors.New("Product runtime private config mount unavailable")
	}
	name := "sr-p6-product-runtime-" + run.id
	owner := fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID)
	args := []string{"create", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", endpoints[0].ID, "--ip", endpoints[0].IP,
		"--restart=no", "--user", owner, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(plan.Principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(plan.Principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(plan.Principal.Resources.PIDs, 10),
		"--mount", "type=volume,src=sr-p6-config-" + plan.Principal.Name + "-" + run.id +
			",dst=" + privateMount.Target + ",readonly"}
	anchorArgs, err := slice6AnchorMountArguments(profile, plan.Principal.Name, anchorFiles)
	if err != nil {
		return errors.New("Product runtime trust anchors unavailable")
	}
	args = append(args, anchorArgs...)
	seenSockets := make(map[string]bool, 3)
	for _, mount := range plan.Principal.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		if !slices.Contains(plan.SocketStorageID, mount.StorageID) || !mount.ReadOnly ||
			socketVolumes[mount.StorageID] == "" || seenSockets[mount.StorageID] {
			return errors.New("Product runtime private socket mount drift")
		}
		seenSockets[mount.StorageID] = true
		args = append(args, "--mount", "type=volume,src="+socketVolumes[mount.StorageID]+
			",dst="+mount.Target+",readonly")
	}
	if len(seenSockets) != 3 {
		return errors.New("Product runtime private socket set incomplete")
	}
	args = append(args, plan.Principal.ImageReference, "--config", privateMount.Target+"/"+
		phase6security.Slice6StartupConfigFile, "product", "serve")
	created, err := run.docker(parent, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return errors.New("create independent Product runtime PID1")
	}
	defer func() {
		cleanup := &slice6CleanupSequence{stages: []slice6CleanupStage{
			{"remove-product-runtime", func(ctx context.Context) error {
				if _, err := run.docker(ctx, "rm", "-f", "-v", id); err != nil {
					return errors.New("Product runtime PID1 removal unconfirmed")
				}
				return nil
			}},
		}}
		resultErr = errors.Join(resultErr, cleanup.Run())
	}()
	for _, endpoint := range endpoints[1:] {
		if _, err := run.docker(parent, "network", "connect", "--ip", endpoint.IP, endpoint.ID, id); err != nil {
			return errors.New("attach Product runtime to exact isolated Profile bridge")
		}
	}
	if err := slice6VerifyProductRuntimeContainer(parent, run, id, plan, endpoints, seccomp,
		socketVolumes, anchorFiles, profile); err != nil {
		return err
	}
	var receiptCapture *slice6GuestReceiptCapture
	if composed.PrivateGuestReceipt {
		receiptCapture, err = slice6StartGuestReceiptCapture(t, parent, id, "product",
			profile.ProfileDigest, receiptConfigDigest)
		if err != nil {
			return errors.New("start attached Product runtime PID1 receipt capture")
		}
		defer receiptCapture.abort()
	} else if _, err := run.docker(parent, "start", id); err != nil {
		return errors.New("start independent Product runtime PID1")
	}
	initialReady, err := slice6ObserveProductReady(parent, run, profile, plan, endpoints,
		anchorFiles, observer, http.StatusOK, 20)
	if err != nil {
		return err
	}
	if err := slice6VerifyProductRuntimeSQLSession(parent, postgresID, plan.SourceAddress); err != nil {
		return err
	}
	baseline, err := slice6ObserveProductRuntimeFaultState(parent, run, id, postgresID, endpoints, true)
	if err != nil {
		return err
	}
	// Disconnect only Product's PostgreSQL edge. The same PG PID1 and its
	// other service bridges continue; the exact IP is restored below.
	if _, err := run.docker(parent, "network", "disconnect", endpoints[0].ID, id); err != nil {
		return errors.New("Product runtime SQL-dependency disconnect failed")
	}
	disconnectedAt := time.Now()
	if err := slice6AssertProductRuntimeFaultState(parent, run, id, postgresID, endpoints, false, baseline); err != nil {
		return err
	}
	reconnected := false
	defer func() {
		if !reconnected {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, reconnectErr := run.docker(cleanup, "network", "connect", "--ip", endpoints[0].IP,
				endpoints[0].ID, id); reconnectErr != nil {
				resultErr = errors.Join(resultErr, errors.New("failure-path Product SQL bridge recovery unconfirmed"))
			} else if observeErr := slice6AssertProductRuntimeFaultState(cleanup, run, id, postgresID,
				endpoints, true, baseline); observeErr != nil {
				resultErr = errors.Join(resultErr, errors.New("failure-path Product SQL bridge endpoint recovery drift"))
			}
		}
	}()
	notReady, err := slice6ObserveProductReady(parent, run, profile, plan, endpoints,
		anchorFiles, observer, http.StatusServiceUnavailable, 20)
	if err != nil {
		return err
	}
	connectionLossObservedAfter := time.Since(disconnectedAt)
	if err := slice6AssertProductRuntimeFaultState(parent, run, id, postgresID, endpoints, false, baseline); err != nil {
		return err
	}
	if _, err := run.docker(parent, "network", "connect", "--ip", endpoints[0].IP, endpoints[0].ID, id); err != nil {
		return errors.New("Product runtime SQL-dependency reconnect failed")
	}
	reconnectedAt := time.Now()
	reconnected = true
	if err := slice6AssertProductRuntimeFaultState(parent, run, id, postgresID, endpoints, true, baseline); err != nil {
		return err
	}
	recovered, err := slice6ObserveProductReady(parent, run, profile, plan, endpoints,
		anchorFiles, observer, http.StatusOK, 20)
	if err != nil {
		return err
	}
	connectionRecoveryObservedAfter := time.Since(reconnectedAt)
	if err := slice6VerifyProductRuntimeSQLSession(parent, postgresID, plan.SourceAddress); err != nil {
		return err
	}
	if err := slice6AssertProductRuntimeFaultState(parent, run, id, postgresID, endpoints, true, baseline); err != nil {
		return err
	}
	t.Logf("real Product serve PID1 admitted exact 7-network/3-socket Profile; verified TLS /readyz ready→SQL-edge loss not_ready→same-PG recovery ready and read-only product_runtime SQL session; observer_poll initial=%s loss=%s recovery=%s; since_network_operation loss=%s recovery=%s; component observer is not public relay or Guest",
		initialReady, notReady, recovered, connectionLossObservedAfter, connectionRecoveryObservedAfter)
	if onReady != nil {
		if err := onReady(id); err != nil {
			return errors.Join(errors.New("Product live dependent gate failed"), err)
		}
		if err := slice6AssertProductRuntimeFaultState(parent, run, id, postgresID, endpoints, true, baseline); err != nil {
			return errors.New("Product PID1 or SQL endpoint changed during dependent gate")
		}
	}
	if receiptCapture != nil {
		if err := slice6StopReceiptContainer(parent, run, id); err != nil {
			return errors.New("Product PID1 graceful receipt shutdown unavailable")
		}
		records, err := receiptCapture.verifyStopped(parent, run, id, 0)
		if err != nil {
			return errors.New("Product PID1 private Guest receipt unavailable")
		}
		receipts.Product = records
	}
	return nil
}

func slice6VerifyProductRuntimeContainer(ctx context.Context, run slice6DockerRun, id string,
	plan slice6ProductRuntimeLaunchPlan, endpoints []slice6ProductRuntimeEndpoint, seccomp string,
	socketVolumes, anchorFiles map[string]string, profile phase6security.Profile) error {
	raw, err := run.docker(ctx, "inspect", id)
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
			PortBindings                map[string]any
		} `json:"HostConfig"`
		Mounts []struct {
			Type, Name, Source, Destination string
			RW                              bool
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]slice6MigrationNetworkEndpoint
		}
	}
	private, _ := phase6security.Slice6PrivateConfigMount(plan.Principal.Name)
	seccompSource, seccompErr := os.ReadFile(seccomp)
	var canonicalSeccomp bytes.Buffer
	if seccompErr == nil {
		seccompErr = json.Compact(&canonicalSeccomp, seccompSource)
	}
	if err != nil || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 ||
		seccompErr != nil ||
		observed[0].Image != plan.Principal.ImageDigest ||
		observed[0].Config.Image != plan.Principal.ImageReference ||
		observed[0].Config.User != fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID) ||
		!slices.Equal(observed[0].Config.Entrypoint, []string{"/usr/local/bin/phase6-role"}) ||
		!slices.Equal(observed[0].Config.Cmd, []string{"--config", private.Target + "/" +
			phase6security.Slice6StartupConfigFile, "product", "serve"}) ||
		!observed[0].HostConfig.ReadonlyRootfs || observed[0].HostConfig.Privileged ||
		observed[0].HostConfig.Memory != plan.Principal.Resources.MemoryBytes ||
		observed[0].HostConfig.NanoCpus != plan.Principal.Resources.CPUMillis*1_000_000 ||
		observed[0].HostConfig.PidsLimit != plan.Principal.Resources.PIDs ||
		observed[0].HostConfig.NetworkMode != endpoints[0].ID ||
		!slices.Contains(observed[0].HostConfig.CapDrop, "ALL") ||
		!slices.Contains(observed[0].HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(observed[0].HostConfig.SecurityOpt, "seccomp="+canonicalSeccomp.String()) ||
		observed[0].HostConfig.RestartPolicy.Name != "no" ||
		observed[0].HostConfig.LogConfig.Type != "none" ||
		len(observed[0].HostConfig.PortBindings) != 0 || len(observed[0].NetworkSettings.Networks) != 7 {
		return errors.New("Product runtime created-container least-privilege or network drift")
	}
	for _, endpoint := range endpoints {
		if endpoint.Network.Name == "" || endpoint.ID == "" || endpoint.IP == "" {
			return errors.New("Product runtime endpoint manifest incomplete")
		}
		entry, ok := observed[0].NetworkSettings.Networks[endpoint.Network.Name]
		if !ok {
			entry, ok = observed[0].NetworkSettings.Networks[endpoint.ID]
		}
		if !ok || entry.IPAMConfig.IPv4Address != endpoint.IP {
			return errors.New("Product runtime created endpoint IPAM drift")
		}
	}
	type expectedMount struct{ kind, source string }
	expectedMounts := map[string]expectedMount{
		private.Target: {kind: "volume", source: "sr-p6-config-" + plan.Principal.Name + "-" + run.id},
	}
	for _, mount := range plan.Principal.Mounts {
		switch mount.Kind {
		case "private_socket":
			expectedMounts[mount.Target] = expectedMount{kind: "volume", source: socketVolumes[mount.StorageID]}
		case "trust_anchor":
			for _, anchor := range profile.TrustAnchors {
				if anchor.StorageID == mount.StorageID && anchor.TargetPath == mount.Target {
					expectedMounts[mount.Target] = expectedMount{kind: "bind", source: anchorFiles[anchor.StorageID]}
				}
			}
		}
	}
	actualMounts := make(map[string]bool, len(observed[0].Mounts))
	for _, mount := range observed[0].Mounts {
		wanted, ok := expectedMounts[mount.Destination]
		if !ok || mount.RW || actualMounts[mount.Destination] || wanted.kind != mount.Type ||
			wanted.source == "" || (mount.Type == "volume" && mount.Name != wanted.source) ||
			(mount.Type == "bind" && mount.Source != wanted.source) {
			return errors.New("Product runtime unreviewed or writable mount")
		}
		actualMounts[mount.Destination] = true
	}
	if len(actualMounts) != len(expectedMounts) || !actualMounts[private.Target] {
		return errors.New("Product runtime private mount inventory incomplete")
	}
	return nil
}

type slice6ProductRuntimeFaultState struct {
	Product  string
	Postgres string
	Signers  map[string]string
}

type slice6ProductRuntimeInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		OOMKilled bool   `json:"OOMKilled"`
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	RestartCount    int `json:"RestartCount"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func slice6InspectProductRuntimeMember(ctx context.Context, run slice6DockerRun, target string) (slice6ProductRuntimeInspect, error) {
	raw, err := run.docker(ctx, "inspect", target)
	var parsed []slice6ProductRuntimeInspect
	if err != nil || json.Unmarshal(raw, &parsed) != nil || len(parsed) != 1 {
		return slice6ProductRuntimeInspect{}, errors.New("Product runtime dependency process inspect unavailable")
	}
	member := parsed[0]
	started, startedErr := time.Parse(time.RFC3339Nano, member.State.StartedAt)
	if len(member.ID) != 64 || !lowerHexSlice6(member.ID) ||
		member.Config.Labels[slice6RunLabel] != run.id || !member.State.Running ||
		member.State.OOMKilled || member.State.Pid < 1 || member.RestartCount != 0 ||
		startedErr != nil || started.IsZero() || len(member.NetworkSettings.Networks) == 0 {
		return slice6ProductRuntimeInspect{}, errors.New("Product runtime dependency process identity or PID1 drift")
	}
	return member, nil
}

func slice6RuntimeMemberFingerprint(member slice6ProductRuntimeInspect, includeNetworks bool) string {
	fingerprint := member.ID + "|" + strconv.Itoa(member.State.Pid) + "|" + member.State.StartedAt +
		"|" + strconv.Itoa(member.RestartCount)
	if includeNetworks {
		var networks []string
		for name, endpoint := range member.NetworkSettings.Networks {
			networks = append(networks, name+"="+endpoint.NetworkID+"@"+endpoint.IPAddress)
		}
		slices.Sort(networks)
		fingerprint += "|" + strings.Join(networks, ",")
	}
	return fingerprint
}

func slice6ObserveProductRuntimeFaultState(ctx context.Context, run slice6DockerRun,
	productID, postgresID string, endpoints []slice6ProductRuntimeEndpoint,
	connected bool) (slice6ProductRuntimeFaultState, error) {
	observeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = observeContext
	if len(endpoints) != 7 || len(productID) != 64 || len(postgresID) != 64 ||
		!lowerHexSlice6(productID) || !lowerHexSlice6(postgresID) {
		return slice6ProductRuntimeFaultState{}, errors.New("Product runtime fault observation target invalid")
	}
	product, err := slice6InspectProductRuntimeMember(ctx, run, productID)
	if err != nil || product.ID != productID || product.Name != "/sr-p6-product-runtime-"+run.id {
		return slice6ProductRuntimeFaultState{}, errors.New("Product runtime PID1 replaced during SQL fault")
	}
	postgres, err := slice6InspectProductRuntimeMember(ctx, run, postgresID)
	if err != nil || postgres.ID != postgresID || postgres.Name != "/sr-p6-postgres-"+run.id {
		return slice6ProductRuntimeFaultState{}, errors.New("PostgreSQL PID1 replaced during Product SQL fault")
	}
	expectedProductNetworks := len(endpoints)
	if !connected {
		expectedProductNetworks--
	}
	if len(product.NetworkSettings.Networks) != expectedProductNetworks {
		return slice6ProductRuntimeFaultState{}, errors.New("Product runtime fault endpoint count drift")
	}
	for index, endpoint := range endpoints {
		attached := connected || index != 0
		observed, present := product.NetworkSettings.Networks[endpoint.Network.Name]
		if present != attached || present &&
			(observed.NetworkID != endpoint.ID || observed.IPAddress != endpoint.IP) {
			return slice6ProductRuntimeFaultState{}, errors.New("Product runtime fault endpoint IP or membership drift")
		}
		raw, err := run.docker(ctx, "network", "inspect", endpoint.ID)
		if err != nil {
			return slice6ProductRuntimeFaultState{}, errors.New("Product runtime fault network inspect unavailable")
		}
		want := endpoint.Network
		members := map[string]string{"product-runtime": productID}
		if index == 0 {
			if !connected {
				want.Principals = nil
				members = nil
			}
			networkObservation, observeErr := phase6security.ObserveDockerNetworkWithExternal(raw, want, members,
				map[string]string{"postgres": postgresID})
			if observeErr != nil || networkObservation.NetworkID != endpoint.ID {
				return slice6ProductRuntimeFaultState{}, errors.New("Product SQL bridge endpoint observation drift")
			}
			continue
		}
		want.Principals = []string{"product-runtime"}
		networkObservation, observeErr := phase6security.ObserveDockerNetwork(raw, want, members)
		if observeErr != nil || networkObservation.NetworkID != endpoint.ID || len(networkObservation.Endpoints) != 1 ||
			networkObservation.Endpoints[0].IPv4Address != endpoint.IP {
			return slice6ProductRuntimeFaultState{}, errors.New("Product non-SQL endpoint observation drift")
		}
	}
	state := slice6ProductRuntimeFaultState{Product: slice6RuntimeMemberFingerprint(product, false),
		Postgres: slice6RuntimeMemberFingerprint(postgres, true), Signers: make(map[string]string, 3)}
	for _, label := range []string{"product-tls", "product-runtime-postgres-tls", "product-material"} {
		name := "sr-p6-" + label + "-live-" + run.id
		member, err := slice6InspectProductRuntimeMember(ctx, run, name)
		if err != nil || member.Name != "/"+name {
			return slice6ProductRuntimeFaultState{}, errors.New("Product runtime private signer or material PID1 unavailable")
		}
		state.Signers[label] = slice6RuntimeMemberFingerprint(member, true)
	}
	return state, nil
}

func slice6AssertProductRuntimeFaultState(ctx context.Context, run slice6DockerRun,
	productID, postgresID string, endpoints []slice6ProductRuntimeEndpoint, connected bool,
	baseline slice6ProductRuntimeFaultState) error {
	observed, err := slice6ObserveProductRuntimeFaultState(ctx, run, productID, postgresID, endpoints, connected)
	if err != nil {
		return err
	}
	if observed.Product != baseline.Product || observed.Postgres != baseline.Postgres ||
		len(observed.Signers) != len(baseline.Signers) {
		return errors.New("Product, PostgreSQL or private signer PID1 changed across SQL connectivity fault")
	}
	for label, before := range baseline.Signers {
		if observed.Signers[label] != before {
			return errors.New("Product private signer process or endpoint changed across SQL connectivity fault")
		}
	}
	return nil
}

func slice6VerifyProductRuntimeSQLSession(ctx context.Context, postgresID, sourceAddress string) error {
	queryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = queryContext
	address, addressErr := netip.ParseAddr(sourceAddress)
	if len(postgresID) != 64 || !lowerHexSlice6(postgresID) || addressErr != nil ||
		!address.Is4() || address.String() != sourceAddress {
		return errors.New("Product runtime SQL observation target invalid")
	}
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\n" +
		"SELECT count(*) FILTER (WHERE client_addr='" + sourceAddress + "'::inet)::text||'|'||" +
		"count(*)::text FROM pg_catalog.pg_stat_activity " +
		"WHERE usename='product_runtime' AND datname='product' AND pid<>pg_backend_pid();\nCOMMIT;\n")
	defer clear(script)
	out, err, overflow := slice6DockerBounded(ctx, 128, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(out)
	if err != nil || overflow {
		return errors.New("Product runtime SQL session readback unavailable")
	}
	counts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(counts) != 2 {
		return errors.New("Product runtime SQL login count unavailable")
	}
	bound, boundErr := strconv.Atoi(counts[0])
	total, totalErr := strconv.Atoi(counts[1])
	if boundErr != nil || totalErr != nil || bound < 1 || bound > 4 || total != bound {
		return errors.New("Product runtime SQL login is not bound to exact Profile source on same PostgreSQL PID1")
	}
	return nil
}

type slice6ProductRuntimeObserver struct {
	Path           string
	Digest         []byte
	ExpectedDigest string
}

func slice6VerifyProductRuntimeObserverBinary(observer slice6ProductRuntimeObserver) error {
	if !filepath.IsAbs(observer.Path) || len(observer.Digest) != sha256.Size {
		return errors.New("Product runtime observer binary identity unavailable")
	}
	info, err := os.Lstat(observer.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 {
		return errors.New("Product runtime observer binary must be non-root readable and executable")
	}
	contents, err := os.ReadFile(observer.Path)
	if err != nil || len(contents) == 0 || len(contents) > 20<<20 {
		return errors.New("Product runtime observer binary unavailable")
	}
	actual := sha256.Sum256(contents)
	clear(contents)
	if !slices.Equal(actual[:], observer.Digest) {
		return errors.New("Product runtime observer binary changed after pre-issuer freeze")
	}
	return nil
}

func slice6ApproveProductRuntimeObserver(expected string, observer *slice6ProductRuntimeObserver) error {
	if observer == nil {
		return errors.New("Product runtime observer expected digest missing or non-canonical")
	}
	observer.ExpectedDigest = ""
	if len(expected) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(expected, "sha256:") || !lowerHexSlice6(strings.TrimPrefix(expected, "sha256:")) {
		return errors.New("Product runtime observer expected digest missing or non-canonical")
	}
	if err := slice6VerifyProductRuntimeObserverBinary(*observer); err != nil {
		return err
	}
	if expected != "sha256:"+hex.EncodeToString(observer.Digest) {
		return errors.New("Product runtime observer differs from externally approved digest")
	}
	observer.ExpectedDigest = expected
	return nil
}

func slice6VerifyApprovedProductRuntimeObserver(observer slice6ProductRuntimeObserver) error {
	if observer.ExpectedDigest == "" ||
		observer.ExpectedDigest != "sha256:"+hex.EncodeToString(observer.Digest) {
		return errors.New("Product runtime observer external digest approval unavailable")
	}
	return slice6VerifyProductRuntimeObserverBinary(observer)
}

func slice6BuildProductRuntimeObserver(t *testing.T, ctx context.Context, root string) (slice6ProductRuntimeObserver, error) {
	t.Helper()
	versionCommand := exec.CommandContext(ctx, "go", "version")
	versionCommand.Dir = root
	versionCommand.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	version, versionErr := versionCommand.Output()
	if versionErr != nil || !bytes.HasPrefix(version, []byte("go version go1.26.8 ")) {
		return slice6ProductRuntimeObserver{}, errors.New("Product runtime observer requires locked Go 1.26.8 toolchain")
	}
	// Docker Desktop shares the workspace checkout, not necessarily Go's
	// system test-temp directory. Keep the transient build inside this E tree.
	directory, err := os.MkdirTemp(".", ".sr-p6-product-runtime-observer-")
	if err != nil {
		return slice6ProductRuntimeObserver{}, errors.New("create Product runtime observer build directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove exact Product runtime observer build directory: %v", err)
		}
	})
	binary, err := filepath.Abs(filepath.Join(directory, "product-runtime-observer"))
	if err != nil {
		return slice6ProductRuntimeObserver{}, errors.New("Product runtime observer build path unavailable")
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binary, "./productphase6gate/testdata/productruntimeobserver")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	output, err := build.CombinedOutput()
	if err != nil {
		clear(output)
		return slice6ProductRuntimeObserver{}, errors.New("build fixed Product runtime observer")
	}
	clear(output)
	if err := os.Chmod(binary, 0o555); err != nil {
		return slice6ProductRuntimeObserver{}, errors.New("seal Product runtime observer binary read-only")
	}
	contents, err := os.ReadFile(binary)
	if err != nil || len(contents) == 0 || len(contents) > 20<<20 {
		return slice6ProductRuntimeObserver{}, errors.New("Product runtime observer binary unavailable")
	}
	digest := sha256.Sum256(contents)
	clear(contents)
	observer := slice6ProductRuntimeObserver{Path: binary, Digest: digest[:]}
	if err := slice6VerifyProductRuntimeObserverBinary(observer); err != nil {
		return slice6ProductRuntimeObserver{}, err
	}
	return observer, nil
}

// A public-only Go certificate fixture and the sealed observer binary are
// bind-read by the exact non-root UID in a networkless container before any
// Vault issuer allocation. The live Profile anchor volumes have their own
// later non-root digest/mode proof; this does not substitute for that proof.
func slice6ProbeProductRuntimeObserverMount(ctx context.Context, observer slice6ProductRuntimeObserver) (resultErr error) {
	if err := slice6VerifyApprovedProductRuntimeObserver(observer); err != nil {
		return err
	}
	fixture := filepath.Join(runtime.GOROOT(), "src", "crypto", "x509", "testdata", "nist-pkits",
		"certs", "TrustAnchorRootCertificate.crt")
	info, err := os.Lstat(fixture)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o004 == 0 {
		return errors.New("Product observer public CA read fixture unavailable")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, run.cleanup(cleanup))
	}()
	name := "sr-p6-product-observer-mount-" + run.id
	script := "set -eu; test -r /etc/product-observer-ca.pem; test -x /observer; " +
		"test \"$(/observer invalid 2>/dev/null)\" = 'product-runtime-readiness=unavailable'; " +
		"echo product-runtime-observer-mount=nonroot-readable"
	out, runErr, overflow := slice6DockerBounded(ctx, 256, nil,
		"run", "--rm", "--pull=never", "--name", name, "--label", run.label(),
		"--network=none", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
		"--mount", "type=bind,src="+observer.Path+",dst=/observer,readonly",
		"--mount", "type=bind,src="+fixture+",dst=/etc/product-observer-ca.pem,readonly",
		slice6PinnedAlpineImage, "/bin/sh", "-ec", script)
	defer clear(out)
	if runErr != nil || overflow || string(out) != "product-runtime-observer-mount=nonroot-readable\n" {
		return errors.New("Product observer non-root public CA/binary mount preflight failed")
	}
	return slice6VerifyApprovedProductRuntimeObserver(observer)
}

var slice6ProductReadinessObservationPattern = regexp.MustCompile(`^product-runtime-readiness=observed elapsed_ms=(0|[1-9][0-9]{0,5})\n$`)

func slice6ObserveProductReady(parent context.Context, run slice6DockerRun,
	profile phase6security.Profile, plan slice6ProductRuntimeLaunchPlan,
	endpoints []slice6ProductRuntimeEndpoint, anchorFiles map[string]string,
	observer slice6ProductRuntimeObserver, status, waitSeconds int) (elapsed time.Duration, resultErr error) {
	if err := slice6VerifyApprovedProductRuntimeObserver(observer); err != nil {
		return 0, err
	}
	_, _, subject, anchor, err := profile.PublicTLSBoundary("product-public", 8444)
	if err != nil || subject.Name != plan.Principal.Name || subject.TLS == nil ||
		len(subject.TLS.DNSNames) != 1 || anchorFiles[anchor.StorageID] == "" ||
		len(observer.Digest) != sha256.Size || status != http.StatusOK && status != http.StatusServiceUnavailable ||
		waitSeconds < 1 || waitSeconds > 20 {
		return 0, errors.New("Product runtime observer Profile authority unavailable")
	}
	var ingress slice6ProductRuntimeEndpoint
	for _, candidate := range endpoints {
		if candidate.Network.Name == "ingress-product" {
			ingress = candidate
		}
	}
	if ingress.ID == "" || ingress.IP == "" || !slices.Contains(ingress.Network.Principals, "public-ingress-relay") {
		return 0, errors.New("Product runtime observer ingress target unavailable")
	}
	observerIP, err := slice6ProductRuntimeObserverIP(ingress.Network)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(waitSeconds+8)*time.Second)
	defer cancel()
	name := "sr-p6-product-ready-observer-" + run.id
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		resultErr = errors.Join(resultErr, slice6EnsureProductRuntimeObserverRemoved(cleanup, run, name))
	}()
	args := []string{"run", "--rm", "--pull=never", "--name", name,
		"--label", run.label(), "--network", ingress.ID, "--ip", observerIP,
		"--user", "65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
		"--mount", "type=bind,src=" + observer.Path + ",dst=/observer,readonly",
		"--mount", "type=bind,src=" + anchorFiles[anchor.StorageID] + ",dst=/etc/product-observer-ca.pem,readonly",
		"--entrypoint=/observer", slice6PinnedAlpineImage,
		ingress.IP, subject.TLS.DNSNames[0], subject.TLS.URI, anchor.BundleDigest,
		strconv.Itoa(status), strconv.Itoa(waitSeconds)}
	out, runErr, overflow := slice6DockerBounded(ctx, 256, nil, args...)
	defer clear(out)
	match := slice6ProductReadinessObservationPattern.FindSubmatch(out)
	if runErr != nil || overflow || match == nil {
		return 0, errors.New("Product runtime authenticated TLS readiness observation failed")
	}
	millis, err := strconv.Atoi(string(match[1]))
	if err != nil || millis > waitSeconds*1000+1000 {
		return 0, errors.New("Product runtime readiness observation duration invalid")
	}
	return time.Duration(millis) * time.Millisecond, nil
}

func slice6EnsureProductRuntimeObserverRemoved(ctx context.Context, run slice6DockerRun, name string) error {
	if name != "sr-p6-product-ready-observer-"+run.id {
		return errors.New("Product readiness observer cleanup target invalid")
	}
	find := func() ([]string, error) {
		raw, err := run.docker(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name+"$")
		if err != nil {
			return nil, errors.New("Product readiness observer cleanup inventory unavailable")
		}
		ids := strings.Fields(string(raw))
		if len(ids) > 1 {
			return nil, errors.New("Product readiness observer name alias")
		}
		for _, id := range ids {
			if len(id) != 64 || !lowerHexSlice6(id) {
				return nil, errors.New("Product readiness observer cleanup ID invalid")
			}
		}
		return ids, nil
	}
	ids, err := find()
	if err != nil || len(ids) == 0 {
		return err
	}
	identity, inspectErr := run.docker(ctx, "inspect", "-f",
		"{{.Name}}|{{index .Config.Labels \""+slice6RunLabel+"\"}}", ids[0])
	if inspectErr != nil {
		again, checkErr := find()
		if checkErr == nil && len(again) == 0 {
			return nil // Docker's --rm won the race.
		}
		return errors.New("Product readiness observer cleanup ownership unavailable")
	}
	if strings.TrimSpace(string(identity)) != "/"+name+"|"+run.id {
		return errors.New("Product readiness observer cleanup ownership drift")
	}
	if _, err := run.docker(ctx, "rm", "-f", "-v", ids[0]); err != nil {
		return errors.New("Product readiness observer exact removal failed")
	}
	remaining, err := find()
	if err != nil || len(remaining) != 0 {
		return errors.New("Product readiness observer container remains")
	}
	return nil
}

// .250 is outside the Profile's stable endpoint allocator, including the
// reserved public-ingress-relay address. It exists only while one observer
// request container is alive and is never added to the formal 78 principals.
func slice6ProductRuntimeObserverIP(network phase6security.Network) (string, error) {
	if network.Name != "ingress-product" || network.GatewayModeIPv4 != "isolated" ||
		!network.Internal || len(network.Principals) != 2 ||
		!slices.Contains(network.Principals, "product-runtime") ||
		!slices.Contains(network.Principals, "public-ingress-relay") {
		return "", errors.New("Product observer is not on the exact ingress bridge")
	}
	prefix, err := netip.ParsePrefix(network.IPv4Subnet)
	if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
		return "", errors.New("Product observer ingress subnet invalid")
	}
	address := prefix.Addr().As4()
	address[3] = 250
	observerIP := netip.AddrFrom4(address).String()
	for _, principal := range network.Principals {
		reserved, err := phase6security.Slice6DesiredEndpointAddress(network.Name, principal)
		if err != nil || reserved == observerIP {
			return "", errors.New("Product observer aliases a Profile principal endpoint")
		}
	}
	return observerIP, nil
}

func TestSlice6ProductRuntimeObserverPlacement(t *testing.T) {
	var ingress phase6security.Network
	for _, network := range phase6security.Slice6DesiredFinalNetworks() {
		if network.Name == "ingress-product" {
			ingress = network
		}
	}
	observerIP, err := slice6ProductRuntimeObserverIP(ingress)
	if err != nil || observerIP == "" {
		t.Fatalf("reviewed Product observer endpoint unavailable: %v", err)
	}
	for _, principal := range ingress.Principals {
		reserved, err := phase6security.Slice6DesiredEndpointAddress(ingress.Name, principal)
		if err != nil || reserved == observerIP {
			t.Fatal("observer aliases a Product or relay Profile address")
		}
	}
	ingress.Principals = append(ingress.Principals, "guest-runtime")
	if _, err := slice6ProductRuntimeObserverIP(ingress); err == nil {
		t.Fatal("observer admitted extra formal principal")
	}
}

func TestSlice6ProductRuntimeObservationEnvelope(t *testing.T) {
	for _, candidate := range []struct {
		text string
		want bool
	}{
		{"product-runtime-readiness=observed elapsed_ms=0\n", true},
		{"product-runtime-readiness=observed elapsed_ms=19742\n", true},
		{"product-runtime-readiness=observed elapsed_ms=01\n", false},
		{"product-runtime-readiness=observed elapsed_ms=-1\n", false},
		{"private-data\nproduct-runtime-readiness=observed elapsed_ms=5\n", false},
		{"product-runtime-readiness=observed elapsed_ms=5\nprivate-data", false},
	} {
		if slice6ProductReadinessObservationPattern.MatchString(candidate.text) != candidate.want {
			t.Fatalf("Product observer output admission mismatch for %q", candidate.text)
		}
	}
}

func TestSlice6ProductRuntimeObserverBuild(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	observer, err := slice6BuildProductRuntimeObserver(t, ctx, root)
	if err != nil || len(observer.Digest) != sha256.Size {
		t.Fatalf("bounded Product TLS observer build unavailable: %v", err)
	}
}

func TestSlice6ProductRuntimeObserverDigestApproval(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	observer, err := slice6BuildProductRuntimeObserver(t, ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	const approved = "sha256:7151292b6f4571892502d786c8486cdf24ac7b19bb25e2cf171eec5ad1b99123"
	for _, invalid := range []string{
		"", "sha256:7151292B6F4571892502D786C8486CDF24AC7B19BB25E2CF171EEC5AD1B99123",
		"sha256:" + strings.Repeat("0", 64), "SHA256:" + strings.TrimPrefix(approved, "sha256:"),
		approved + "\n", "sha256:abc",
	} {
		candidate := observer
		if err := slice6ApproveProductRuntimeObserver(invalid, &candidate); err == nil ||
			candidate.ExpectedDigest != "" {
			t.Fatal("missing, non-canonical or mismatched external observer digest admitted")
		}
	}
	if err := slice6ApproveProductRuntimeObserver(approved, &observer); err != nil ||
		slice6VerifyApprovedProductRuntimeObserver(observer) != nil {
		t.Fatal("externally approved Product observer binary rejected")
	}
	reapproval := observer
	if err := slice6ApproveProductRuntimeObserver("sha256:"+strings.Repeat("0", 64), &reapproval); err == nil ||
		reapproval.ExpectedDigest != "" || slice6VerifyApprovedProductRuntimeObserver(reapproval) == nil {
		t.Fatal("failed observer re-approval retained prior external authority")
	}
	if err := os.Chmod(observer.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(observer.Path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte("test-only-mutation"))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || os.Chmod(observer.Path, 0o555) != nil {
		t.Fatal("test observer binary mutation unavailable")
	}
	if err := slice6VerifyApprovedProductRuntimeObserver(observer); err == nil {
		t.Fatal("observer binary mutation after external digest freeze admitted")
	}
}

func TestSlice6ProductRuntimeObserverMountPreflight(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_MOUNT_PREFLIGHT") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_MOUNT_PREFLIGHT=1 for no-issuer Docker mount proof")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	observer, err := slice6BuildProductRuntimeObserver(t, ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := slice6ApproveProductRuntimeObserver(
		"sha256:7151292b6f4571892502d786c8486cdf24ac7b19bb25e2cf171eec5ad1b99123",
		&observer); err != nil {
		t.Fatal("fixed no-issuer observer fixture digest drift")
	}
	if err := slice6ProbeProductRuntimeObserverMount(ctx, observer); err != nil {
		t.Fatal(err)
	}
	t.Log("non-root networkless Docker observer read/exec preflight and exact run-label cleanup passed without issuer")
}

func TestSlice6ProductRuntimeObserverLeftoverCleanup(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_MOUNT_PREFLIGHT") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_PRODUCT_OBSERVER_MOUNT_PREFLIGHT=1 for no-issuer Docker cleanup proof")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Product observer leftover fixture cleanup: %v", err)
		}
	})
	name := "sr-p6-product-ready-observer-" + run.id
	created, err := run.docker(ctx, "create", "--pull=never", "--name", name, "--label", run.label(),
		"--network=none", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=64m", "--pids-limit=16",
		slice6PinnedAlpineImage, "/bin/true")
	if err != nil || len(strings.TrimSpace(string(created))) != 64 {
		t.Fatal("create run-owned leftover observer fixture")
	}
	if err := slice6EnsureProductRuntimeObserverRemoved(ctx, run, name); err != nil {
		t.Fatalf("exact leftover observer reclaim failed: %v", err)
	}
	ids, err := run.labeledIDs(ctx, "container")
	if err != nil || len(ids) != 0 {
		t.Fatal("run-owned observer container remained after exact reclaim")
	}
}
