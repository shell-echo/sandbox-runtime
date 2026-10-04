//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6GuestRecoveryCreatedNetworkFormat = `{{.Id}}|{{.Name}}|{{.Driver}}|{{.Internal}}|{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}|{{index .Labels "io.github.shell-echo.sandbox-runtime.phase6-slice6-run"}}|{{json .Containers}}`

const (
	slice6GuestRecoveryCreatedProductRaw = "guest-e-created-guest-product.inspect"
	slice6GuestRecoveryCreatedRuntimeRaw = "guest-e-created-guest-runtime.inspect"
	slice6GuestRecoveryCreatedReceiptRaw = "guest-e-created-networks.json"
)

type slice6GuestRecoveryCreatedNetworks struct {
	Protocol, RunID                  string
	GuestProductID, GuestRuntimeID   string
	GuestProductSHA, GuestRuntimeSHA string
}

func slice6CheckGuestRecoveryCreatedNetworkRaw(raw []byte, runID, networkID, name string) error {
	if len(raw) < 2 || len(raw) > 256 || raw[len(raw)-1] != '\n' ||
		strings.Count(string(raw), "\n") != 1 {
		return errors.New("Guest E original network projection framing invalid")
	}
	parts := strings.Split(string(raw[:len(raw)-1]), "|")
	if len(parts) != 7 || parts[0] != networkID || parts[1] != name ||
		parts[2] != "bridge" || parts[3] != "true" || parts[4] != "isolated" ||
		parts[5] != runID || parts[6] != "{}" {
		return errors.New("Guest E original empty network projection invalid")
	}
	return nil
}

// The formal E launcher calls this instead of the bare allocator. The two
// original IDs are captured from that allocator's create result before any
// Product/Guest container joins; a later same-named, same-labeled bridge has
// a different ID and cannot satisfy the durable receipt.
func (run *slice6ReceiptEvidenceRun) createGuestRecoveryFinalNetworks(ctx context.Context,
	dockerRun slice6DockerRun) ([]phase6security.NetworkObservation, string, error) {
	if run == nil || run.check() != nil || ctx == nil || ctx.Err() != nil || dockerRun.id != run.id {
		return nil, "", phase6guestreceipt.ErrUnavailable
	}
	inventory, err := createSlice6FinalNetworkInventory(ctx, dockerRun)
	if err != nil {
		return nil, "", err
	}
	fail := func(cause error) ([]phase6security.NetworkObservation, string, error) {
		return nil, "", cleanupFailedSlice6NetworkBootstrap(dockerRun, cause)
	}
	created := slice6GuestRecoveryCreatedNetworks{Protocol: "sandbox-runtime.phase6-guest-created-networks.v1",
		RunID: run.id}
	for _, observation := range inventory {
		switch observation.Name {
		case "guest-product":
			created.GuestProductID = observation.NetworkID
		case "network-guest-runtime":
			created.GuestRuntimeID = observation.NetworkID
		}
	}
	if created.GuestProductID == "" || created.GuestRuntimeID == "" ||
		created.GuestProductID == created.GuestRuntimeID {
		return fail(errors.New("Guest E created network identity unavailable"))
	}
	read := func(id, name string) ([]byte, error) {
		raw, commandErr, overflow := slice6DockerBounded(ctx, 256, nil,
			"network", "inspect", "--format", slice6GuestRecoveryCreatedNetworkFormat, id)
		if commandErr != nil || overflow || ctx.Err() != nil ||
			slice6CheckGuestRecoveryCreatedNetworkRaw(raw, run.id, id, name) != nil {
			clear(raw)
			return nil, errors.New("Guest E original network readback unavailable")
		}
		return raw, nil
	}
	productRaw, err := read(created.GuestProductID, "guest-product")
	if err != nil {
		return fail(err)
	}
	defer clear(productRaw)
	runtimeRaw, err := read(created.GuestRuntimeID, "network-guest-runtime")
	if err != nil {
		return fail(err)
	}
	defer clear(runtimeRaw)
	digest, err := run.writeGuestRecoveryCreatedNetworks(created, productRaw, runtimeRaw)
	if err != nil {
		return fail(err)
	}
	return inventory, digest, nil
}

func (run *slice6ReceiptEvidenceRun) writeGuestRecoveryCreatedNetworks(
	created slice6GuestRecoveryCreatedNetworks, productRaw, runtimeRaw []byte) (string, error) {
	if run == nil || run.check() != nil || created.Protocol != "sandbox-runtime.phase6-guest-created-networks.v1" ||
		created.RunID != run.id || len(created.GuestProductID) != 64 || !lowerHexSlice6(created.GuestProductID) ||
		len(created.GuestRuntimeID) != 64 || !lowerHexSlice6(created.GuestRuntimeID) ||
		created.GuestProductID == created.GuestRuntimeID ||
		slice6CheckGuestRecoveryCreatedNetworkRaw(productRaw, run.id, created.GuestProductID, "guest-product") != nil ||
		slice6CheckGuestRecoveryCreatedNetworkRaw(runtimeRaw, run.id, created.GuestRuntimeID, "network-guest-runtime") != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	created.GuestProductSHA = slice6ReceiptSHA256(productRaw)
	created.GuestRuntimeSHA = slice6ReceiptSHA256(runtimeRaw)
	encoded, err := json.Marshal(created)
	if err != nil || len(encoded) > 512 {
		return "", phase6guestreceipt.ErrUnavailable
	}
	if run.writeV2BoundedPrivateFile(slice6GuestRecoveryCreatedProductRaw, productRaw, 256, false) != nil ||
		run.writeV2BoundedPrivateFile(slice6GuestRecoveryCreatedRuntimeRaw, runtimeRaw, 256, false) != nil ||
		run.writeV2BoundedPrivateFile(slice6GuestRecoveryCreatedReceiptRaw, encoded, 512, false) != nil {
		return "", errors.New("Guest E original network receipt unavailable")
	}
	return slice6ReceiptSHA256(encoded), nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryCreatedNetworks(
	input slice6GuestRecoveryPrecleanupInput) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(input.CreatedNetworksDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	encoded, err := run.readFile(slice6GuestRecoveryCreatedReceiptRaw, 512)
	if err != nil || slice6ReceiptSHA256(encoded) != input.CreatedNetworksDigest {
		clear(encoded)
		return errors.New("Guest E original network receipt digest drift")
	}
	defer clear(encoded)
	var created slice6GuestRecoveryCreatedNetworks
	if json.Unmarshal(encoded, &created) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(created)
	if err != nil || !bytes.Equal(canonical, encoded) || created.RunID != run.id ||
		created.Protocol != "sandbox-runtime.phase6-guest-created-networks.v1" {
		return phase6guestreceipt.ErrUnavailable
	}
	for _, item := range [2]struct{ name, id, digest, file string }{
		{"guest-product", created.GuestProductID, created.GuestProductSHA, slice6GuestRecoveryCreatedProductRaw},
		{"network-guest-runtime", created.GuestRuntimeID, created.GuestRuntimeSHA, slice6GuestRecoveryCreatedRuntimeRaw},
	} {
		raw, readErr := run.readFile(item.file, 256)
		if readErr != nil || slice6ReceiptSHA256(raw) != item.digest ||
			slice6CheckGuestRecoveryCreatedNetworkRaw(raw, run.id, item.id, item.name) != nil {
			clear(raw)
			return errors.New("Guest E original network raw drift")
		}
		clear(raw)
	}
	productRaw, err := run.readFile("guest-source-product-networks.inspect", 4096)
	if err != nil {
		return err
	}
	defer clear(productRaw)
	product, err := slice6ParseGuestSourceProductNetworks(productRaw, run.id, input.Process[0].ContainerID)
	guestProjection := strings.Split(input.Actions.GuestOff.BeforeProjection, "|")
	if err != nil || len(guestProjection) != 13 ||
		product["guest-product"].NetworkID != created.GuestProductID ||
		input.Actions.GuestOff.ProductNetworkID != created.GuestProductID ||
		input.Actions.GuestOn.ProductNetworkID != created.GuestProductID ||
		guestProjection[10] != created.GuestRuntimeID {
		return errors.New("Guest E original network IDs not retained into source/action")
	}
	return nil
}

func TestSlice6GuestRecoveryOriginalNetworkCreationNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_CREATED_NETWORKS_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_CREATED_NETWORKS_NO_ISSUER=1 for original network creation")
	}
	dockerRun, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := dockerRun.cleanup(ctx); err != nil {
			t.Errorf("original network creation exact cleanup: %v", err)
		}
	})
	private := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	private, err = filepath.EvalSymlinks(private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(private)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(dockerRun.id)
	if err != nil {
		t.Fatal(err)
	}
	defer run.closeV2Incomplete()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	inventory, digest, err := run.createGuestRecoveryFinalNetworks(ctx, dockerRun)
	if err != nil || !guestRevokeFixtureDigestGate(digest) ||
		len(inventory) != len(phase6security.Slice6DesiredFinalNetworks()) {
		t.Fatalf("same-run original network creation unavailable: %v", err)
	}
	encoded, err := run.readFile(slice6GuestRecoveryCreatedReceiptRaw, 512)
	if err != nil || slice6ReceiptSHA256(encoded) != digest {
		t.Fatal("original network receipt not independently reread")
	}
	var created slice6GuestRecoveryCreatedNetworks
	if json.Unmarshal(encoded, &created) != nil {
		t.Fatal("original network receipt decode unavailable")
	}
	clear(encoded)
	manifest, err := slice6GuestRecoveryOriginalNetworkManifest(dockerRun, inventory, digest, run)
	if err != nil {
		t.Fatalf("original network manifest rejected actual allocation: %v", err)
	}
	eRun, err := dockerRun.withGuestRecoveryOriginalNetworks(manifest)
	if err != nil {
		t.Fatal("E network source did not accept original allocation")
	}
	beforeIDs, err := dockerRun.labeledIDs(ctx, "network")
	if err != nil || len(beforeIDs) != len(inventory) {
		t.Fatal("E original run-labeled network inventory unavailable")
	}
	for _, network := range phase6security.Slice6DesiredFinalNetworks() {
		resolved, resolveErr := eRun.resolveProfileNetwork(ctx, network)
		if resolveErr != nil || resolved.NetworkID != manifest.byName[network.Name].NetworkID {
			t.Fatalf("E bootstrap could not reuse original %s ID: %v", network.Name, resolveErr)
		}
	}
	afterIDs, err := dockerRun.labeledIDs(ctx, "network")
	slices.Sort(beforeIDs)
	slices.Sort(afterIDs)
	if err != nil || !slices.Equal(beforeIDs, afterIDs) {
		t.Fatal("E bootstrap resolver allocated or replaced a network")
	}
	wrongRun := eRun
	wrongRun.id = strings.Repeat("f", 32)
	if _, err := wrongRun.resolveProfileNetwork(ctx, phase6security.Slice6DesiredFinalNetworks()[0]); err == nil {
		t.Fatal("E network source accepted another run")
	}
	wrongSpec := phase6security.Slice6DesiredFinalNetworks()[0]
	wrongSpec.IPv4Subnet = "10.255.0.0/24"
	if _, err := eRun.resolveProfileNetwork(ctx, wrongSpec); err == nil {
		t.Fatal("E network source accepted a same-name changed subnet")
	}
	if _, err := dockerRun.resolveProfileNetwork(ctx, phase6security.Slice6DesiredFinalNetworks()[0]); err == nil {
		t.Fatal("legacy allocator silently accepted a pre-existing same-name E network")
	}
	productPlan := slice6ProductRuntimeLaunchPlan{
		Principal: phase6security.Principal{Name: "product-runtime"}}
	productPlan.SourceAddress, err = phase6security.Slice6DesiredFinalServiceEndpointAddress(
		"service-product-postgres", "product-runtime")
	if err != nil {
		t.Fatal("Product original SQL source address unavailable")
	}
	for _, network := range phase6security.Slice6DesiredFinalNetworks() {
		if slices.Contains(network.Principals, "product-runtime") {
			productPlan.Networks = append(productPlan.Networks, network)
			if network.Name == "service-product-postgres" {
				productPlan.ServiceNetwork = network
			}
		}
	}
	endpoints, err := manifest.productEndpoints(ctx, dockerRun, productPlan)
	if err != nil || len(endpoints) != 7 || endpoints[0].Network.Name != "service-product-postgres" {
		t.Fatalf("Product E original endpoints unavailable: %v", err)
	}
	for _, endpoint := range endpoints {
		if endpoint.ID != manifest.byName[endpoint.Network.Name].NetworkID {
			t.Fatal("Product E endpoint substituted a same-named network")
		}
	}
	guestPlan := slice6GuestRuntimeLaunchPlan{}
	for _, network := range phase6security.Slice6DesiredFinalNetworks() {
		switch network.Name {
		case "guest-product":
			guestPlan.ProductNetwork = network
			guestPlan.ProductIP, err = phase6security.Slice6DesiredEndpointAddress(network.Name, "guest-runtime")
		case "network-guest-runtime":
			guestPlan.InternalNetwork = network
			guestPlan.InternalIP, err = phase6security.Slice6DesiredEndpointAddress(network.Name, "guest-runtime")
		}
		if err != nil {
			t.Fatal("Guest original endpoint address unavailable")
		}
	}
	productID, runtimeID, err := manifest.guestNetworks(ctx, dockerRun, guestPlan)
	if err != nil || productID != created.GuestProductID || runtimeID != created.GuestRuntimeID {
		t.Fatalf("Guest E original networks unavailable: %v", err)
	}
	vaultCreated, err := dockerRun.docker(ctx, "create", "--pull=never",
		"--name", "sr-p6-original-vault-"+dockerRun.id, "--label", dockerRun.label(),
		"--network=none", "--user=20090:30090", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--read-only", "--log-driver=none",
		"--memory=64m", "--cpus=0.25", "--pids-limit=16", slice6VaultTestImage)
	vaultID := strings.TrimSpace(string(vaultCreated))
	if err != nil || len(vaultID) != 64 || !lowerHexSlice6(vaultID) {
		t.Fatal("original Vault-image container create unavailable")
	}
	if err := slice6VerifyGuestRecoveryCreatedName(ctx, dockerRun, vaultID,
		"sr-p6-original-vault-"+dockerRun.id); err != nil {
		t.Fatal("original container name/ID verification unavailable")
	}
	origin, err := run.captureGuestRecoveryImplicitOrigin(ctx, vaultID)
	if err != nil {
		t.Fatalf("original Vault identity/mount capture unavailable: %v", err)
	}
	// A later same-named and same-labeled bridge must never replace the
	// allocator's original ID, even when its frozen spec is identical.
	replacedSpec := phase6security.Slice6DesiredFinalNetworks()[0]
	originalID := manifest.byName[replacedSpec.Name].NetworkID
	removed, err := dockerRun.docker(ctx, "network", "rm", originalID)
	if err != nil || strings.TrimSpace(string(removed)) != originalID {
		t.Fatal("remove exact disposable original network for replacement negative")
	}
	replacement, err := createSlice6ProfileNetwork(ctx, dockerRun, replacedSpec)
	if err != nil || replacement.NetworkID == originalID {
		t.Fatal("same-name disposable replacement network unavailable")
	}
	if _, err := eRun.resolveProfileNetwork(ctx, replacedSpec); err == nil {
		t.Fatal("E resolver accepted a same-name replacement network")
	}
	if err := dockerRun.cleanup(ctx); err != nil {
		t.Fatalf("original network/Vault cleanup unavailable: %v", err)
	}
	if err := slice6CheckImplicitVolumesRemoved(ctx, dockerRun,
		[]string{origin.FileVolumeID, origin.LogsVolumeID}); err != nil {
		t.Fatal("original Vault anonymous volumes not absent")
	}
	for index, id := range [3]string{created.GuestProductID, created.GuestRuntimeID, vaultID} {
		command := []string{"network", "inspect", id}
		if index == 2 {
			command = []string{"inspect", id}
		}
		raw, commandErr, overflow := slice6DockerBounded(ctx, 512, nil, command...)
		missing := commandErr != nil && !overflow &&
			slice6GuestRecoveryExactOriginMissing(raw, id, index < 2)
		clear(raw)
		if !missing {
			t.Fatalf("original Docker resource %d not exactly absent", index)
		}
	}
}
