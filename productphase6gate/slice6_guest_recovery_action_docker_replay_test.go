//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6GuestRecoveryReplayNetwork struct {
	ID          string
	Name        string
	Driver      string
	Internal    bool
	GatewayMode string
	RunID       string
	Containers  map[string]struct {
		IPv4Address string `json:"IPv4Address"`
	}
}

const slice6GuestRecoveryNetworkProjectionFormat = `{{.Id}}|{{.Name}}|{{.Driver}}|{{.Internal}}|{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}|{{index .Labels "io.github.shell-echo.sandbox-runtime.phase6-slice6-run"}}|{{range $id, $member := .Containers}}{{$id}}={{$member.IPv4Address}},{{end}}`

func slice6GuestRecoveryMemberAddress(observed, expected string) bool {
	prefix, err := netip.ParsePrefix(observed)
	return err == nil && prefix.Addr().Is4() && prefix.Addr().String() == expected
}

func slice6ReadGuestRecoveryActionNetwork(ctx context.Context, runID, networkID string) (slice6GuestRecoveryReplayNetwork, []byte, error) {
	if ctx == nil || ctx.Err() != nil || len(networkID) != 64 || !lowerHexSlice6(networkID) {
		return slice6GuestRecoveryReplayNetwork{}, nil, errors.New("Guest E network observation target invalid")
	}
	raw, commandErr, overflow := slice6DockerBounded(ctx, 16<<10, nil,
		"network", "inspect", "--format", slice6GuestRecoveryNetworkProjectionFormat, networkID)
	if commandErr != nil || overflow || ctx.Err() != nil {
		clear(raw)
		return slice6GuestRecoveryReplayNetwork{}, nil, errors.New("Guest E bounded Docker network projection unavailable")
	}
	observed, err := slice6ReplayGuestActionNetwork(raw, runID, networkID)
	if err != nil {
		clear(raw)
		return slice6GuestRecoveryReplayNetwork{}, nil, err
	}
	return observed, raw, nil
}

func slice6ReplayGuestActionNetwork(raw []byte, runID, networkID string) (slice6GuestRecoveryReplayNetwork, error) {
	if len(raw) < 2 || len(raw) > 16<<10 || raw[len(raw)-1] != '\n' ||
		strings.Count(string(raw), "\n") != 1 {
		return slice6GuestRecoveryReplayNetwork{}, errors.New("Guest E Docker network raw framing invalid")
	}
	parts := strings.Split(string(raw[:len(raw)-1]), "|")
	if len(parts) != 7 || parts[0] != networkID || parts[2] != "bridge" ||
		parts[3] != "true" || parts[4] != "isolated" || parts[5] != runID {
		return slice6GuestRecoveryReplayNetwork{}, errors.New("Guest E Docker network raw invalid")
	}
	observed := slice6GuestRecoveryReplayNetwork{ID: parts[0], Name: parts[1],
		Driver: parts[2], Internal: true, GatewayMode: parts[4], RunID: parts[5]}
	if len(parts[6]) < 1 || parts[6][len(parts[6])-1] != ',' {
		return slice6GuestRecoveryReplayNetwork{}, errors.New("Guest E Docker network member projection invalid")
	}
	observed.Containers = make(map[string]struct {
		IPv4Address string `json:"IPv4Address"`
	})
	last := ""
	for _, entry := range strings.Split(strings.TrimSuffix(parts[6], ","), ",") {
		member := strings.Split(entry, "=")
		if len(member) != 2 || len(member[0]) != 64 || !lowerHexSlice6(member[0]) ||
			member[0] <= last || len(observed.Containers) >= 2 {
			return slice6GuestRecoveryReplayNetwork{}, errors.New("Guest E Docker network member identity invalid")
		}
		prefix, err := netip.ParsePrefix(member[1])
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().String() != strings.Split(member[1], "/")[0] {
			return slice6GuestRecoveryReplayNetwork{}, errors.New("Guest E Docker network member IPv4 invalid")
		}
		observed.Containers[member[0]] = struct {
			IPv4Address string `json:"IPv4Address"`
		}{IPv4Address: member[1]}
		last = member[0]
	}
	return observed, nil
}

func TestSlice6GuestRecoveryNetworkRawFailClosed(t *testing.T) {
	const runID = "0123456789abcdef0123456789abcdef"
	networkID := strings.Repeat("a", 64)
	firstID, secondID, thirdID := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	base := networkID + "|guest-product|bridge|true|isolated|" + runID + "|"
	member := firstID + "=172.20.0.1/24,"
	if observed, err := slice6ReplayGuestActionNetwork([]byte(base+member+"\n"), runID, networkID); err != nil ||
		len(observed.Containers) != 1 || observed.Containers[firstID].IPv4Address != "172.20.0.1/24" {
		t.Fatalf("canonical bounded network projection rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"missing-final-comma": base + strings.TrimSuffix(member, ",") + "\n",
		"wrong-run":           strings.Replace(base, runID, strings.Repeat("f", 32), 1) + member + "\n",
		"duplicate":           base + member + member + "\n",
		"unsorted":            base + secondID + "=172.20.0.2/24," + member + "\n",
		"third-member":        base + member + secondID + "=172.20.0.2/24," + thirdID + "=172.20.0.3/24,\n",
		"ipv6":                base + firstID + "=::1/128,\n",
		"invalid-mask":        base + firstID + "=172.20.0.1/33,\n",
		"extra-field":         base + member + "|endpoint-id\n",
		"extra-line":          base + member + "\nsecond\n",
	} {
		if _, err := slice6ReplayGuestActionNetwork([]byte(raw), runID, networkID); err == nil {
			t.Fatalf("network raw admitted %s", name)
		}
	}
}

func slice6ReplayPGActionSnapshot(source slice6GuestOperatorFormalSource,
	action slice6ProductPGFaultAction, snapshot slice6GuestRecoveryDockerSnapshot,
	connected bool) (string, error) {
	run := slice6DockerRun{id: source.runID}
	product, err := slice6ParseGuestEdgeProcessRaw(snapshot.Product, run, action.ProductID,
		"sr-p6-product-runtime-"+run.id)
	if err != nil {
		return "", err
	}
	postgres, err := slice6ParseGuestEdgeProcessRaw(snapshot.Peer, run, action.PostgresID,
		"sr-p6-postgres-"+run.id)
	if err != nil {
		return "", err
	}
	identity := strings.Split(strings.TrimSuffix(string(snapshot.Retained), "\n"), "|")
	if len(identity) != 7 || identity[0] != action.PostgresID || identity[1] != source.imageID ||
		identity[2] != source.imageRef || identity[3] != source.runID || identity[4] != "true" ||
		identity[5] != strconv.Itoa(postgres.PID) || identity[6] != postgres.StartedAt {
		return "", errors.New("Guest E PostgreSQL identity raw drift")
	}
	network, err := slice6ReplayGuestActionNetwork(snapshot.Network, run.id, action.NetworkID)
	if err != nil || network.Name != "service-product-postgres" ||
		len(network.Containers) != 1+boolToIntSlice6(connected) {
		return "", errors.New("Guest E PostgreSQL edge network raw drift")
	}
	pgIP := source.endpoints[network.Name].IP
	productIP, ipErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(network.Name, "product-runtime")
	if ipErr != nil || postgres.Networks[network.Name].NetworkID != action.NetworkID ||
		postgres.Networks[network.Name].IPAddress != pgIP ||
		network.Containers[action.PostgresID].IPv4Address != pgIP+"/24" {
		return "", errors.New("Guest E PostgreSQL endpoint raw drift")
	}
	productEndpoint, productPresent := product.Networks[network.Name]
	_, memberPresent := network.Containers[action.ProductID]
	if productPresent != connected || memberPresent != connected ||
		(connected && (productEndpoint.NetworkID != action.NetworkID ||
			productEndpoint.IPAddress != productIP ||
			network.Containers[action.ProductID].IPv4Address != productIP+"/24")) ||
		product.PID != action.ProductPID || product.StartedAt != action.ProductStartedAt ||
		postgres.PID != action.PostgresPID || postgres.StartedAt != action.PostgresStartedAt {
		return "", errors.New("Guest E PostgreSQL action process/member raw drift")
	}
	productOther := slice6ProductPGNetworkDigest(product.Networks, network.Name)
	pgNetworks := slice6ProductPGNetworkDigest(postgres.Networks, "")
	projection := strings.Join([]string{run.id, action.ProductID, action.PostgresID,
		strconv.Itoa(product.PID), product.StartedAt, strconv.Itoa(postgres.PID), postgres.StartedAt,
		action.NetworkID, productIP, pgIP, productOther, pgNetworks,
		strconv.FormatBool(connected)}, "|")
	return projection, nil
}

func slice6ReplayGuestActionSnapshot(source slice6GuestOperatorFormalSource,
	action slice6GuestRecoveryEdgeAction, snapshot slice6GuestRecoveryDockerSnapshot,
	connected bool) (string, error) {
	run := slice6DockerRun{id: source.runID}
	product, err := slice6ParseGuestEdgeProcessRaw(snapshot.Product, run, action.ProductID,
		"sr-p6-product-runtime-"+run.id)
	if err != nil {
		return "", err
	}
	guest, err := slice6ParseGuestEdgeProcessRaw(snapshot.Peer, run, action.GuestID,
		"sr-p6-guest-runtime-"+run.id)
	if err != nil {
		return "", err
	}
	productNetworksRaw, err := source.evidence.readFile("guest-source-product-networks.inspect", 4096)
	if err != nil {
		return "", err
	}
	defer clear(productNetworksRaw)
	productSource, err := slice6ParseGuestSourceProductNetworks(productNetworksRaw, run.id, action.ProductID)
	if err != nil {
		return "", err
	}
	productNetworkID := productSource["guest-product"].NetworkID
	productIP := productSource["guest-product"].IPAddress
	if action.ProductNetworkID != productNetworkID {
		return "", errors.New("Guest E original Product network raw drift")
	}
	productNetwork, err := slice6ReplayGuestActionNetwork(snapshot.Network, run.id, productNetworkID)
	if err != nil || productNetwork.Name != "guest-product" ||
		len(productNetwork.Containers) != 1+boolToIntSlice6(connected) ||
		productNetwork.Containers[action.ProductID].IPv4Address != productIP+"/24" {
		return "", errors.New("Guest E Product trust edge raw drift")
	}
	runtimeIDParts := strings.Split(action.BeforeProjection, "|")
	if len(runtimeIDParts) != 13 {
		return "", errors.New("Guest E runtime projection unavailable")
	}
	runtimeID := runtimeIDParts[10]
	runtimeNetwork, err := slice6ReplayGuestActionNetwork(snapshot.Retained, run.id, runtimeID)
	if err != nil || runtimeNetwork.Name != "network-guest-runtime" ||
		len(runtimeNetwork.Containers) != 1 ||
		runtimeNetwork.Containers[action.GuestID].IPv4Address != action.RuntimeIP+"/24" {
		return "", errors.New("Guest E retained runtime edge raw drift")
	}
	guestIP, guestIPErr := phase6security.Slice6DesiredEndpointAddress("guest-product", "guest-runtime")
	runtimeIP, runtimeIPErr := phase6security.Slice6DesiredEndpointAddress("network-guest-runtime", "guest-runtime")
	productEndpoint := product.Networks["guest-product"]
	guestRuntime := guest.Networks["network-guest-runtime"]
	guestProduct, guestPresent := guest.Networks["guest-product"]
	_, memberPresent := productNetwork.Containers[action.GuestID]
	if guestIPErr != nil || runtimeIPErr != nil || action.GuestIP != guestIP || action.RuntimeIP != runtimeIP ||
		productEndpoint.NetworkID != productNetworkID || productEndpoint.IPAddress != productIP ||
		guestRuntime.NetworkID != runtimeID || guestRuntime.IPAddress != runtimeIP ||
		guestPresent != connected || memberPresent != connected || len(guest.Networks) != 1+boolToIntSlice6(connected) ||
		(connected && (guestProduct.NetworkID != productNetworkID || guestProduct.IPAddress != guestIP ||
			productNetwork.Containers[action.GuestID].IPv4Address != guestIP+"/24")) ||
		product.PID != action.ProductPID || product.StartedAt != action.ProductStartedAt ||
		guest.PID != action.GuestPID || guest.StartedAt != action.GuestStartedAt {
		return "", errors.New("Guest E trust edge process/member raw drift")
	}
	projection := strings.Join([]string{run.id, action.ProductID, action.GuestID,
		strconv.Itoa(product.PID), product.StartedAt, strconv.Itoa(guest.PID), guest.StartedAt,
		productNetworkID, productIP, guestIP, runtimeID, runtimeIP,
		strconv.FormatBool(connected)}, "|")
	return projection, nil
}

func slice6ReplayGuestRecoveryActionDockerRaw(source slice6GuestOperatorFormalSource,
	ledger slice6GuestRecoveryActionLedger) error {
	checks := []struct {
		projection    string
		snapshot      slice6GuestRecoveryDockerSnapshot
		pg, connected bool
		pgAction      slice6ProductPGFaultAction
		guestAction   slice6GuestRecoveryEdgeAction
	}{
		{ledger.PGDown.BeforeProjection, ledger.PGDown.BeforeDocker, true, true, ledger.PGDown, slice6GuestRecoveryEdgeAction{}},
		{ledger.PGDown.AfterProjection, ledger.PGDown.AfterDocker, true, false, ledger.PGDown, slice6GuestRecoveryEdgeAction{}},
		{ledger.GuestOff.BeforeProjection, ledger.GuestOff.BeforeDocker, false, true, slice6ProductPGFaultAction{}, ledger.GuestOff},
		{ledger.GuestOff.AfterProjection, ledger.GuestOff.AfterDocker, false, false, slice6ProductPGFaultAction{}, ledger.GuestOff},
		{ledger.PGUp.BeforeProjection, ledger.PGUp.BeforeDocker, true, false, ledger.PGUp, slice6GuestRecoveryEdgeAction{}},
		{ledger.PGUp.AfterProjection, ledger.PGUp.AfterDocker, true, true, ledger.PGUp, slice6GuestRecoveryEdgeAction{}},
		{ledger.GuestOn.BeforeProjection, ledger.GuestOn.BeforeDocker, false, false, slice6ProductPGFaultAction{}, ledger.GuestOn},
		{ledger.GuestOn.AfterProjection, ledger.GuestOn.AfterDocker, false, true, slice6ProductPGFaultAction{}, ledger.GuestOn},
	}
	for _, check := range checks {
		var projection string
		var err error
		if check.pg {
			projection, err = slice6ReplayPGActionSnapshot(source, check.pgAction, check.snapshot, check.connected)
		} else {
			projection, err = slice6ReplayGuestActionSnapshot(source, check.guestAction, check.snapshot, check.connected)
		}
		if err != nil || projection != check.projection {
			return errors.New("Guest E action projection not reconstructable from original Docker raw")
		}
	}
	return nil
}
