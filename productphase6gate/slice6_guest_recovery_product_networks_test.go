//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
)

const slice6GuestSourceProductNetworksFormat = `{{.Id}}|{{index .Config.Labels "io.github.shell-echo.sandbox-runtime.phase6-slice6-run"}}{{range $name, $net := .NetworkSettings.Networks}}{{printf "\n%s|%s|%s" $name $net.NetworkID $net.IPAddress}}{{end}}`

func slice6ReadGuestSourceProductNetworks(ctx context.Context, runID, productID string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(runID) != 32 || !lowerHexSlice6(runID) ||
		len(productID) != 64 || !lowerHexSlice6(productID) {
		return nil, errors.New("Product network source target invalid")
	}
	raw, commandErr, overflow := slice6DockerBounded(ctx, 4096, nil,
		"inspect", "--format", slice6GuestSourceProductNetworksFormat, productID)
	if commandErr != nil || overflow || ctx.Err() != nil {
		clear(raw)
		return nil, errors.New("Product network source projection unavailable")
	}
	if _, err := slice6ParseGuestSourceProductNetworks(raw, runID, productID); err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

func slice6ParseGuestSourceProductNetworks(raw []byte, runID, productID string) (map[string]struct {
	NetworkID string `json:"NetworkID"`
	IPAddress string `json:"IPAddress"`
}, error) {
	type endpoint = struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if len(raw) < 2 || len(raw) > 4096 || !bytes.HasSuffix(raw, []byte("\n")) ||
		bytes.ContainsRune(raw, '\r') || bytes.ContainsRune(raw, '\x00') {
		return nil, errors.New("Product network source framing invalid")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) < 2 || len(lines) > 16 || lines[0] != productID+"|"+runID {
		return nil, errors.New("Product network source identity/size drift")
	}
	result := make(map[string]endpoint, len(lines)-1)
	lastName := ""
	for _, line := range lines[1:] {
		parts := strings.Split(line, "|")
		if len(parts) != 3 || !slice6GuestOperatorID(parts[0]) ||
			parts[0] <= lastName || len(parts[1]) != 64 || !lowerHexSlice6(parts[1]) {
			return nil, errors.New("Product network source row noncanonical")
		}
		ip, err := netip.ParseAddr(parts[2])
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() {
			return nil, errors.New("Product network source IP invalid")
		}
		result[parts[0]] = endpoint{NetworkID: parts[1], IPAddress: parts[2]}
		lastName = parts[0]
	}
	return result, nil
}
