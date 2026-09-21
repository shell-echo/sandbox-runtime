// Package gateway implements the process-local enforcement used by the
// restricted-egress Docker gateway. It is not a public Runtime Gateway.
package gateway

import (
	"net/netip"

	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

const ConfigEnvironment = restricted.ConfigEnvironment

var (
	ErrInvalidConfig = restricted.ErrInvalidConfig
	ErrPolicyDenied  = restricted.ErrPolicyDenied
)

type Policy = restricted.Policy
type Config = restricted.Config

func NormalizePolicy(policy Policy) (Policy, error) { return restricted.NormalizePolicy(policy) }
func EncodeConfig(config Config) (string, error)    { return restricted.EncodeConfig(config) }
func DecodeConfig(value string) (Config, error)     { return restricted.DecodeConfig(value) }
func PublicUpstreamAddress(address netip.Addr) bool { return restricted.PublicUpstreamAddress(address) }

func normalizeConfig(config Config) (Config, error) { return restricted.NormalizeConfig(config) }
func normalizeDestinationHost(value string) (string, error) {
	return restricted.NormalizeDestinationHost(value)
}
