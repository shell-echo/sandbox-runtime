// Package docker provisions one fail-closed restricted-egress Docker network
// for each Provider-local Browser allocation.
package docker

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	browserdriver "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

const (
	GatewayUser       = "65532:65532"
	GatewayEntrypoint = "/browser-egress-gateway"
	GatewayComponent  = "browser-egress-gateway-v1"
	GatewayPath       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	UplinkRole = "browser-egress-uplink"

	maxPolicies        = 64
	maxGatewayMemory   = 1 << 30
	maxGatewayNanoCPUs = 4_000_000_000
	maxGatewayPIDs     = 256
	maxTimeoutSeconds  = 600
)

var (
	ErrInvalidOptions     = errors.New("invalid Browser restricted-network options")
	ErrPolicyUnavailable  = errors.New("Browser egress policy is unavailable")
	ErrOwnershipConflict  = errors.New("Browser restricted-network ownership conflict")
	ErrNetworkUnavailable = errors.New("Browser restricted network is unavailable")
	ErrOutcomeUnknown     = errors.New("Browser restricted-network outcome is unknown")

	privateValuePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
	immutableImage      = regexp.MustCompile("^(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64})$")
)

type Options struct {
	Host                    string
	GatewayImage            string
	UplinkNetwork           string
	Namespace               string
	ControllerID            string
	Policies                []gateway.Policy
	MemoryBytes             int64
	NanoCPUs                int64
	PidsLimit               int64
	OperationTimeoutSeconds int
	StopTimeoutSeconds      int
}

func (o Options) validate() (map[string]gateway.Policy, error) {
	if !immutableImage.MatchString(o.GatewayImage) || !privateValuePattern.MatchString(o.Namespace) ||
		!privateValuePattern.MatchString(o.ControllerID) || !validDockerName(o.UplinkNetwork) ||
		reservedNetwork(o.UplinkNetwork) || len(o.Policies) == 0 || len(o.Policies) > maxPolicies ||
		o.MemoryBytes <= 0 || o.MemoryBytes > maxGatewayMemory || o.NanoCPUs <= 0 || o.NanoCPUs > maxGatewayNanoCPUs ||
		o.PidsLimit <= 0 || o.PidsLimit > maxGatewayPIDs || o.OperationTimeoutSeconds <= 0 ||
		o.OperationTimeoutSeconds > maxTimeoutSeconds || o.StopTimeoutSeconds < 0 || o.StopTimeoutSeconds > maxTimeoutSeconds {
		return nil, ErrInvalidOptions
	}
	policies := make(map[string]gateway.Policy, len(o.Policies))
	for _, configured := range o.Policies {
		policy, err := gateway.NormalizePolicy(configured)
		if err != nil || !privateValuePattern.MatchString(policy.Reference) {
			return nil, fmt.Errorf("%w: invalid policy", ErrInvalidOptions)
		}
		if _, exists := policies[policy.Reference]; exists {
			return nil, fmt.Errorf("%w: duplicate policy reference", ErrInvalidOptions)
		}
		policies[policy.Reference] = policy
	}
	return policies, nil
}

func validDockerName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("_.-", character)) {
			continue
		}
		return false
	}
	return true
}

func reservedNetwork(value string) bool {
	switch value {
	case "none", "host", "bridge", "default":
		return true
	default:
		return false
	}
}

var _ browserdriver.RestrictedNetwork = (*Provisioner)(nil)
