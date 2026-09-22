// Package egressbroker implements the closed, alias-only network boundary used
// by Product Phase 6. A caller can select only a profile-defined target alias;
// DNS resolution and the numeric dial occur inside the broker.
package egressbroker

import (
	"errors"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/netpolicy"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

var (
	ErrDenied      = errors.New("egress broker request denied")
	ErrUnavailable = errors.New("egress broker unavailable")
	ErrInvalid     = errors.New("invalid egress broker policy")
)

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type Target struct {
	Alias    string `json:"alias"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Policy struct {
	ID            string
	Revision      string
	Registry      *securityprincipal.Registry
	Principal     securityprincipal.Principal
	Broker        securityprincipal.Principal
	Lease         time.Duration
	DNSMaxAnswers int
	Targets       []Target
	network       netpolicy.Policy
}

func NewPolicy(id, revision string, registry *securityprincipal.Registry, principal, broker securityprincipal.Principal,
	lease time.Duration, dnsMaxAnswers int, targets []Target) (Policy, error) {
	policy := Policy{ID: id, Revision: revision, Registry: registry, Principal: principal, Broker: broker,
		Lease: lease, DNSMaxAnswers: dnsMaxAnswers, Targets: append([]Target(nil), targets...)}
	if !namePattern.MatchString(id) || !namePattern.MatchString(revision) || registry == nil || registry.Validate(principal) != nil ||
		registry.Validate(broker) != nil || principal.Kind == securityprincipal.KindEgressBroker ||
		broker.Kind != securityprincipal.KindEgressBroker || principal.Digest() == broker.Digest() || lease < time.Second ||
		lease > 5*time.Minute || dnsMaxAnswers < 1 || dnsMaxAnswers > 32 || len(targets) < 1 || len(targets) > 64 {
		return Policy{}, ErrInvalid
	}
	hosts, ports := make([]string, 0, len(targets)), make([]int, 0, len(targets))
	previous := ""
	seenHosts := make(map[string]struct{}, len(targets))
	seenPorts := make(map[int]struct{}, len(targets))
	for _, target := range targets {
		if target.Alias <= previous || !namePattern.MatchString(target.Alias) || !validHost(target.Host) ||
			target.Port < 1 || target.Port > 65535 || !validProtocol(target.Protocol) {
			return Policy{}, ErrInvalid
		}
		previous = target.Alias
		if _, duplicate := seenHosts[target.Host]; !duplicate {
			hosts = append(hosts, target.Host)
			seenHosts[target.Host] = struct{}{}
		}
		if _, duplicate := seenPorts[target.Port]; !duplicate {
			ports = append(ports, target.Port)
			seenPorts[target.Port] = struct{}{}
		}
	}
	sort.Strings(hosts)
	sort.Ints(ports)
	network, err := netpolicy.NewBounded(hosts, ports, dnsMaxAnswers)
	if err != nil {
		return Policy{}, ErrInvalid
	}
	policy.network = network
	return policy, nil
}

func (p Policy) Validate() error {
	_, err := NewPolicy(p.ID, p.Revision, p.Registry, p.Principal, p.Broker, p.Lease, p.DNSMaxAnswers, p.Targets)
	return err
}

func (p Policy) target(alias string) (Target, bool) {
	for _, target := range p.Targets {
		if target.Alias == alias {
			return target, true
		}
	}
	return Target{}, false
}

func validHost(value string) bool {
	return value == strings.ToLower(strings.TrimSpace(value)) && hostPattern.MatchString(value) &&
		!strings.Contains(value, "..") && net.ParseIP(value) == nil
}

func validProtocol(value string) bool {
	switch value {
	case "https", "wss", "postgres", "tls":
		return true
	default:
		return false
	}
}
