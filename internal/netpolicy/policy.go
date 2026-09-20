// Package netpolicy implements the deterministic egress checks shared by
// private Browser/Desktop roles. It does not perform DNS itself; callers must
// supply every resolved address for the dial attempt so rebinding cannot bypass
// the policy.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrDenied  = errors.New("network destination denied by policy")
	ErrInvalid = errors.New("invalid network policy")
	ErrDial    = errors.New("network destination could not be reached")
)

var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?$`)

var blockedCIDRs = mustCIDRs([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
})

type Policy struct {
	AllowedHosts []string
	AllowedPorts map[int]struct{}
}

func New(allowedHosts []string, allowedPorts []int) (Policy, error) {
	if len(allowedHosts) == 0 || len(allowedHosts) > 256 || len(allowedPorts) == 0 || len(allowedPorts) > 64 {
		return Policy{}, ErrInvalid
	}
	hosts := make([]string, 0, len(allowedHosts))
	seenHosts := make(map[string]struct{}, len(allowedHosts))
	for _, value := range allowedHosts {
		host := strings.ToLower(strings.TrimSpace(value))
		if host != value || !hostPattern.MatchString(host) || strings.Contains(host, "..") || strings.HasPrefix(host, ".") || net.ParseIP(host) != nil {
			return Policy{}, fmt.Errorf("%w: host", ErrInvalid)
		}
		if _, exists := seenHosts[host]; exists {
			return Policy{}, ErrInvalid
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	ports := make(map[int]struct{}, len(allowedPorts))
	for _, port := range allowedPorts {
		if port < 1 || port > 65535 {
			return Policy{}, ErrInvalid
		}
		ports[port] = struct{}{}
	}
	return Policy{AllowedHosts: hosts, AllowedPorts: ports}, nil
}

func (p Policy) Check(host string, port int, resolved []net.IP) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host != strings.TrimSpace(host) || !hostPattern.MatchString(host) || net.ParseIP(host) != nil {
		return ErrDenied
	}
	allowedHost := false
	for _, candidate := range p.AllowedHosts {
		if host == candidate {
			allowedHost = true
			break
		}
	}
	if !allowedHost {
		return ErrDenied
	}
	if _, ok := p.AllowedPorts[port]; !ok {
		return ErrDenied
	}
	if len(resolved) == 0 {
		return ErrDenied
	}
	for _, address := range resolved {
		if address == nil || isBlocked(address) {
			return ErrDenied
		}
	}
	return nil
}

// IPResolver is the only DNS capability accepted by DialContext. Callers
// must pass the same resolver used for the connection attempt so every
// returned address is checked before a socket is opened.
type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// ContextDialer is intentionally narrower than net.Dialer. A role can wrap
// it to enforce a network namespace or a service-account-specific socket
// policy without widening this package's authority.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// DialContext resolves host once, validates the complete answer set, and
// then dials only one of those validated addresses. It never dials a name
// directly, which prevents a resolver answer from changing between policy
// evaluation and connection establishment.
func (p Policy) DialContext(ctx context.Context, resolver IPResolver, dialer ContextDialer, host string, port int) (net.Conn, error) {
	if ctx == nil || resolver == nil || dialer == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	answers, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(answers) == 0 {
		return nil, ErrDenied
	}
	resolved := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		resolved = append(resolved, answer.IP)
	}
	if err := p.Check(host, port, resolved); err != nil {
		return nil, err
	}
	for _, answer := range answers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(answer.IP.String(), fmt.Sprint(port)))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, ErrDial
}

func isBlocked(address net.IP) bool {
	for _, network := range blockedCIDRs {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

func mustCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		result = append(result, network)
	}
	return result
}
