package providerapi

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
)

const maxCompactBearerBytes = 8 << 10

// clientIdentityAdmission freezes the Provider mTLS allowlist and selects one
// exact caller from TLS verification state. It is shared by the handshake and
// protected-request extraction so both layers make the same caller decision.
type clientIdentityAdmission struct {
	allowed map[string]struct{}
}

func (a *clientIdentityAdmission) VerifyConnection(state tls.ConnectionState) error {
	_, err := a.Caller(state)
	return err
}

// Caller returns the one URI SAN that is both present in the verified client
// leaf and in the frozen allowlist. Multiple URI SANs are permitted only when
// exactly one is allowed; multiple eligible identities are ambiguous and fail
// closed rather than selecting an arbitrary bearer-binding principal.
func (a *clientIdentityAdmission) Caller(state tls.ConnectionState) (string, error) {
	if a == nil || len(a.allowed) == 0 {
		return "", errors.New("provider mTLS identity admission is unavailable")
	}
	leaf, err := verifiedClientLeaf(state)
	if err != nil {
		return "", err
	}
	if !hasExplicitExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
		return "", errors.New("provider mTLS client certificate lacks explicit client-auth usage")
	}

	matched := ""
	for _, identity := range leaf.URIs {
		if identity == nil {
			continue
		}
		candidate := identity.String()
		if _, allowed := a.allowed[candidate]; !allowed {
			continue
		}
		if matched != "" {
			return "", errors.New("provider mTLS client has multiple allowed URI identities")
		}
		matched = candidate
	}
	if matched == "" {
		return "", errors.New("provider mTLS client URI identity is not allowed")
	}
	return matched, nil
}

func verifiedClientLeaf(state tls.ConnectionState) (*x509.Certificate, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, errors.New("provider mTLS client has no verified certificate chain")
	}
	leaf := state.VerifiedChains[0][0]
	if leaf == nil {
		return nil, errors.New("provider mTLS client has no verified leaf certificate")
	}
	return leaf, nil
}

// protectedRequestFacts holds transient request material for the future
// protected Provider transport. It is deliberately unexported so callers
// cannot treat a raw bearer as a stable application value.
type protectedRequestFacts struct {
	caller        string
	compactBearer string
}

func (a *clientIdentityAdmission) protectedFacts(request *http.Request) (protectedRequestFacts, error) {
	if request == nil || request.TLS == nil {
		return protectedRequestFacts{}, errors.New("protected Provider request has no TLS state")
	}
	caller, err := a.Caller(*request.TLS)
	if err != nil {
		return protectedRequestFacts{}, err
	}
	bearer, err := extractCompactBearer(request.Header.Values("Authorization"))
	if err != nil {
		return protectedRequestFacts{}, err
	}
	return protectedRequestFacts{caller: caller, compactBearer: bearer}, nil
}

func extractCompactBearer(values []string) (string, error) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", errors.New("protected Provider request has an invalid bearer header")
	}
	bearer := strings.TrimPrefix(values[0], "Bearer ")
	if len(bearer) == 0 || len(bearer) > maxCompactBearerBytes || strings.ContainsAny(bearer, " \t\r\n") {
		return "", errors.New("protected Provider request has an invalid bearer header")
	}
	return bearer, nil
}
