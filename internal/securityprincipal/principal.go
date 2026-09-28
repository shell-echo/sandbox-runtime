// Package securityprincipal defines the closed, versioned identity vocabulary
// shared by private credential, certificate, network and evidence protocols.
// It is independent of the public Provider Contract.
package securityprincipal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
)

const (
	Schema  = "sandbox-runtime.security-principal.v1"
	Version = 1

	KindRuntimeRole     Kind = "runtime_role"
	KindMaterialAgent   Kind = "material_agent"
	KindTLSAgent        Kind = "tls_agent"
	KindMigrationJob    Kind = "migration_job"
	KindController      Kind = "controller"
	KindExecutorBackend Kind = "executor_backend"
	KindEgressBroker    Kind = "egress_broker"
	KindIngressRelay    Kind = "ingress_relay"

	RoleProduct  Role = "product"
	RoleProvider Role = "provider"
	RoleGateway  Role = "gateway"
	RoleGuest    Role = "guest"
	RoleBrowser  Role = "browser"
	RoleDesktop  Role = "desktop"

	maxDocumentBytes = 4 << 10
)

var (
	ErrInvalid           = errors.New("invalid security principal")
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	egressNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}_egress_broker$`)
	authorityNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,60}_policy_authority$`)
)

type Kind string
type Role string

type Principal struct {
	Schema            string `json:"schema"`
	Version           int    `json:"version"`
	Kind              Kind   `json:"kind"`
	Name              string `json:"name"`
	Role              Role   `json:"role"`
	InstanceDigest    string `json:"instance_digest"`
	EnvironmentDigest string `json:"environment_digest"`
	ProfileDigest     string `json:"profile_digest"`
	PrincipalDigest   string `json:"principal_digest"`
}

type Registry struct {
	environmentDigest string
	profileDigest     string
	allowed           map[Kind]map[string]Role
}

// The registry vocabulary is only one authorization layer. A name added
// here cannot become a deployment until the closed Phase 6 profile inventory,
// UID/GID, signer/socket policy and executable gate all admit it explicitly.
var builtins = map[Kind]map[string]Role{
	KindRuntimeRole: {
		"product": RoleProduct, "provider": RoleProvider, "gateway": RoleGateway,
		"guest": RoleGuest, "browser": RoleBrowser, "desktop": RoleDesktop,
		"browser_action_ingress": RoleGateway,
	},
	KindMaterialAgent: {
		"product_runtime_agent": RoleProduct, "provider_runtime_agent": RoleProvider, "gateway_agent": RoleGateway,
		"browser_action_ingress_agent": RoleGateway,
		"guest_agent":                  RoleGuest, "browser_agent": RoleBrowser, "desktop_agent": RoleDesktop,
		"product_migration_agent": RoleProduct, "provider_migration_agent": RoleProvider,
		"provider_browser_migration_agent": RoleProvider, "provider_desktop_migration_agent": RoleProvider,
	},
	KindTLSAgent: {
		"product_tls_agent": RoleProduct, "provider_tls_agent": RoleProvider,
		"gateway_tls_agent": RoleGateway, "guest_tls_agent": RoleGuest,
		"browser_action_ingress_tls_agent": RoleGateway,
		"browser_tls_agent":                RoleBrowser, "desktop_tls_agent": RoleDesktop,
		"browser_executor_tls_agent": RoleBrowser, "desktop_executor_tls_agent": RoleDesktop,
		"browser_action_ingress_agent_tls_agent": RoleGateway,
		"browser_agent_tls_agent":                RoleBrowser, "desktop_agent_tls_agent": RoleDesktop,
		"gateway_agent_tls_agent": RoleGateway, "guest_agent_tls_agent": RoleGuest,
		"product_migration_agent_tls_agent": RoleProduct, "product_runtime_agent_tls_agent": RoleProduct,
		"provider_browser_runtime_agent_tls_agent": RoleProvider,
		"provider_desktop_runtime_agent_tls_agent": RoleProvider,
		"provider_migration_agent_tls_agent":       RoleProvider, "provider_runtime_agent_tls_agent": RoleProvider,
		"provider_browser_migration_agent_tls_agent": RoleProvider,
		"provider_desktop_migration_agent_tls_agent": RoleProvider,
		"product_postgres_tls_agent":                 RoleProduct, "gateway_postgres_tls_agent": RoleGateway,
		"provider_postgres_tls_agent":                   RoleProvider,
		"product_migration_postgres_tls_agent":          RoleProduct,
		"provider_migration_postgres_tls_agent":         RoleProvider,
		"provider_browser_migration_postgres_tls_agent": RoleProvider,
		"provider_desktop_migration_postgres_tls_agent": RoleProvider,
	},
	KindMigrationJob: {
		"product_migration": RoleProduct, "provider_migration": RoleProvider,
		"provider_browser_migration": RoleProvider, "provider_desktop_migration": RoleProvider,
	},
	KindController: {
		"credential_controller": "", "certificate_controller": "", "break_glass_controller": "",
	},
	KindExecutorBackend: {
		"browser_executor": RoleBrowser, "desktop_executor": RoleDesktop,
	},
	KindIngressRelay: {
		"public_ingress_relay": "",
	},
}

func NewRegistry(environmentDigest, profileDigest string, egressBrokers map[string]Role) (*Registry, error) {
	return NewRegistryWithPolicyAuthorities(environmentDigest, profileDigest, egressBrokers, nil)
}

func NewRegistryWithPolicyAuthorities(environmentDigest, profileDigest string, egressBrokers map[string]Role, authorities map[string]Role) (*Registry, error) {
	if !digestPattern.MatchString(environmentDigest) || !digestPattern.MatchString(profileDigest) || len(egressBrokers) > 128 {
		return nil, ErrInvalid
	}
	registry := &Registry{environmentDigest: environmentDigest, profileDigest: profileDigest, allowed: make(map[Kind]map[string]Role, len(builtins)+1)}
	for kind, names := range builtins {
		registry.allowed[kind] = make(map[string]Role, len(names))
		for name, role := range names {
			registry.allowed[kind][name] = role
		}
	}
	registry.allowed[KindEgressBroker] = make(map[string]Role, len(egressBrokers))
	for name, role := range egressBrokers {
		tlsAgentName := name + "_tls_agent"
		if !egressNamePattern.MatchString(name) || !validRole(role) || len(tlsAgentName) > 64 {
			return nil, ErrInvalid
		}
		registry.allowed[KindEgressBroker][name] = role
		registry.allowed[KindTLSAgent][tlsAgentName] = role
	}
	if len(authorities) > 128 {
		return nil, ErrInvalid
	}
	for name, role := range authorities {
		if !authorityNamePattern.MatchString(name) || role != "" {
			return nil, ErrInvalid
		}
		if _, exists := registry.allowed[KindController][name]; exists {
			return nil, ErrInvalid
		}
		registry.allowed[KindController][name] = role
	}
	return registry, nil
}

func (r *Registry) New(kind Kind, name string, role Role, instanceDigest string) (Principal, error) {
	principal := Principal{Schema: Schema, Version: Version, Kind: kind, Name: name, Role: role, InstanceDigest: instanceDigest}
	if r != nil {
		principal.EnvironmentDigest, principal.ProfileDigest = r.environmentDigest, r.profileDigest
	}
	principal.PrincipalDigest = digest(principal)
	if r.Validate(principal) != nil {
		return Principal{}, ErrInvalid
	}
	return principal, nil
}

func (r *Registry) Validate(principal Principal) error {
	if r == nil || principal.Schema != Schema || principal.Version != Version || !digestPattern.MatchString(principal.InstanceDigest) ||
		principal.EnvironmentDigest != r.environmentDigest || principal.ProfileDigest != r.profileDigest ||
		principal.PrincipalDigest != digest(principal) || !digestPattern.MatchString(principal.PrincipalDigest) {
		return ErrInvalid
	}
	names, ok := r.allowed[principal.Kind]
	if !ok {
		return ErrInvalid
	}
	role, ok := names[principal.Name]
	if !ok || role != principal.Role {
		return ErrInvalid
	}
	return nil
}

func (r *Registry) Decode(document []byte) (Principal, error) {
	var principal Principal
	if len(document) < 1 || len(document) > maxDocumentBytes || rejectDuplicateJSON(document) != nil {
		return Principal{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&principal) != nil {
		return Principal{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Principal{}, ErrInvalid
	}
	canonical, err := json.Marshal(principal)
	if err != nil || !bytes.Equal(canonical, document) || r.Validate(principal) != nil {
		return Principal{}, ErrInvalid
	}
	return principal, nil
}

func (r *Registry) Encode(principal Principal) ([]byte, error) {
	if r.Validate(principal) != nil {
		return nil, ErrInvalid
	}
	document, err := json.Marshal(principal)
	if err != nil || len(document) > maxDocumentBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func (r *Registry) Names(kind Kind) []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.allowed[kind]))
	for name := range r.allowed[kind] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p Principal) Digest() string { return p.PrincipalDigest }

func digest(principal Principal) string {
	principal.PrincipalDigest = ""
	document, _ := json.Marshal(principal)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/security-principal/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validRole(role Role) bool {
	switch role {
	case RoleProduct, RoleProvider, RoleGateway, RoleGuest, RoleBrowser, RoleDesktop:
		return true
	default:
		return false
	}
}

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var scan func(json.Token) error
	scan = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
