//go:build phase6slice6gate

package productphase6gate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6MigrationPostgresBridgeMemberIsExact(t *testing.T) {
	const networkID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const postgresID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const wrongID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	expected := phase6security.Network{Name: "service-product-migration-job-postgres", Kind: "service_bridge",
		Internal: true, GatewayModeIPv4: "isolated", IPv4Subnet: "10.77.0.0/24",
		ExternalServices: []string{"postgres"}}
	base := map[string]any{
		"Name": expected.Name, "Id": networkID, "Driver": "bridge", "Scope": "local",
		"Internal": true, "Attachable": false, "Ingress": false,
		"EnableIPv4": true, "EnableIPv6": false,
		"Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
			"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"},
		"IPAM":       map[string]any{"Config": []map[string]string{{"Subnet": expected.IPv4Subnet, "Gateway": ""}}},
		"Containers": map[string]any{postgresID: map[string]string{"IPv4Address": "10.77.0.3/24"}},
	}
	encode := func(value map[string]any) []byte {
		t.Helper()
		result, err := json.Marshal([]any{value})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if err := slice6VerifyMigrationPostgresBridge(encode(base), expected,
		networkID, postgresID, "10.77.0.3"); err != nil {
		t.Fatalf("same-run PostgreSQL service rejected: %v", err)
	}
	for _, candidate := range []struct {
		name    string
		mutate  func(map[string]any, *phase6security.Network)
		checkID string
	}{
		{"vault member", func(_ map[string]any, network *phase6security.Network) {
			network.ExternalServices = []string{"vault"}
		}, postgresID},
		{"wrong container", func(value map[string]any, _ *phase6security.Network) {
			value["Containers"] = map[string]any{wrongID: map[string]string{"IPv4Address": "10.77.0.3/24"}}
		}, postgresID},
		{"extra member", func(value map[string]any, _ *phase6security.Network) {
			value["Containers"] = map[string]any{postgresID: map[string]string{"IPv4Address": "10.77.0.3/24"},
				wrongID: map[string]string{"IPv4Address": "10.77.0.4/24"}}
		}, postgresID},
		{"wrong IP", func(value map[string]any, _ *phase6security.Network) {
			value["Containers"] = map[string]any{postgresID: map[string]string{"IPv4Address": "10.77.0.4/24"}}
		}, postgresID},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			value := make(map[string]any, len(base))
			for key, item := range base {
				value[key] = item
			}
			network := expected
			candidate.mutate(value, &network)
			if err := slice6VerifyMigrationPostgresBridge(encode(value), network,
				networkID, candidate.checkID, "10.77.0.3"); err == nil {
				t.Fatal("wrong PostgreSQL bridge member admitted")
			}
		})
	}
}

func TestSlice6MigrationCreatedNetworksSeparateRequestedFromEffective(t *testing.T) {
	serviceID, dedicatedID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	serviceName, dedicatedName := "service-product-migration-job-postgres", "network-product-migration-job"
	makeEndpoint := func(ip, networkID string) slice6MigrationNetworkEndpoint {
		value := slice6MigrationNetworkEndpoint{NetworkID: networkID}
		value.IPAMConfig.IPv4Address = ip
		return value
	}
	base := map[string]slice6MigrationNetworkEndpoint{
		serviceID:     makeEndpoint("10.77.0.2", ""),
		dedicatedName: makeEndpoint("10.78.0.2", ""),
	}
	check := func(values map[string]slice6MigrationNetworkEndpoint) error {
		return slice6ValidateMigrationCreatedNetworks(values, serviceID, serviceName, "10.77.0.2",
			dedicatedID, dedicatedName, "10.78.0.2")
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name   string
		mutate func(map[string]slice6MigrationNetworkEndpoint)
	}{
		{"wrong requested IP", func(value map[string]slice6MigrationNetworkEndpoint) {
			value[serviceID] = makeEndpoint("10.77.0.9", "")
		}},
		{"conflicting effective ID", func(value map[string]slice6MigrationNetworkEndpoint) {
			value[serviceID] = makeEndpoint("10.77.0.2", dedicatedID)
		}},
		{"duplicate alias", func(value map[string]slice6MigrationNetworkEndpoint) {
			value[serviceName] = makeEndpoint("10.77.0.2", "")
		}},
		{"extra network", func(value map[string]slice6MigrationNetworkEndpoint) {
			value["unreviewed"] = makeEndpoint("10.79.0.2", "")
		}},
		{"missing network", func(value map[string]slice6MigrationNetworkEndpoint) {
			delete(value, dedicatedName)
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			value := make(map[string]slice6MigrationNetworkEndpoint, len(base)+1)
			for key, item := range base {
				value[key] = item
			}
			candidate.mutate(value)
			if err := check(value); err == nil {
				t.Fatal("unsafe pre-start network request admitted")
			}
		})
	}
}

func TestSlice6MigrationFailureCategoryIsClosed(t *testing.T) {
	for _, candidate := range []struct{ output, expected string }{
		{"migration v2 PostgreSQL connection is unavailable", "migration-connect"},
		{"Phase 6 core startup file owner mismatch", "core-file-uid"},
		{"apply migrations: password=private-key", "unknown"},
		{"", "unknown"},
	} {
		if got := slice6MigrationFailureCategory([]byte(candidate.output)); got != candidate.expected ||
			strings.Contains(got, "password") || strings.Contains(got, "private-key") {
			t.Fatal("migration error category escaped its fixed allowlist")
		}
	}
}
