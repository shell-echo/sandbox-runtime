package qualificationadapterprotocol

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

func TestInvocationLocationsAcceptCanonicalValues(t *testing.T) {
	schema := loadProtocolSchemaForLocationTest(t)
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "profile path", field: "profile_path", value: "/run/p27/profile.json"},
		{name: "state root", field: "caller_state_root", value: "/var/tmp/sandbox-runtime-qualification/state-a"},
		{name: "single-label provider", field: "provider_origin", value: "https://a"},
		{name: "digit-leading DNS label", field: "provider_origin", value: "https://3scale.example"},
		{name: "non-numeric hexadecimal prefix", field: "provider_origin", value: "https://provider.0xg"},
		{name: "decimal-looking alphanumeric label", field: "provider_origin", value: "https://example.1e2"},
		{name: "hex-letter DNS labels", field: "provider_origin", value: "https://dead.beef"},
		{name: "provider DNS and port", field: "provider_origin", value: "https://provider.invalid:8443"},
		{name: "provider IPv4", field: "provider_origin", value: "https://127.0.0.1:8443"},
		{name: "provider IPv6", field: "provider_origin", value: "https://[2001:db8::1]:8443"},
		{name: "single-label gateway root", field: "gateway_probe_endpoint", value: "wss://a/"},
		{name: "gateway DNS and path", field: "gateway_probe_endpoint", value: "wss://gateway.invalid:8443/terminal"},
		{name: "gateway HTTPS", field: "gateway_probe_endpoint", value: "https://127.0.0.1:9444/probe"},
		{name: "gateway IPv6 and colon path", field: "gateway_probe_endpoint", value: "https://[2001:db8::1]:9444/api/terminal:connect"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validInvocationLocationFields()
			setLocationField(&fields, test.field, test.value)
			if err := validateInvocationLocationFields(fields); err != nil {
				t.Fatalf("semantic validation rejected canonical value: %v", err)
			}
			if err := schema.Validate(invocationWithLocations(fields)); err != nil {
				t.Fatalf("schema rejected canonical value: %v", err)
			}
		})
	}
}

func TestInvocationLocationsRejectAmbiguousOrUnsafeValues(t *testing.T) {
	schema := loadProtocolSchemaForLocationTest(t)
	tests := []struct {
		name             string
		field            string
		value            string
		schemaMustReject bool
	}{
		{name: "relative profile path", field: "profile_path", value: "profile.json", schemaMustReject: true},
		{name: "filesystem root", field: "profile_path", value: "/", schemaMustReject: true},
		{name: "repeated path separator", field: "profile_path", value: "/a//b", schemaMustReject: true},
		{name: "dot path segment", field: "profile_path", value: "/a/./b", schemaMustReject: true},
		{name: "parent path segment", field: "profile_path", value: "/a/../b", schemaMustReject: true},
		{name: "network-style path", field: "profile_path", value: "//host/share", schemaMustReject: true},
		{name: "Windows path", field: "caller_state_root", value: `C:\state`, schemaMustReject: true},
		{name: "percent path alias", field: "caller_state_root", value: "/a/%2e%2e/b", schemaMustReject: true},
		{name: "space in path", field: "caller_state_root", value: "/a/with space", schemaMustReject: true},
		{name: "Unicode path", field: "caller_state_root", value: "/a/状态", schemaMustReject: true},
		{name: "trailing path separator", field: "caller_state_root", value: "/a/state/", schemaMustReject: true},
		{name: "state root equals profile", field: "caller_state_root", value: "/qualification/profile.json"},
		{name: "state root contains profile", field: "caller_state_root", value: "/qualification"},
		{name: "Provider HTTP scheme", field: "provider_origin", value: "http://provider.invalid", schemaMustReject: true},
		{name: "Provider uppercase scheme", field: "provider_origin", value: "HTTPS://provider.invalid", schemaMustReject: true},
		{name: "Provider uppercase host", field: "provider_origin", value: "https://Provider.invalid"},
		{name: "Provider empty host", field: "provider_origin", value: "https:///v1", schemaMustReject: true},
		{name: "Provider root path", field: "provider_origin", value: "https://provider.invalid/", schemaMustReject: true},
		{name: "Provider route path", field: "provider_origin", value: "https://provider.invalid/v1", schemaMustReject: true},
		{name: "Provider userinfo", field: "provider_origin", value: "https://user:pass@provider.invalid", schemaMustReject: true},
		{name: "Provider bare query", field: "provider_origin", value: "https://provider.invalid?", schemaMustReject: true},
		{name: "Provider query", field: "provider_origin", value: "https://provider.invalid?operation_id=x", schemaMustReject: true},
		{name: "Provider bare fragment", field: "provider_origin", value: "https://provider.invalid#", schemaMustReject: true},
		{name: "Provider fragment", field: "provider_origin", value: "https://provider.invalid#handoff", schemaMustReject: true},
		{name: "Provider percent host", field: "provider_origin", value: "https://provider%2einvalid", schemaMustReject: true},
		{name: "Provider backslash", field: "provider_origin", value: `https://provider.invalid\v1`, schemaMustReject: true},
		{name: "Provider zero port", field: "provider_origin", value: "https://provider.invalid:0"},
		{name: "Provider oversized port", field: "provider_origin", value: "https://provider.invalid:65536"},
		{name: "Provider leading-zero port", field: "provider_origin", value: "https://provider.invalid:0443"},
		{name: "Provider plus-sign port", field: "provider_origin", value: "https://provider.invalid:+8443"},
		{name: "Provider explicit default port", field: "provider_origin", value: "https://provider.invalid:443"},
		{name: "Provider IPv4 abbreviation", field: "provider_origin", value: "https://127.1"},
		{name: "Provider legacy IPv4", field: "provider_origin", value: "https://0177.0.0.1"},
		{name: "Provider hexadecimal IPv4", field: "provider_origin", value: "https://0x7f000001"},
		{name: "Provider empty hexadecimal IPv4", field: "provider_origin", value: "https://0x"},
		{name: "Provider dotted hexadecimal IPv4", field: "provider_origin", value: "https://0x7f.0.0.1"},
		{name: "Provider numeric final DNS label", field: "provider_origin", value: "https://provider.1"},
		{name: "Provider hexadecimal final DNS label", field: "provider_origin", value: "https://provider.0x1"},
		{name: "Provider noncanonical IPv6", field: "provider_origin", value: "https://[0:0:0:0:0:0:0:1]"},
		{name: "Provider IPv4-mapped IPv6", field: "provider_origin", value: "https://[::ffff:7f00:1]"},
		{name: "Provider zoned IPv6", field: "provider_origin", value: "https://[fe80::1%25en0]", schemaMustReject: true},
		{name: "Provider Unicode host", field: "provider_origin", value: "https://例子.invalid", schemaMustReject: true},
		{name: "Provider trailing DNS dot", field: "provider_origin", value: "https://provider.invalid."},
		{name: "Gateway missing path", field: "gateway_probe_endpoint", value: "wss://gateway.invalid", schemaMustReject: true},
		{name: "Gateway non-root trailing slash", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/terminal/", schemaMustReject: true},
		{name: "Gateway repeated slash", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/a//b", schemaMustReject: true},
		{name: "Gateway dot segment", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/a/../b", schemaMustReject: true},
		{name: "Gateway percent alias", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/%41", schemaMustReject: true},
		{name: "Gateway query credential", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/terminal?token=x", schemaMustReject: true},
		{name: "Gateway fragment", field: "gateway_probe_endpoint", value: "wss://gateway.invalid/terminal#state", schemaMustReject: true},
		{name: "Gateway userinfo", field: "gateway_probe_endpoint", value: "wss://user@gateway.invalid/terminal", schemaMustReject: true},
		{name: "Gateway hexadecimal IPv4", field: "gateway_probe_endpoint", value: "wss://0x7f000001/terminal"},
		{name: "Gateway empty hexadecimal IPv4", field: "gateway_probe_endpoint", value: "wss://0x/terminal"},
		{name: "Gateway dotted hexadecimal IPv4", field: "gateway_probe_endpoint", value: "wss://0x7f.0.0.1/terminal"},
		{name: "Gateway numeric final DNS label", field: "gateway_probe_endpoint", value: "wss://gateway.1/terminal"},
		{name: "Gateway plus-sign port", field: "gateway_probe_endpoint", value: "wss://gateway.invalid:+8443/terminal"},
		{name: "Gateway explicit default port", field: "gateway_probe_endpoint", value: "wss://gateway.invalid:443/terminal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validInvocationLocationFields()
			setLocationField(&fields, test.field, test.value)
			if err := validateInvocationLocationFields(fields); err == nil {
				t.Fatal("semantic validation accepted an ambiguous or unsafe location")
			}
			if test.schemaMustReject {
				if err := schema.Validate(invocationWithLocations(fields)); err == nil {
					t.Fatal("schema accepted an ambiguity it is required to reject lexically")
				}
			}
		})
	}
}

func TestReconstructionLocationBindingRejectsEveryFieldDrift(t *testing.T) {
	initial := validInvocationLocationFields()
	if err := validateReconstructionLocationBinding(initial, initial); err != nil {
		t.Fatalf("identical phase locations were rejected: %v", err)
	}
	tests := []struct {
		field string
		value string
	}{
		{field: "profile_path", value: "/qualification/profile-v2.json"},
		{field: "provider_origin", value: "https://provider-alt.invalid"},
		{field: "gateway_probe_endpoint", value: "wss://gateway.invalid/terminal-v2"},
		{field: "caller_state_root", value: "/caller-state-v2"},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			reconstruction := initial
			setLocationField(&reconstruction, test.field, test.value)
			if err := validateInvocationLocationFields(reconstruction); err != nil {
				t.Fatalf("test drift is not independently valid: %v", err)
			}
			if err := validateReconstructionLocationBinding(initial, reconstruction); err == nil {
				t.Fatal("location drift was accepted across phase invocations")
			}
		})
	}
}

func TestValidateSemanticsRejectsLocationPolicyDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "freeze order",
			mutate: func(policy map[string]any) {
				policy["values_frozen_before"] = []any{"adapter-process-start"}
			},
		},
		{
			name: "configuration commitment",
			mutate: func(policy map[string]any) {
				policy["values_commitment"] = "unbound"
			},
		},
		{
			name: "definition verifier runtime claim",
			mutate: func(policy map[string]any) {
				policy["definition_verifier_claims_derivation_or_order_proof"] = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeStrictObject(content)
			if err != nil {
				t.Fatal(err)
			}
			invocation := value["invocation"].(map[string]any)
			policy := invocation["location_policy"].(map[string]any)
			test.mutate(policy)
			if err := validateSemantics(value); err == nil {
				t.Fatal("validateSemantics accepted location policy drift")
			}
		})
	}
}

func loadProtocolSchemaForLocationTest(t *testing.T) *jsonschema.Schema {
	t.Helper()
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", qualificationreport.ReportSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validInvocationLocationFields() invocationLocationFields {
	return invocationLocationFields{
		ProfilePath:          "/qualification/profile.json",
		ProviderOrigin:       "https://provider.invalid",
		GatewayProbeEndpoint: "wss://gateway.invalid/terminal",
		CallerStateRoot:      "/caller-state",
	}
}

func setLocationField(fields *invocationLocationFields, field, value string) {
	switch field {
	case "profile_path":
		fields.ProfilePath = value
	case "provider_origin":
		fields.ProviderOrigin = value
	case "gateway_probe_endpoint":
		fields.GatewayProbeEndpoint = value
	case "caller_state_root":
		fields.CallerStateRoot = value
	default:
		panic("unknown location field: " + field)
	}
}

func invocationWithLocations(fields invocationLocationFields) map[string]any {
	message := invocationExampleForSchemaTest()
	message["profile_path"] = fields.ProfilePath
	message["provider_origin"] = fields.ProviderOrigin
	message["gateway_probe_endpoint"] = fields.GatewayProbeEndpoint
	message["caller_state_root"] = fields.CallerStateRoot
	return message
}
