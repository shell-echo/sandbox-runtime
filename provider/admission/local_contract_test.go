package admission

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

func TestLocalContractProtectedOperationBindings(t *testing.T) {
	type operationBinding struct {
		Operation     string `json:"operation"`
		ContractID    string `json:"contract_id"`
		DigestProfile string `json:"digest_profile"`
	}
	data, err := os.ReadFile(localAdmissionContractPath(t, "semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatalf("read local semantic rules: %v", err)
	}
	var document struct {
		Rules []struct {
			ID                string             `json:"id"`
			OperationBindings []operationBinding `json:"operation_bindings"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode local semantic rules: %v", err)
	}
	var bindings []operationBinding
	for _, rule := range document.Rules {
		if rule.ID == "protected-admission-contract-ids" {
			bindings = rule.OperationBindings
			break
		}
	}
	if len(bindings) != len(requestBindings) {
		t.Fatalf("local Contract protected bindings = %d, implementation = %d", len(bindings), len(requestBindings))
	}
	for _, binding := range bindings {
		operation := Operation(binding.Operation)
		expected, ok := requestBindings[operation]
		if !ok {
			t.Fatalf("local Contract declares unsupported operation %q", binding.Operation)
		}
		if expected.contractID != binding.ContractID || string(expected.profile) != binding.DigestProfile {
			t.Fatalf("binding %q = (%q, %q), implementation = (%q, %q)", binding.Operation, binding.ContractID, binding.DigestProfile, expected.contractID, expected.profile)
		}
	}
}

func TestLocalContractProtectedAdmissionJWSProfile(t *testing.T) {
	type schemaRef struct {
		Ref string `yaml:"$ref"`
	}
	type operation struct {
		OperationID string                `yaml:"operationId"`
		Security    []map[string][]string `yaml:"security"`
		Parameters  []schemaRef           `yaml:"parameters"`
	}
	type pathItem struct {
		Get  operation `yaml:"get"`
		Post operation `yaml:"post"`
	}
	type parameter struct {
		Name            string    `yaml:"name"`
		In              string    `yaml:"in"`
		Required        bool      `yaml:"required"`
		ExactlyOne      bool      `yaml:"x-exactly-one-value"`
		ContentEncoding string    `yaml:"x-content-encoding"`
		MaxDecodedBytes int       `yaml:"x-max-decoded-bytes"`
		DecodedSchema   schemaRef `yaml:"x-decoded-schema"`
		Schema          struct {
			MinLength int    `yaml:"minLength"`
			MaxLength int    `yaml:"maxLength"`
			Pattern   string `yaml:"pattern"`
		} `yaml:"schema"`
	}
	type securityScheme struct {
		Type            string `yaml:"type"`
		Scheme          string `yaml:"scheme"`
		BearerFormat    string `yaml:"bearerFormat"`
		MaxEncodedBytes int    `yaml:"x-max-encoded-bytes"`
		JWSProfile      struct {
			Serialization string    `yaml:"serialization"`
			HeaderSchema  schemaRef `yaml:"header-schema"`
			ClaimsSchema  schemaRef `yaml:"claims-schema"`
		} `yaml:"x-jws-profile"`
	}
	var openAPI struct {
		Paths      map[string]pathItem `yaml:"paths"`
		Components struct {
			Parameters      map[string]parameter      `yaml:"parameters"`
			SecuritySchemes map[string]securityScheme `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	openAPIData, err := os.ReadFile(localAdmissionContractPath(t, "openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(openAPIData, &openAPI); err != nil {
		t.Fatalf("decode Provider OpenAPI: %v", err)
	}

	const admissionHeaderRef = "#/components/parameters/AdmissionContextHeader"
	protectedOperations := 0
	for path, item := range openAPI.Paths {
		for _, operation := range []operation{item.Get, item.Post} {
			if operation.OperationID == "" {
				continue
			}
			hasBearer := false
			for _, security := range operation.Security {
				_, hasBearer = security["bearerAuth"]
				if hasBearer {
					break
				}
			}
			headerRefs := 0
			for _, candidate := range operation.Parameters {
				if candidate.Ref == admissionHeaderRef {
					headerRefs++
				}
			}
			if hasBearer {
				protectedOperations++
				if headerRefs != 1 {
					t.Fatalf("protected OpenAPI operation %q Admission Context header refs = %d", operation.OperationID, headerRefs)
				}
			} else if path == "/v1/capabilities" && headerRefs != 0 {
				t.Fatal("capability discovery declares the protected Admission Context header")
			}
		}
	}
	if protectedOperations != 19 {
		t.Fatalf("protected OpenAPI operations = %d, want 19", protectedOperations)
	}

	headerParameter := openAPI.Components.Parameters["AdmissionContextHeader"]
	if headerParameter.Name != AdmissionContextHeader || headerParameter.In != "header" || !headerParameter.Required || !headerParameter.ExactlyOne || headerParameter.ContentEncoding != "base64url-unpadded" || headerParameter.MaxDecodedBytes != MaxAdmissionContextBytes || headerParameter.Schema.MinLength != 1 || headerParameter.Schema.MaxLength != MaxAdmissionContextBytes || headerParameter.Schema.Pattern != "^[A-Za-z0-9_-]+$" || headerParameter.DecodedSchema.Ref != "../schemas/admission-context.schema.json" {
		t.Fatalf("Admission Context OpenAPI parameter = %#v", headerParameter)
	}
	bearer := openAPI.Components.SecuritySchemes["bearerAuth"]
	if bearer.Type != "http" || bearer.Scheme != "bearer" || bearer.BearerFormat != "compact-jws" || bearer.MaxEncodedBytes != maxCompactJWSBytes || bearer.JWSProfile.Serialization != "compact" || bearer.JWSProfile.HeaderSchema.Ref != "../schemas/protected-operation-jws-header.schema.json" || bearer.JWSProfile.ClaimsSchema.Ref != "../schemas/protected-operation-jws-claims.schema.json" {
		t.Fatalf("bearerAuth OpenAPI profile = %#v", bearer)
	}

	var fixture struct {
		ConfiguredAuthority struct {
			Issuer                    string   `json:"issuer"`
			ProviderInstanceAudience  string   `json:"provider_instance_audience"`
			ProviderRevisionID        string   `json:"provider_revision_id"`
			AdmittedControllerURISANs []string `json:"admitted_controller_uri_sans"`
			VerificationKeyIDs        []string `json:"verification_key_ids"`
		} `json:"configured_authority"`
		Header                  map[string]any `json:"header"`
		Claims                  map[string]any `json:"claims"`
		AdmissionContextFixture string         `json:"admission_context_fixture"`
		ExpectedStatus          string         `json:"expected_status"`
	}
	readLocalAdmissionJSON(t, "fixtures/protected-admission-jws-profile.json", &fixture)
	if fixture.ExpectedStatus != "accepted" || fixture.AdmissionContextFixture != "admission-context.json" {
		t.Fatalf("protected admission accepted fixture metadata = %#v", fixture)
	}
	headerSchema := compileLocalAdmissionSchema(t, "schemas/protected-operation-jws-header.schema.json", "urn:shell-echo:sandbox-runtime:contract:protected-operation-jws-header:v1")
	claimsSchema := compileLocalAdmissionSchema(t, "schemas/protected-operation-jws-claims.schema.json", "urn:shell-echo:sandbox-runtime:contract:protected-operation-jws-claims:v1")
	assertClosedRequiredDocument(t, headerSchema, fixture.Header, 3)
	assertClosedRequiredDocument(t, claimsSchema, fixture.Claims, 24)

	legacyHeader := cloneAdmissionDocument(fixture.Header)
	legacyHeader["typ"] = "agent-sandbox-operation+jwt"
	if err := headerSchema.Validate(legacyHeader); err == nil {
		t.Fatal("protected JWS header Schema accepts the retired typ")
	}
	missingContextClaims := cloneAdmissionDocument(fixture.Claims)
	delete(missingContextClaims, "admission_context_contract_id")
	delete(missingContextClaims, "admission_context_digest_profile")
	delete(missingContextClaims, "admission_context_digest")
	if err := claimsSchema.Validate(missingContextClaims); err == nil {
		t.Fatal("protected JWS claims Schema accepts missing Admission Context binding")
	}

	contextData, err := os.ReadFile(localAdmissionContractPath(t, "fixtures/"+fixture.AdmissionContextFixture))
	if err != nil {
		t.Fatal(err)
	}
	var fixtureContext AdmissionContext
	if err := json.Unmarshal(contextData, &fixtureContext); err != nil {
		t.Fatalf("decode locked Admission Context fixture JSON: %v", err)
	}
	if !validAdmissionContext(fixtureContext) {
		t.Fatal("locked Admission Context fixture fails implementation shape validation")
	}
	computedContextDigest, err := DigestForAdmissionContext(fixtureContext)
	if err != nil {
		t.Fatalf("digest locked Admission Context fixture: %v", err)
	}
	if computedContextDigest != fixtureContext.ContextDigest {
		t.Fatalf("locked Admission Context digest = %q, want %q", fixtureContext.ContextDigest, computedContextDigest)
	}
	admissionContext, err := DecodeAdmissionContextCarrier(base64.RawURLEncoding.EncodeToString(contextData))
	if err != nil {
		t.Fatalf("decode locked Admission Context fixture: %v", err)
	}
	if fixture.Claims["iss"] != fixture.ConfiguredAuthority.Issuer || fixture.Claims["sub"] != admissionContext.ControllerSubject || fixture.Claims["aud"] != admissionContext.ProviderInstanceAudience || fixture.Claims["provider_revision_id"] != admissionContext.ProviderRevisionID || fixture.Claims["admission_context_digest"] != admissionContext.ContextDigest || !slices.Contains(fixture.ConfiguredAuthority.AdmittedControllerURISANs, admissionContext.ControllerSubject) || len(fixture.ConfiguredAuthority.VerificationKeyIDs) != 1 || fixture.Header["kid"] != fixture.ConfiguredAuthority.VerificationKeyIDs[0] {
		t.Fatal("accepted JWS fixture does not bind its configured authority and Admission Context")
	}

	var semantic struct {
		Rules []struct {
			ID      string `json:"id"`
			Fixture string `json:"fixture"`
			JWS     struct {
				HeaderSchema                 string `json:"header_schema"`
				ClaimsSchema                 string `json:"claims_schema"`
				MaxEncodedBytes              int    `json:"max_encoded_bytes"`
				MaximumBearerLifetimeSeconds int    `json:"maximum_bearer_lifetime_seconds"`
			} `json:"jws"`
			AdmissionContextHeader struct {
				Name                 string `json:"name"`
				ValueCount           int    `json:"value_count"`
				Encoding             string `json:"encoding"`
				MaxEncodedCharacters int    `json:"max_encoded_characters"`
				MaxDecodedBytes      int    `json:"max_decoded_bytes"`
				Schema               string `json:"schema"`
			} `json:"admission_context_header"`
		} `json:"rules"`
	}
	readLocalAdmissionJSON(t, "semantic-rules/provider-v1.json", &semantic)
	found := false
	for _, rule := range semantic.Rules {
		if rule.ID != "protected-admission-jws-profile" {
			continue
		}
		found = true
		if rule.Fixture != "protected-admission-jws-profile.json" || rule.JWS.HeaderSchema != "protected-operation-jws-header.schema.json" || rule.JWS.ClaimsSchema != "protected-operation-jws-claims.schema.json" || rule.JWS.MaxEncodedBytes != maxCompactJWSBytes || rule.JWS.MaximumBearerLifetimeSeconds != 300 || rule.AdmissionContextHeader.Name != AdmissionContextHeader || rule.AdmissionContextHeader.ValueCount != 1 || rule.AdmissionContextHeader.Encoding != "base64url-unpadded" || rule.AdmissionContextHeader.MaxEncodedCharacters != MaxAdmissionContextBytes || rule.AdmissionContextHeader.MaxDecodedBytes != MaxAdmissionContextBytes || rule.AdmissionContextHeader.Schema != "admission-context.schema.json" {
			t.Fatalf("protected admission JWS semantic rule = %#v", rule)
		}
	}
	if !found {
		t.Fatal("local Contract omits protected-admission-jws-profile")
	}
}

func TestLocalContractProtectedAdmissionIssuerLocalAuthorityBinding(t *testing.T) {
	type rejectionCase struct {
		Name           string         `json:"name"`
		Presented      map[string]any `json:"presented"`
		ExpectedStatus int            `json:"expected_status"`
		ExpectedClass  string         `json:"expected_class"`
	}
	var fixture struct {
		ConfiguredAuthority struct {
			Issuer                    string   `json:"issuer"`
			ProviderInstanceAudience  string   `json:"provider_instance_audience"`
			ProviderRevisionID        string   `json:"provider_revision_id"`
			AdmittedControllerURISANs []string `json:"admitted_controller_uri_sans"`
			VerificationKeyIDs        []string `json:"verification_key_ids"`
		} `json:"configured_authority"`
		Cases []rejectionCase `json:"cases"`
	}
	readLocalAdmissionJSON(t, "fixtures/protected-admission-issuer-rejections.json", &fixture)
	authority, err := NewAdmissionAuthority(fixture.ConfiguredAuthority.Issuer, fixture.ConfiguredAuthority.ProviderRevisionID, fixture.ConfiguredAuthority.ProviderInstanceAudience)
	if err != nil {
		t.Fatalf("construct fixture authority: %v", err)
	}
	if authority.Issuer() != fixture.ConfiguredAuthority.Issuer || authority.ProviderRevisionID() != fixture.ConfiguredAuthority.ProviderRevisionID || authority.ProviderInstanceAudience() != fixture.ConfiguredAuthority.ProviderInstanceAudience || len(fixture.ConfiguredAuthority.AdmittedControllerURISANs) != 1 || len(fixture.ConfiguredAuthority.VerificationKeyIDs) != 1 {
		t.Fatalf("configured fixture authority = %#v", fixture.ConfiguredAuthority)
	}

	wantCases := map[string]struct {
		status int
		class  string
	}{
		"issuer substitution": {401, "authentication"},
		"legacy issuer without explicit legacy configuration":   {401, "authentication"},
		"fragment-bearing issuer":                               {401, "authentication"},
		"unknown issuer-scoped key":                             {401, "authentication"},
		"invalid signature":                                     {401, "authentication"},
		"verified token subject differs from selected URI SAN":  {403, "authorization"},
		"caller documents agree on non-local audience":          {403, "authorization"},
		"caller documents agree on non-local provider revision": {403, "authorization"},
	}
	if len(fixture.Cases) != len(wantCases) {
		t.Fatalf("issuer rejection cases = %d, want %d", len(fixture.Cases), len(wantCases))
	}
	for _, candidate := range fixture.Cases {
		want, ok := wantCases[candidate.Name]
		if !ok || candidate.ExpectedStatus != want.status || candidate.ExpectedClass != want.class || len(candidate.Presented) == 0 {
			t.Fatalf("issuer rejection case = %#v", candidate)
		}
		delete(wantCases, candidate.Name)
	}
	if len(wantCases) != 0 {
		t.Fatalf("missing issuer rejection cases = %#v", wantCases)
	}

	var semantic struct {
		Rules []struct {
			ID      string `json:"id"`
			Fixture string `json:"fixture"`
			Issuer  struct {
				Source            string `json:"source"`
				Cardinality       string `json:"cardinality"`
				Type              string `json:"type"`
				MinCharacters     int    `json:"min_characters"`
				MaxCharacters     int    `json:"max_characters"`
				ColonPresent      string `json:"colon_present"`
				Fragment          string `json:"fragment"`
				Comparison        string `json:"comparison"`
				LegacyOpaqueValue string `json:"legacy_opaque_value"`
				LegacyMode        string `json:"legacy_mode"`
			} `json:"issuer"`
			LocalAuthority struct {
				AudienceSource                             string `json:"audience_source"`
				ProviderRevisionSource                     string `json:"provider_revision_source"`
				CallerDocumentsMustIndependentlyMatchLocal bool   `json:"caller_documents_must_independently_match_local_values"`
			} `json:"local_authority"`
			KeyRotation struct {
				Mode                        string `json:"mode"`
				KIDNamespace                string `json:"kid_namespace"`
				OldKeyRetirementWaitSeconds int    `json:"old_key_retirement_wait_seconds"`
				RemoteDiscovery             string `json:"remote_discovery"`
			} `json:"key_rotation"`
			Errors  map[string]int `json:"errors"`
			Forbids []string       `json:"forbids"`
		} `json:"rules"`
	}
	readLocalAdmissionJSON(t, "semantic-rules/provider-v1.json", &semantic)
	found := false
	for _, rule := range semantic.Rules {
		if rule.ID != "protected-admission-issuer-local-authority-binding" {
			continue
		}
		found = true
		if rule.Fixture != "protected-admission-issuer-rejections.json" || rule.Issuer.Source != "provider-listener-configuration" || rule.Issuer.Cardinality != "exactly-one" || rule.Issuer.Type != "jwt-string-or-uri" || rule.Issuer.MinCharacters != 1 || rule.Issuer.MaxCharacters != maxAdmissionAuthorityTextRunes || rule.Issuer.ColonPresent != "must-be-absolute-uri" || rule.Issuer.Fragment != "forbidden" || rule.Issuer.Comparison != "exact-case-sensitive" || rule.Issuer.LegacyOpaqueValue != "agent-platform" || rule.Issuer.LegacyMode != "explicit-configuration-only" || rule.LocalAuthority.AudienceSource != "provider-listener-configuration" || rule.LocalAuthority.ProviderRevisionSource != "immutable-local-capability-revision" || !rule.LocalAuthority.CallerDocumentsMustIndependentlyMatchLocal || rule.KeyRotation.Mode != "bounded-overlap-and-listener-restart" || rule.KeyRotation.KIDNamespace != "configured-issuer" || rule.KeyRotation.OldKeyRetirementWaitSeconds != 300 || rule.KeyRotation.RemoteDiscovery != "forbidden" {
			t.Fatalf("issuer local-authority semantic rule = %#v", rule)
		}
		wantErrors := map[string]int{"invalid_issuer": 401, "unknown_issuer": 401, "unknown_key": 401, "invalid_signature": 401, "verified_wrong_mtls_subject": 403, "verified_wrong_local_audience": 403, "verified_wrong_local_provider_revision": 403}
		if len(rule.Errors) != len(wantErrors) {
			t.Fatalf("issuer error classes = %#v", rule.Errors)
		}
		for name, status := range wantErrors {
			if rule.Errors[name] != status {
				t.Fatalf("issuer error %q = %d, want %d", name, rule.Errors[name], status)
			}
		}
		for _, forbidden := range []string{"default-issuer", "fallback-issuer", "fragment-bearing-issuer", "bearer-selected-trust-bundle", "simultaneous-multi-issuer-listener", "certificate-thumbprint-binding", "jwt-cnf-binding"} {
			if !slices.Contains(rule.Forbids, forbidden) {
				t.Fatalf("issuer semantic rule omits forbidden behavior %q", forbidden)
			}
		}
	}
	if !found {
		t.Fatal("local Contract omits protected-admission-issuer-local-authority-binding")
	}
}

func compileLocalAdmissionSchema(t *testing.T, relative, id string) *jsonschema.Schema {
	t.Helper()
	var document any
	readLocalAdmissionJSON(t, relative, &document)
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(id, document); err != nil {
		t.Fatalf("register local Contract Schema %s: %v", relative, err)
	}
	schema, err := compiler.Compile(id)
	if err != nil {
		t.Fatalf("compile local Contract Schema %s: %v", relative, err)
	}
	return schema
}

func assertClosedRequiredDocument(t *testing.T, schema *jsonschema.Schema, document map[string]any, wantProperties int) {
	t.Helper()
	if len(document) != wantProperties {
		t.Fatalf("accepted document properties = %d, want %d", len(document), wantProperties)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("validate accepted document: %v", err)
	}
	for property := range document {
		missing := cloneAdmissionDocument(document)
		delete(missing, property)
		if err := schema.Validate(missing); err == nil {
			t.Fatalf("Schema accepts missing required property %q", property)
		}
	}
	extra := cloneAdmissionDocument(document)
	extra["unknown"] = true
	if err := schema.Validate(extra); err == nil {
		t.Fatal("Schema accepts an unknown property")
	}
}

func cloneAdmissionDocument(document map[string]any) map[string]any {
	clone := make(map[string]any, len(document))
	for key, value := range document {
		clone[key] = value
	}
	return clone
}

func readLocalAdmissionJSON(t *testing.T, relative string, target any) {
	t.Helper()
	data, err := os.ReadFile(localAdmissionContractPath(t, relative))
	if err != nil {
		t.Fatalf("read local Contract resource %s: %v", relative, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode local Contract resource %s: %v", relative, err)
	}
}

func localAdmissionContractPath(t *testing.T, relative string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve local Contract path")
	}
	return filepath.Join(filepath.Dir(file), "../../contract", relative)
}

func TestLocalContractProtectedAdmissionJWSProfileRejectsRetiredWireProfile(t *testing.T) {
	fixture := newEdDSAFixture(t)
	legacyClaims := validTokenClaims()
	legacyToken := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: "agent-sandbox-operation+jwt"}, legacyClaims)
	if _, err := VerifyCompactJWS(context.Background(), legacyToken, fixture.keys, validAdmissionAuthorityForTest()); err != ErrInvalidToken {
		t.Fatalf("VerifyCompactJWS(retired profile) error = %v, want exact %v", err, ErrInvalidToken)
	}
}
