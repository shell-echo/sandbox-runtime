package workloadpki

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func TestControlScannerTLSDelegationRequiresV2RegistryAndExactSubject(t *testing.T) {
	fixture := newProtocolFixture(t)
	digest := func(s string) string { return "sha256:" + strings.Repeat(s, 64) }
	registry, err := securityprincipal.NewSlice6V2Registry(digest("a"), digest("b"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name string
		kind securityprincipal.Kind
		role securityprincipal.Role
	}{
		{"provider_docker_control", securityprincipal.KindDockerControl, securityprincipal.RoleControl},
		{"provider_artifact_scanner", securityprincipal.KindArtifactScanner, securityprincipal.RoleScanner},
	} {
		t.Run(target.name, func(t *testing.T) {
			policy := fixture.policy
			policy.Registry = registry
			policy.Requester, err = registry.New(securityprincipal.KindTLSAgent, target.name+"_tls_agent", target.role, digest("c"))
			if err != nil {
				t.Fatal(err)
			}
			policy.Subject, err = registry.New(target.kind, target.name, target.role, digest("d"))
			if err != nil {
				t.Fatal(err)
			}
			policy.URI = "spiffe://sandbox-runtime.test/" + strings.ReplaceAll(target.name, "_", "-")
			if err := policy.Validate(); err != nil {
				t.Fatalf("reviewed v2 delegation rejected: %v", err)
			}
			legacy := policy
			legacy.Registry = fixture.policy.Registry
			if legacy.Validate() == nil {
				t.Fatal("v1 registry admitted v2 identity")
			}
			cross := policy
			cross.Subject = fixture.policy.Subject
			if cross.Validate() == nil {
				t.Fatal("new agent obtained another subject")
			}
			cross = policy
			cross.Requester = fixture.policy.Requester
			if cross.Validate() == nil {
				t.Fatal("ordinary agent obtained new subject")
			}
			cross = policy
			cross.Purpose = PostgresClientPurpose
			cross.URI = "spiffe://sandbox-runtime.test/product-runtime"
			cross.DNSNames, cross.Usages = nil, []string{"client_auth"}
			cross.Postgres = PostgresClientIdentity{OwnerDeployment: "product-runtime", DatabaseName: "product",
				RuntimeRole: "product_runtime", ServiceName: "postgres", URI: cross.URI, CommonName: "product_runtime",
				MaxTTL: time.Duration(cross.MaxTTLSeconds) * time.Second}
			if cross.Postgres.Validate() != nil {
				t.Fatal("negative test needs a valid PostgreSQL identity")
			}
			if cross.Validate() == nil {
				t.Fatal("new agent obtained PostgreSQL purpose")
			}
		})
	}
}
