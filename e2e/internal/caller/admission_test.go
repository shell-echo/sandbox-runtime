package caller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArtifactFixtureDigestMatchesLockedContract(t *testing.T) {
	t.Parallel()
	const fixture = `{
  "operation_id":"artifact-operation-1","attempt_id":"artifact-attempt-1","fencing_token":3,
  "idempotency_key":"artifact-idempotency-1","deadline_at":"2026-08-25T12:00:00Z","expected_generation":4,
  "artifact_reference":"artifact-ref:platform/artifact-1","source_path":"/outputs/report.json",
  "expected_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "expected_media_type":"application/json","max_bytes":1048576,"retention_seconds":3600
}`
	var document map[string]any
	if err := json.Unmarshal([]byte(fixture), &document); err != nil {
		t.Fatal(err)
	}
	digest, err := canonicalDigest(document)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:813c32c35c60442f131a477a9a7af4029edc896c4baa47a2cbb0c0afdc550b4f"
	if digest != expected {
		t.Fatalf("artifact digest = %s, want %s", digest, expected)
	}
}

func TestPrepareProducesIndependentlyVerifiableAdmissionJWS(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := IdentityConfig{ControllerSubject: "spiffe://reference-caller/controller-a", JWSPrivateKeyFile: keyPath, JWSKeyID: "controller-a-key"}
	requestSigner, err := loadSigner(identity)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{ProviderRevisionID: "provider-revision-e2e-v1", ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:e2e"}
	deadline := time.Now().UTC().Add(time.Minute)
	body := mutationEnvelope("operation-exec-1", "attempt-exec-1", 2, "exec-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["command"] = []string{"/bin/true"}
	body["working_directory"] = "/workspace"
	body["result_retention_seconds"] = 60
	prepared, err := requestSigner.prepare(config, "POST", "/v1/sandboxes/sandbox-1/exec", body, admissionBinding{
		Operation: "exec", SandboxID: "sandbox-1", OperationID: "operation-exec-1", AttemptID: "attempt-exec-1",
		FencingToken: 2, TenantID: "tenant-1", WorkOrderID: "work-order-1", Deadline: deadline, JTI: "e2e-jti-fixed-00000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.TrimPrefix(prepared.Authorization, "Bearer ")
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		t.Fatalf("compact JWS segments = %d", len(segments))
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || !ed25519.Verify(public, []byte(segments[0]+"."+segments[1]), signature) {
		t.Fatal("compact JWS signature did not verify independently")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims tokenClaims
	if err := decodeStrict(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.JTI != "e2e-jti-fixed-00000001" || claims.Operation != "exec" || claims.RequestDigestProfile != requestDigestExcluding {
		t.Fatalf("claims = %#v", claims)
	}
	carrier, err := base64.RawURLEncoding.DecodeString(prepared.AdmissionContext)
	if err != nil {
		t.Fatal(err)
	}
	var admitted admissionContext
	if err := decodeStrict(carrier, &admitted); err != nil {
		t.Fatal(err)
	}
	wantContextDigest, err := contextDigest(admitted)
	if err != nil || admitted.ContextDigest != wantContextDigest || claims.AdmissionContextDigest != wantContextDigest {
		t.Fatalf("context digest = (%s, %s), want %s, err=%v", admitted.ContextDigest, claims.AdmissionContextDigest, wantContextDigest, err)
	}
	var encodedBody map[string]any
	if err := json.Unmarshal(prepared.Body, &encodedBody); err != nil {
		t.Fatal(err)
	}
	embedded, _ := encodedBody["request_digest"].(string)
	delete(encodedBody, "request_digest")
	wantRequestDigest, err := canonicalDigest(encodedBody)
	if err != nil || embedded != wantRequestDigest || claims.RequestDigest != wantRequestDigest {
		t.Fatalf("request digest = (%s, %s), want %s, err=%v", embedded, claims.RequestDigest, wantRequestDigest, err)
	}
}

func TestBackendDisclosureCheckAllowsOpaqueReferenceOnly(t *testing.T) {
	t.Parallel()
	if err := checkNoBackendDisclosure([]byte(`{"internal_endpoint_reference":"ref:session:opaque-1"}`)); err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{
		`{"endpoint":"unix:///var/run/docker.sock"}`,
		`{"container_id":"abcdef"}`,
		`{"value":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
	} {
		if err := checkNoBackendDisclosure([]byte(document)); err == nil {
			t.Fatalf("checkNoBackendDisclosure(%s) succeeded", document)
		}
	}
}
