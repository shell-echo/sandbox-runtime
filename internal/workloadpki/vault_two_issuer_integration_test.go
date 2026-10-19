//go:build integration

package workloadpki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This is a VaultClient component, not Profile admission, a Controller/agent
// process chain, or production Vault bootstrap. Its dev TLS root is separate
// from the two in-memory PKI issuers. It never pulls or changes an image lock.
func TestVaultTwoIssuerSourceBindingIntegration(t *testing.T) { //nolint:gocyclo
	if os.Getenv("SANDBOX_RUNTIME_VAULT_TWO_ISSUER_INTEGRATION") != "1" {
		t.Skip("explicit verified Vault input required")
	}
	archive := os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE")
	const selected = "sha256:3aae140ea5b73deaf10d70607194ab52ff80f4ebfc4ef4796ad1a7be5f4db682"
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archive, "registry",
		phase6security.ImageIdentityOCIIndex, vaultPKIIntegrationImage,
		strings.Split(vaultPKIIntegrationImage, "@")[1], "linux/arm64/v8", selected)
	if err != nil || phase6security.VerifyOCIArchiveLayers(archive, documents.Manifest, documents.Config) != nil {
		t.Fatal("complete pinned Vault archive unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	if exec.CommandContext(ctx, "docker", "image", "inspect", vaultPKIIntegrationImage).Run() != nil {
		t.Fatal("verified pinned Vault must already exist in Docker")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	runID := hex.EncodeToString(random[:16])
	rootToken := hex.EncodeToString(random[:])
	container := "sr-vault-two-issuer-" + runID
	containerID := ""
	var anonymousVolumes []string
	volumeInventoryComplete := false
	// Register before creation. A failed run can still have created its uniquely
	// named container; only this fresh run label permits failure-path removal.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		ids, e := exec.CommandContext(cleanup, "docker", "ps", "-aq", "--no-trunc", "--filter",
			"label=sandbox-runtime.vault-two-issuer.run="+runID).Output()
		if e != nil {
			t.Error("cannot enumerate exact run cleanup")
			return
		}
		for _, id := range strings.Fields(string(ids)) {
			if containerID != "" && id != containerID {
				t.Error("unexpected additional run container; preserved")
				continue
			}
			if exec.CommandContext(cleanup, "docker", "rm", "-f", "-v", id).Run() != nil {
				t.Error("exact Vault container cleanup failed")
			}
		}
		left, e := exec.CommandContext(cleanup, "docker", "ps", "-aq", "--filter",
			"label=sandbox-runtime.vault-two-issuer.run="+runID).Output()
		if e != nil || len(bytes.TrimSpace(left)) != 0 {
			t.Error("Vault cleanup did not reach zero")
		} else {
			if !volumeInventoryComplete {
				t.Error("container removed but volume inventory unavailable; volume cleanup unproven")
				return
			}
			volumes, e := exec.CommandContext(cleanup, "docker", "volume", "ls", "--format", "{{.Name}}").Output()
			if e != nil {
				t.Error("cannot verify anonymous-volume removal")
				return
			}
			remaining := strings.Fields(string(volumes))
			removed := true
			for _, name := range anonymousVolumes {
				if slices.Contains(remaining, name) {
					t.Error("run-owned anonymous volume remains")
					removed = false
				}
			}
			if removed {
				t.Log("exact run container/anonymous-volume removal completed", runID)
			}
		}
	})
	containerID = strings.TrimSpace(twoIssuerDocker(t, ctx, "run", "-d", "--pull=never", "--name", container,
		"--label", "sandbox-runtime.vault-two-issuer.run="+runID, "--platform", "linux/arm64/v8",
		"-p", "127.0.0.1::8200", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--memory", "512m", "--cpus", "1", "--pids-limit", "128",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken, vaultPKIIntegrationImage,
		"server", "-dev", "-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls"))
	if len(containerID) != 64 {
		t.Fatal("invalid container identity")
	}
	containerDocument, err := exec.CommandContext(ctx, "docker", "inspect", containerID).Output()
	var observed []struct {
		ID     string `json:"Id"`
		Mounts []struct{ Type, Name string }
	}
	decodeErr := json.Unmarshal(containerDocument, &observed)
	defer clear(containerDocument) // Docker inspection contains the dev token environment.
	if err != nil || decodeErr != nil || len(observed) != 1 || observed[0].ID != containerID {
		t.Fatal("container observation unavailable")
	}
	for _, mount := range observed[0].Mounts {
		if mount.Type == "volume" {
			anonymousVolumes = append(anonymousVolumes, mount.Name)
		}
	}
	volumeInventoryComplete = true
	imageDocument, err := exec.CommandContext(ctx, "docker", "image", "inspect", vaultPKIIntegrationImage).Output()
	if err != nil {
		t.Fatal("runtime image observation unavailable")
	}
	image, err := phase6security.ObserveDockerRuntimeImage(containerDocument, imageDocument,
		"registry", phase6security.ImageIdentityOCIIndex, vaultPKIIntegrationImage,
		strings.Split(vaultPKIIntegrationImage, "@")[1], "linux/arm64/v8", selected, proof.ConfigDigest, documents)
	clear(containerDocument)
	if err != nil || image.OCIConfigDigest != proof.ConfigDigest || image.DescriptorProofDigest != proof.ProofDigest {
		t.Fatal("running Vault differs from the verified OCI input")
	}
	t.Log("verified running Vault selected manifest", selected, "config", proof.ConfigDigest)
	port := strings.TrimSpace(twoIssuerDocker(t, ctx, "port", containerID, "8200/tcp"))
	if !strings.HasPrefix(port, "127.0.0.1:") || strings.ContainsAny(port, "\r\n") {
		t.Fatal("Vault loopback port unavailable")
	}
	endpoint := "https://" + port
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(waitPKIVaultCA(t, ctx, containerID)) {
		t.Fatal("Vault transport CA unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}
	defer transport.CloseIdleConnections()
	admin := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	waitPKIVault(t, ctx, admin, endpoint, rootToken)
	write := func(path string, value, result any) {
		t.Helper()
		twoIssuerHTTP(t, ctx, admin, http.MethodPost, endpoint+path, rootToken, value, result)
	}
	write("/v1/sys/mounts/pki", map[string]any{"type": "pki", "config": map[string]string{"max_lease_ttl": "1h"}}, nil)
	crlConfig := map[string]bool{"disable": false, "auto_rebuild": false, "enable_delta": false}
	write("/v1/pki/config/crl", crlConfig, nil)
	type issuerRecord struct {
		ID  string `json:"id"`
		DER []byte `json:"der"`
	}
	issuers := map[string]issuerRecord{}
	var sources []VaultPeerIssuerSource
	for _, name := range []string{"broker", "general"} {
		var generated struct {
			Data struct {
				IssuerID    string `json:"issuer_id"`
				Certificate string `json:"certificate"`
			} `json:"data"`
		}
		write("/v1/pki/root/generate/internal", map[string]any{"issuer_name": name,
			"common_name": "diagnostic-" + name, "ttl": "1h", "key_type": "ec", "key_bits": 256}, &generated)
		block, rest := pem.Decode([]byte(generated.Data.Certificate))
		if !vaultIssuerIDPattern.MatchString(generated.Data.IssuerID) || block == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("immutable Vault issuer unavailable")
		}
		issuers[name] = issuerRecord{generated.Data.IssuerID, block.Bytes}
		sum := sha256.Sum256(block.Bytes)
		sources = append(sources, VaultPeerIssuerSource{SourceID: name + "-peer", Mount: "pki",
			IssuerID: generated.Data.IssuerID, IssuerDigest: "sha256:" + hex.EncodeToString(sum[:])})
	}
	if issuers["broker"].ID == issuers["general"].ID || bytes.Equal(issuers["broker"].DER, issuers["general"].DER) {
		t.Fatal("issuers are not distinct")
	}
	var listed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	twoIssuerHTTP(t, ctx, admin, "LIST", endpoint+"/v1/pki/issuers", rootToken, nil, &listed)
	slices.Sort(listed.Data.Keys)
	wantIDs := []string{issuers["broker"].ID, issuers["general"].ID}
	slices.Sort(wantIDs)
	if !slices.Equal(listed.Data.Keys, wantIDs) {
		t.Fatal("PKI mount does not contain exactly broker/general")
	}
	setDefault := func(id string) {
		t.Helper()
		write("/v1/pki/config/issuers", map[string]any{"default": id, "default_follows_latest_issuer": false}, nil)
		var actual struct {
			Data struct {
				Default string `json:"default"`
			} `json:"data"`
		}
		twoIssuerHTTP(t, ctx, admin, http.MethodGet, endpoint+"/v1/pki/config/issuers", rootToken, nil, &actual)
		if actual.Data.Default != id {
			t.Fatal("Vault default issuer readback differs")
		}
	}
	setDefault(issuers["general"].ID)
	_, _, allPolicies := controllerV2PolicyFields(t)
	var policies []Policy
	roles := map[string]map[string]any{}
	allowed := map[string]string{}
	acl := "path \"pki/config/crl\" { capabilities = [\"read\"] }\npath \"pki/revoke\" { capabilities = [\"update\"] }\n"
	for _, p := range allPolicies {
		if p.ID != "provider-docker-control-tls" && p.ID != "provider-artifact-scanner-tls" &&
			p.ID != "egress-broker-product-tls" && p.ID != "product-postgres-client" {
			continue
		}
		issuer := p.IssuerSourceID
		p.IssuerSourceID += "-peer"
		if p.Validate() != nil || issuer != "broker" && issuer != "general" || p.Purpose == PostgresClientPurpose && issuer != "general" {
			t.Fatal("invalid bounded issuer policy")
		}
		role := map[string]any{"issuer_ref": issuers[issuer].ID, "allowed_domains": p.DNSNames,
			"allow_bare_domains": true, "allow_subdomains": false, "allowed_uri_sans": []string{p.URI},
			"require_cn": false, "use_csr_common_name": true, "use_csr_sans": true, "max_ttl": "15m",
			"not_before_duration": "30s", "client_flag": true, "server_flag": slices.Contains(p.Usages, "server_auth"),
			"code_signing_flag": false, "email_protection_flag": false, "key_type": "ec", "key_bits": 256,
			"key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{"ClientAuth", "ServerAuth"}}
		if p.Purpose == PostgresClientPurpose {
			role["require_cn"], role["enforce_hostnames"] = true, false
			role["allowed_domains"], role["ext_key_usage"] = []string{p.Postgres.CommonName}, []string{"ClientAuth"}
		}
		roles[p.ID], allowed[p.ID] = role, p.VaultRole
		write("/v1/pki/roles/"+p.VaultRole, role, nil)
		var actual struct {
			Data struct {
				IssuerRef string `json:"issuer_ref"`
				Backdate  int64  `json:"not_before_duration"`
			} `json:"data"`
		}
		twoIssuerHTTP(t, ctx, admin, http.MethodGet, endpoint+"/v1/pki/roles/"+p.VaultRole, rootToken, nil, &actual)
		if actual.Data.IssuerRef != issuers[issuer].ID || actual.Data.Backdate != 30 {
			t.Fatal("Vault role issuer/backdate readback differs")
		}
		policies = append(policies, p)
		acl += "path \"pki/roles/" + p.VaultRole + "\" { capabilities = [\"read\"] }\npath \"pki/sign/" + p.VaultRole + "\" { capabilities = [\"update\"] }\n"
	}
	if len(policies) != 4 {
		t.Fatal("missing bounded policy")
	}
	for _, source := range sources {
		acl += "path \"pki/issuer/" + source.IssuerID + "/der\" { capabilities = [\"read\"] }\npath \"pki/issuer/" + source.IssuerID + "/crl/der\" { capabilities = [\"read\"] }\n"
	}
	write("/v1/sys/policies/acl/two-issuer", map[string]string{"policy": acl}, nil)
	var token struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	write("/v1/auth/token/create", map[string]any{"policies": []string{"two-issuer"}, "ttl": "10m", "renewable": false, "no_default_policy": true}, &token)
	if !validVaultToken([]byte(token.Auth.ClientToken)) || token.Auth.LeaseDuration < 240 {
		t.Fatal("scoped token unavailable")
	}
	audit := &twoIssuerAudit{next: transport, paths: map[string]int{}, statuses: map[string]int{}}
	client, err := NewVaultClient(VaultConfig{Endpoint: endpoint, Mount: "pki", AllowedPolicies: allowed,
		OperationTimeout: 5 * time.Second, Now: time.Now, RequireImmediateCompleteCRL: true, PeerIssuerSources: sources},
		&http.Client{Transport: audit}, staticVaultTokenSource{token: VaultToken{Value: []byte(token.Auth.ClientToken),
			ExpiresAt: time.Now().Add(time.Duration(token.Auth.LeaseDuration) * time.Second), Revision: "two-issuer-run"}})
	if err != nil || client.ValidatePolicyIssuers(policies) != nil {
		t.Fatal("policy/source client unavailable", err)
	}
	var declared []phase6security.PeerCRLSource
	for _, source := range sources {
		declared = append(declared, phase6security.PeerCRLSource{ID: source.SourceID, Mount: source.Mount, IssuerID: source.IssuerID, IssuerDigest: source.IssuerDigest})
	}
	if client.ValidatePeerSources(declared) != nil || client.ValidatePeerSources([]phase6security.PeerCRLSource{declared[0], declared[0]}) == nil {
		t.Fatal("source set not exact")
	}
	for _, policy := range policies {
		t.Run(policy.ID, func(t *testing.T) {
			name := strings.TrimSuffix(policy.IssuerSourceID, "-peer")
			csr, _ := testPostgresCSR(t, pkix.Name{CommonName: policy.Postgres.CommonName}, policy.URI, policy.DNSNames)
			issued, e := client.Issue(ctx, policy, csr, 869*time.Second)
			if e != nil {
				t.Fatal("fixed issuer signing failed", e)
			}
			defer issued.Destroy()
			if !bytes.Equal(mustPEMCertificateDER(t, issued.IssuingCAPEM), issuers[name].DER) {
				t.Fatal("wrong issuing CA")
			}
			before, e := client.PolicyRevocations(ctx, policy)
			if e != nil {
				t.Fatal(e)
			}
			defer before.Destroy()
			verified, e := VerifyCRLForIssuer(before, issuers[name].DER, time.Now())
			if e != nil || verified.CheckPeer(mustPEMCertificateDER(t, issued.CertificatePEM), issuers[name].DER, time.Now()) != nil {
				t.Fatal("fresh leaf/CRL invalid", e)
			}
			if client.Revoke(ctx, issued.Serial) != nil {
				t.Fatal("revoke failed")
			}
			after, e := client.PeerRevocations(ctx, policy.IssuerSourceID, issuers[name].DER)
			if e != nil {
				t.Fatal(e)
			}
			defer after.Destroy()
			revoked, e := VerifyCRLForIssuer(after, issuers[name].DER, time.Now())
			if e != nil || revoked.Number().Cmp(verified.Number()) <= 0 || revoked.CheckPeer(mustPEMCertificateDER(t, issued.CertificatePEM), issuers[name].DER, time.Now()) != ErrPeerRevoked {
				t.Fatal("exact serial not immediately revoked", e)
			}
			other := "broker"
			if name == "broker" {
				other = "general"
			}
			otherCRL, e := client.PeerRevocations(ctx, other+"-peer", issuers[other].DER)
			if e != nil {
				t.Fatal(e)
			}
			defer otherCRL.Destroy()
			list, e := x509.ParseRevocationList(otherCRL.DER)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range list.RevokedCertificateEntries {
				if serialString(entry.SerialNumber.Bytes()) == issued.Serial {
					t.Fatal("cross-issuer revocation leakage")
				}
			}
		})
	}
	var policy Policy
	for _, candidate := range policies {
		if candidate.ID == "provider-docker-control-tls" {
			policy = candidate
		}
	}
	if policy.IssuerSourceID != "general-peer" || roles[policy.ID]["issuer_ref"] != issuers["general"].ID {
		t.Fatal("Control/general negative-case precondition missing")
	}
	csr, _ := testPostgresCSR(t, pkix.Name{}, policy.URI, policy.DNSNames)
	for _, target := range []string{"default", issuers["broker"].ID} {
		t.Run("role-issuer-"+target, func(t *testing.T) {
			role := roles[policy.ID]
			original := role["issuer_ref"]
			role["issuer_ref"] = target
			write("/v1/pki/roles/"+policy.VaultRole, role, nil)
			defer func() { role["issuer_ref"] = original; write("/v1/pki/roles/"+policy.VaultRole, role, nil) }()
			before := audit.count("/v1/pki/sign/" + policy.VaultRole)
			if _, e := client.Issue(ctx, policy, csr, 869*time.Second); e == nil || audit.count("/v1/pki/sign/"+policy.VaultRole) != before {
				t.Fatal("role drift reached signing")
			}
		})
	}
	setDefault(issuers["broker"].ID)
	if _, e := client.Revocations(ctx); e == nil || audit.count("/v1/pki/crl") != 0 {
		t.Fatal("mutable default CRL fallback")
	}
	for _, p := range policies {
		snapshot, e := client.PolicyRevocations(ctx, p)
		if e != nil {
			t.Fatal("default drift changed explicit source", e)
		}
		snapshot.Destroy()
	}
	if _, e := client.PeerRevocations(ctx, "general-peer", issuers["broker"].DER); e == nil {
		t.Fatal("wrong issuer DER accepted")
	}
	write("/v1/pki/config/crl", map[string]bool{"disable": true, "auto_rebuild": false, "enable_delta": false}, nil)
	if _, e := client.PeerRevocations(ctx, "general-peer", issuers["general"].DER); e == nil {
		t.Fatal("disabled complete CRL accepted")
	}
	write("/v1/pki/config/crl", crlConfig, nil)
	crlPath := "/v1/pki/issuer/" + issuers["broker"].ID + "/crl/der"
	readRule := "path \"pki/issuer/" + issuers["broker"].ID + "/crl/der\" { capabilities = [\"read\"] }"
	denyRule := "path \"pki/issuer/" + issuers["broker"].ID + "/crl/der\" { capabilities = [\"deny\"] }"
	if strings.Count(acl, readRule) != 1 {
		t.Fatal("exact CRL ACL rule missing")
	}
	denied := strings.Replace(acl, readRule, denyRule, 1)
	write("/v1/sys/policies/acl/two-issuer", map[string]string{"policy": denied}, nil)
	beforeCRLRead := audit.count(crlPath)
	if _, e := client.PeerRevocations(ctx, "broker-peer", issuers["broker"].DER); e == nil ||
		audit.count(crlPath) != beforeCRLRead+1 || audit.status(crlPath) != http.StatusForbidden {
		t.Fatal("CRL access loss accepted")
	}
	write("/v1/sys/policies/acl/two-issuer", map[string]string{"policy": acl}, nil)
	for _, source := range sources {
		der, e := client.PeerIssuerCertificate(ctx, source.SourceID)
		if e != nil {
			t.Fatal(e)
		}
		snapshot, e := client.PeerRevocations(ctx, source.SourceID, der)
		if e != nil {
			t.Fatal("restored source unavailable", e)
		}
		snapshot.Destroy()
	}
	write("/v1/sys/seal", map[string]any{}, nil)
	if _, e := client.PeerRevocations(ctx, "general-peer", issuers["general"].DER); e == nil ||
		audit.status("/v1/pki/config/crl") != http.StatusServiceUnavailable {
		t.Fatal("sealed authority accepted")
	}
	if t.Failed() {
		return
	}
	if output := os.Getenv("SANDBOX_RUNTIME_VAULT_TWO_ISSUER_OUTPUT"); output != "" {
		data, e := json.Marshal(struct {
			RunID   string                  `json:"run_id"`
			Issuers map[string]issuerRecord `json:"issuers"`
		}{runID, issuers})
		if e != nil {
			t.Fatal(e)
		}
		f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if e != nil || syncErr != nil || closeErr != nil {
			t.Fatal("issuer evidence write failed")
		}
	}
	t.Log("two fixed issuers; four signed/revoked policies; default, role, CRL access and sealed-authority checks passed")
}

type twoIssuerAudit struct {
	mu       sync.Mutex
	next     http.RoundTripper
	paths    map[string]int
	statuses map[string]int
}

func (a *twoIssuerAudit) RoundTrip(r *http.Request) (*http.Response, error) {
	a.mu.Lock()
	a.paths[r.URL.Path]++
	a.mu.Unlock()
	response, err := a.next.RoundTrip(r)
	a.mu.Lock()
	a.statuses[r.URL.Path] = 0
	if response != nil {
		a.statuses[r.URL.Path] = response.StatusCode
	}
	a.mu.Unlock()
	return response, err
}
func (a *twoIssuerAudit) count(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.paths[path]
}

func (a *twoIssuerAudit) status(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statuses[path]
}

// Never print request headers, bodies, Docker arguments or Vault error bodies:
// initialization/token responses and dev server diagnostics contain secrets.
func twoIssuerDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, e := exec.CommandContext(ctx, "docker", args...).Output()
	if e != nil {
		t.Fatal("bounded Docker operation failed")
	}
	return string(out)
}
func twoIssuerHTTP(t *testing.T, ctx context.Context, client *http.Client, method, target, token string, value, result any) {
	t.Helper()
	var body []byte
	var e error
	if value != nil {
		body, e = json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
	}
	defer clear(body)
	r, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if e != nil {
		t.Fatal("Vault setup request failed")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Vault-Token", token)
	response, e := client.Do(r)
	if e != nil {
		t.Fatal("Vault setup transport failed")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
	defer clear(data)
	if e != nil || len(data) > 512<<10 || response.StatusCode < 200 || response.StatusCode > 299 {
		t.Fatalf("Vault setup rejected, status=%d", response.StatusCode)
	}
	if result != nil && json.Unmarshal(data, result) != nil {
		t.Fatal("Vault setup response invalid")
	}
}
