package phase6profilebuilder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6CABundle(t *testing.T, name string, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testSlice6TrustFiles(t *testing.T, now time.Time) map[string]string {
	t.Helper()
	directory := testSlice6OperatorDirectory(t)
	paths := make(map[string]string)
	for _, anchor := range phase6security.Slice6DesiredFinalTrustAnchorTemplates() {
		path := filepath.Join(directory, anchor.ID+".pem")
		if err := os.WriteFile(path, testSlice6CABundle(t, anchor.ID, now), 0o400); err != nil {
			t.Fatal(err)
		}
		paths[anchor.ID] = path
	}
	return paths
}

func testSlice6OperatorDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "operator")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func testSlice6ResourceDraft(t *testing.T) ResourceDraft {
	t.Helper()
	root, _ := writeSyntheticResourceSupply(t)
	supply, err := LoadResourceSeccompSupply(root, "linux/arm64/v8")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := BuildSlice6PrincipalDraft(strings.Repeat("c", 32),
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	for index := range draft.Principals {
		draft.Principals[index].ImagePlatform = "linux/arm64/v8"
		draft.Principals[index].ImageDigest = "sha256:" + strings.Repeat("d", 64)
	}
	bound, budgets, err := supply.BindResourceSeccompDraft(draft)
	if err != nil {
		t.Fatal(err)
	}
	return ResourceDraft{PrincipalDraft: bound, Supply: supply, Budgets: budgets}
}

func TestSlice6TrustAnchorSupplyBindsExactReviewedConsumers(t *testing.T) {
	now := time.Now().UTC()
	supply, err := LoadSlice6TrustAnchorSupply(testSlice6TrustFiles(t, now), now)
	if err != nil {
		t.Fatal(err)
	}
	before := testSlice6ResourceDraft(t)
	bound, err := BindSlice6TrustAnchorDraft(before, supply, now)
	if err != nil || len(bound.TrustAnchors) != 5 || len(bound.Principals) != 78 {
		t.Fatalf("trust-anchor draft = %d anchors, %v", len(bound.TrustAnchors), err)
	}
	for _, anchor := range bound.TrustAnchors {
		bundle, err := supply.BundleBytes(anchor.ID)
		if err != nil || digestSlice6Bytes(bundle) != anchor.BundleDigest {
			t.Fatalf("bundle %s not bound to original bytes: %v", anchor.ID, err)
		}
		bundle[0] = 'x'
		fresh, err := supply.BundleBytes(anchor.ID)
		if err != nil || fresh[0] == 'x' {
			t.Fatalf("caller mutated bundle %s", anchor.ID)
		}
		for _, principal := range bound.Principals {
			wanted := slices.Contains(anchor.Consumers, principal.Name)
			found := false
			for _, mount := range principal.Mounts {
				if mount.StorageID == anchor.StorageID {
					found = mount.Kind == "trust_anchor" && mount.Target == anchor.TargetPath && mount.ReadOnly
				}
			}
			if found != wanted {
				t.Fatalf("anchor %s mount mismatch for %s", anchor.ID, principal.Name)
			}
		}
	}
	for _, principal := range before.Principals {
		for _, mount := range principal.Mounts {
			if mount.Kind == "trust_anchor" {
				t.Fatal("binding mutated original resource draft")
			}
		}
	}
	changed := before
	changed.Principals = append([]phase6security.Principal(nil), before.Principals...)
	changed.Principals[0].Mounts = append([]phase6security.Mount(nil), changed.Principals[0].Mounts...)
	changed.Principals[0].Mounts = append(changed.Principals[0].Mounts,
		phase6security.Mount{Target: "/run/trust/external-server-ca.pem", Kind: "trust_anchor", ReadOnly: true})
	if _, err := BindSlice6TrustAnchorDraft(changed, supply, now); err == nil {
		t.Fatal("prebound CA mount admitted")
	}
	changed = before
	changed.Principals = append([]phase6security.Principal(nil), before.Principals...)
	changed.Principals[0].Resources.PIDs++
	if _, err := BindSlice6TrustAnchorDraft(changed, supply, now); err == nil {
		t.Fatal("resource-policy drift admitted by trust-anchor binder")
	}
	tampered := supply
	tampered.bundles = make(map[string][]byte, len(supply.bundles))
	for id, bundle := range supply.bundles {
		tampered.bundles[id] = slices.Clone(bundle)
	}
	tampered.bundles["vault-client-ca"][0] = 'x'
	if _, err := tampered.BundleBytes("vault-client-ca"); err == nil {
		t.Fatal("mutated CA snapshot exposed")
	}
	if _, err := BindSlice6TrustAnchorDraft(before, tampered, now); err == nil {
		t.Fatal("mutated CA snapshot admitted")
	}
	path := supply.paths["vault-client-ca"]
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, testSlice6CABundle(t, "replacement", now), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if supply.VerifySources(now) == nil {
		t.Fatal("changed operator CA source accepted at freeze")
	}
	if _, err := BindSlice6TrustAnchorDraft(before, supply, now); err == nil {
		t.Fatal("changed operator CA source admitted by binder")
	}
}

func TestSlice6TrustAnchorSupplyRejectsMissingUnsafeAndInvalidCAFiles(t *testing.T) {
	now := time.Now().UTC()
	paths := testSlice6TrustFiles(t, now)
	if _, err := LoadSlice6TrustAnchorSupply(paths, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing": func(value map[string]string) { delete(value, "vault-client-ca") },
		"surplus": func(value map[string]string) { value["unknown-ca"] = value["vault-client-ca"] },
		"symlink": func(value map[string]string) {
			link := filepath.Join(filepath.Dir(value["vault-client-ca"]), "link.pem")
			if err := os.Symlink(value["vault-client-ca"], link); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = link
		},
		"writable": func(value map[string]string) {
			path := filepath.Join(testSlice6OperatorDirectory(t), "writable.pem")
			if err := os.WriteFile(path, testSlice6CABundle(t, "writable", now), 0o600); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
		"non-CA": func(value map[string]string) {
			path := filepath.Join(testSlice6OperatorDirectory(t), "invalid.pem")
			if err := os.WriteFile(path, []byte("not a CA"), 0o400); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
		"duplicate CA": func(value map[string]string) {
			path := filepath.Join(testSlice6OperatorDirectory(t), "duplicate.pem")
			bundle := testSlice6CABundle(t, "duplicate", now)
			if err := os.WriteFile(path, append(slices.Clone(bundle), bundle...), 0o400); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
		"public source directory": func(value map[string]string) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "public.pem")
			if err := os.WriteFile(path, testSlice6CABundle(t, "public", now), 0o400); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
		"expired": func(value map[string]string) {
			path := filepath.Join(testSlice6OperatorDirectory(t), "expired.pem")
			if err := os.WriteFile(path, testSlice6CABundle(t, "expired", now.Add(-2*time.Hour)), 0o400); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
		"junk prefix": func(value map[string]string) {
			path := filepath.Join(testSlice6OperatorDirectory(t), "junk.pem")
			bundle := append([]byte("untrusted prefix\n"), testSlice6CABundle(t, "junk", now)...)
			if err := os.WriteFile(path, bundle, 0o400); err != nil {
				t.Fatal(err)
			}
			value["vault-client-ca"] = path
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]string, len(paths)+1)
			for id, path := range paths {
				candidate[id] = path
			}
			mutate(candidate)
			if _, err := LoadSlice6TrustAnchorSupply(candidate, now); err == nil {
				t.Fatal("unsafe CA supply admitted")
			}
		})
	}
}
