// Package candidate names the reviewed, unsigned local Coding build records.
// Matching these records is not a fresh supply gate, signature, execution grant,
// or Profile admission. The separate recipe is NOT part of SourceCommit's tree.
package candidate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
)

const Protocol = "sandbox-runtime.phase6-coding-candidate-identity.v1"

var ErrIdentity = errors.New("invalid locked Coding candidate identity")

//go:embed inputs.lock.json artifacts.json evidence.lock.json Dockerfile *-manifest.json *-config.json
var records embed.FS

// Identity binds both the selected platform and the complete original input,
// artifact and historical evidence records. No caller supplies a replacement
// digest, signature flag, CVE exception, or current scan verdict.
type Identity struct {
	Protocol        string `json:"protocol"`
	Status          string `json:"status"`
	Candidate       string `json:"candidate"`
	Platform        string `json:"platform"`
	InputsDigest    string `json:"inputs_digest"`
	ArtifactsDigest string `json:"artifacts_digest"`
	EvidenceDigest  string `json:"evidence_digest"`
	RecipeDigest    string `json:"recipe_digest"`
	SourceCommit    string `json:"source_commit"`
	SourceTree      string `json:"source_tree"`
	SourceArchive   string `json:"source_archive"`
	GoVersion       string `json:"go_version"`
	ToolchainDigest string `json:"toolchain_digest"`
	BaseIndex       string `json:"base_index"`
	BaseManifest    string `json:"base_manifest"`
	ManifestDigest  string `json:"manifest_digest"`
	ManifestSize    int64  `json:"manifest_size"`
	ConfigDigest    string `json:"config_digest"`
	ArchiveDigest   string `json:"archive_digest"`
	BrokerDigest    string `json:"broker_digest"`
	HistoricalScan  string `json:"historical_scan"`
	HistoricalSBOM  string `json:"historical_sbom"`
}

// Runtime is the image's locked default config, not its per-slot execution UID.
type Runtime struct {
	Command, Environment   []string
	User, WorkingDirectory string
}

type lockedPlatform struct {
	identity         Identity
	runtime          Runtime
	manifest, config []byte
}

var loadRecords = sync.OnceValues(func() (map[string]lockedPlatform, error) {
	// Updating a lock or adding a candidate requires a reviewed source change;
	// merely editing an inventory file cannot select arbitrary caller bytes.
	checks := map[string]string{
		"inputs.lock.json":   "ec4501b7326b2bea85e059f43ff40584f501092d25211642b257d22a501a37b3",
		"artifacts.json":     "f8f1754dd9bb9c03ce743b8263b8adacad6537775756843c6b53c10ccc703af1",
		"evidence.lock.json": "d74d8727486ed93cabbbd744e45bb08c9a9ac7850e13c5e4c1df289639d465bb",
		"Dockerfile":         "ce232aa4cc44206523252f5bd5d4222f2428f687b5a319d424cf37cd8667913d",
	}
	data := map[string][]byte{}
	for name, want := range checks {
		b, err := records.ReadFile(name)
		if err != nil || sum(b) != "sha256:"+want {
			return nil, ErrIdentity
		}
		data[name] = b
	}
	var inputs struct {
		Candidate string `json:"candidate"`
		Source    struct {
			Commit, Tree string
			Archive      string `json:"archive_sha256"`
		} `json:"source"`
		Toolchain struct{ Version, SHA256 string } `json:"toolchain"`
		Base      struct {
			Index     string                                                `json:"index_digest"`
			Platforms map[string]struct{ Manifest struct{ Digest string } } `json:"platforms"`
		} `json:"base"`
	}
	var artifacts struct {
		Platforms map[string]struct {
			Manifest string `json:"manifest_digest"`
			Config   string `json:"config_digest"`
			Archive  string `json:"archive_digest"`
			Broker   string `json:"broker_digest"`
			Scan     string `json:"scan_report_sha256"`
			SBOM     string `json:"sbom_sha256"`
		} `json:"platforms"`
	}
	if json.Unmarshal(data["inputs.lock.json"], &inputs) != nil || json.Unmarshal(data["artifacts.json"], &artifacts) != nil {
		return nil, ErrIdentity
	}
	result := map[string]lockedPlatform{}
	for platform, arch := range map[string]string{"linux/arm64/v8": "arm64", "linux/amd64": "amd64"} {
		a := artifacts.Platforms[platform]
		manifest, err := records.ReadFile(arch + "-manifest.json")
		if err != nil || sum(manifest) != a.Manifest {
			return nil, ErrIdentity
		}
		config, err := records.ReadFile(arch + "-config.json")
		if err != nil || sum(config) != a.Config {
			return nil, ErrIdentity
		}
		var c struct {
			Config struct {
				Cmd, Env         []string
				User, WorkingDir string
			}
		}
		if json.Unmarshal(config, &c) != nil {
			return nil, ErrIdentity
		}
		i := Identity{Protocol: Protocol, Status: "unsigned-local-held", Candidate: inputs.Candidate, Platform: platform,
			InputsDigest: sum(data["inputs.lock.json"]), ArtifactsDigest: sum(data["artifacts.json"]), EvidenceDigest: sum(data["evidence.lock.json"]), RecipeDigest: sum(data["Dockerfile"]),
			SourceCommit: inputs.Source.Commit, SourceTree: inputs.Source.Tree, SourceArchive: "sha256:" + inputs.Source.Archive,
			GoVersion: inputs.Toolchain.Version, ToolchainDigest: "sha256:" + inputs.Toolchain.SHA256, BaseIndex: inputs.Base.Index, BaseManifest: inputs.Base.Platforms[platform].Manifest.Digest,
			ManifestDigest: a.Manifest, ManifestSize: int64(len(manifest)), ConfigDigest: a.Config, ArchiveDigest: a.Archive, BrokerDigest: a.Broker, HistoricalScan: "sha256:" + a.Scan, HistoricalSBOM: "sha256:" + a.SBOM}
		result[platform] = lockedPlatform{i, Runtime{c.Config.Cmd, c.Config.Env, c.Config.User, c.Config.WorkingDir}, manifest, config}
	}
	return result, nil
})

func LockedIdentity(platform string) (Identity, error) {
	m, err := loadRecords()
	v, ok := m[platform]
	if err != nil || !ok {
		return Identity{}, ErrIdentity
	}
	return v.identity, nil
}

func (i Identity) ValidateLocked() error {
	want, err := LockedIdentity(i.Platform)
	if err != nil || i != want {
		return ErrIdentity
	}
	return nil
}

func (i Identity) Digest() (string, error) {
	if i.ValidateLocked() != nil {
		return "", ErrIdentity
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", ErrIdentity
	}
	return sum(append([]byte(Protocol+"\x00"), b...)), nil
}

func LockedRuntime(platform string) (Runtime, error) {
	m, err := loadRecords()
	v, ok := m[platform]
	if err != nil || !ok {
		return Runtime{}, ErrIdentity
	}
	r := v.runtime
	r.Command, r.Environment = slices.Clone(r.Command), slices.Clone(r.Environment)
	return r, nil
}

// DescriptorDocuments returns original public metadata bytes, not OCI layers,
// an installed image, a signature, or proof that the private archive is present.
func DescriptorDocuments(platform string) (manifest, config []byte, err error) {
	m, err := loadRecords()
	v, ok := m[platform]
	if err != nil || !ok {
		return nil, nil, ErrIdentity
	}
	return slices.Clone(v.manifest), slices.Clone(v.config), nil
}

func sum(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
