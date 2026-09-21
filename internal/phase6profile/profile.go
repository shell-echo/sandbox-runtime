// Package phase6profile validates the repository-owned portion of a Phase 6
// deployment release profile. It does not attest that an image was actually
// published or that a cluster ran it; those facts remain external evidence.
package phase6profile

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var imagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$`)
var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

var (
	ErrInvalidProfile = errors.New("invalid Phase 6 release profile")
	ErrProfileFile    = errors.New("invalid Phase 6 release profile file")
)

type Artifact struct {
	ImageReference   string   `json:"image_reference"`
	ImageDigest      string   `json:"image_digest"`
	SBOMDigest       string   `json:"sbom_digest"`
	ProvenanceDigest string   `json:"provenance_digest"`
	SignatureDigest  string   `json:"signature_digest"`
	Architectures    []string `json:"architectures"`
}

type Role struct {
	Name           string   `json:"name"`
	ServiceAccount string   `json:"service_account"`
	Artifact       Artifact `json:"artifact"`
	LivenessPath   string   `json:"liveness_path"`
	ReadinessPath  string   `json:"readiness_path"`
	PublicIngress  bool     `json:"public_ingress"`
	OutboundOnly   bool     `json:"outbound_only"`
	AllowedEgress  []string `json:"allowed_egress"`
}

type Profile struct {
	Version       int    `json:"version"`
	Revision      string `json:"revision"`
	SourceDigest  string `json:"source_digest"`
	Configuration string `json:"configuration_digest"`
	ProfileDigest string `json:"profile_digest"`
	Roles         []Role `json:"roles"`
}

func (p Profile) Validate() error {
	if p.Version != 1 || strings.TrimSpace(p.Revision) == "" || len(p.Revision) > 128 || !digestPattern.MatchString(p.SourceDigest) || !digestPattern.MatchString(p.Configuration) || !digestPattern.MatchString(p.ProfileDigest) || len(p.Roles) != 4 {
		return ErrInvalidProfile
	}
	seen := make(map[string]struct{}, len(p.Roles))
	seenAccounts := make(map[string]struct{}, len(p.Roles))
	for _, role := range p.Roles {
		if !rolePattern.MatchString(role.Name) || strings.TrimSpace(role.ServiceAccount) != role.ServiceAccount || role.ServiceAccount == "" || len(role.ServiceAccount) > 128 || strings.ContainsAny(role.ServiceAccount, "\x00\r\n") || role.LivenessPath != "/livez" || role.ReadinessPath != "/readyz" {
			return ErrInvalidProfile
		}
		if _, ok := seen[role.Name]; ok {
			return ErrInvalidProfile
		}
		seen[role.Name] = struct{}{}
		if _, ok := seenAccounts[role.ServiceAccount]; ok {
			return ErrInvalidProfile
		}
		seenAccounts[role.ServiceAccount] = struct{}{}
		if err := role.Artifact.Validate(); err != nil {
			return err
		}
		for _, destination := range role.AllowedEgress {
			if strings.TrimSpace(destination) != destination || destination == "" || len(destination) > 256 || strings.ContainsAny(destination, "\x00\r\n") {
				return ErrInvalidProfile
			}
		}
		switch role.Name {
		case "gateway":
			if !role.PublicIngress || role.OutboundOnly {
				return ErrInvalidProfile
			}
		case "guest":
			if role.PublicIngress || !role.OutboundOnly {
				return ErrInvalidProfile
			}
		case "browser", "desktop":
			if role.PublicIngress || role.OutboundOnly {
				return ErrInvalidProfile
			}
		default:
			return ErrInvalidProfile
		}
	}
	for _, required := range []string{"gateway", "guest", "browser", "desktop"} {
		if _, ok := seen[required]; !ok {
			return ErrInvalidProfile
		}
	}
	if p.ProfileDigest != p.CanonicalDigest() {
		return ErrInvalidProfile
	}
	return nil
}

// CanonicalDigest binds the immutable release profile contents to its source
// and configuration digests. ProfileDigest is excluded from the projection so
// the document is not self-referential; callers compute this value after
// assembling the source/configuration/role projections and before publication.
func (p Profile) CanonicalDigest() string {
	projection := struct {
		Version       int    `json:"version"`
		Revision      string `json:"revision"`
		SourceDigest  string `json:"source_digest"`
		Configuration string `json:"configuration_digest"`
		Roles         []Role `json:"roles"`
	}{p.Version, p.Revision, p.SourceDigest, p.Configuration, p.Roles}
	document, _ := json.Marshal(projection)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-release-profile/v1\x00"), document...))
	return fmt.Sprintf("sha256:%x", digest[:])
}

func (a Artifact) Validate() error {
	if !imagePattern.MatchString(a.ImageReference) || !digestPattern.MatchString(a.ImageDigest) || !digestPattern.MatchString(a.SBOMDigest) || !digestPattern.MatchString(a.ProvenanceDigest) || !digestPattern.MatchString(a.SignatureDigest) || len(a.Architectures) == 0 || len(a.Architectures) > 4 {
		return ErrInvalidProfile
	}
	seen := make(map[string]struct{}, len(a.Architectures))
	for _, architecture := range a.Architectures {
		if architecture != "amd64" && architecture != "arm64" && architecture != "arm64/v8" {
			return ErrInvalidProfile
		}
		if _, ok := seen[architecture]; ok {
			return ErrInvalidProfile
		}
		seen[architecture] = struct{}{}
	}
	return nil
}

func VerifyFile(path string) (Profile, error) {
	contents, err := secretfile.Read(path, 1<<20)
	if err != nil {
		return Profile{}, ErrProfileFile
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, ErrProfileFile
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Profile{}, ErrProfileFile
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}
