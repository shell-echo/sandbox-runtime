package phase6security

import (
	"maps"
	"slices"
)

// ReviewControlServiceImage binds the complete held Profile's selected OCI
// descriptor/layer bytes to its role and loader hashes. The operator must
// separately reproduce those binaries from the declared source snapshot.
// This is not supply-chain/release admission or a running process check.
func ReviewControlServiceImage(document []byte, deployment, archive string, docs ImageDescriptorDocuments) (ImageDescriptorProof, error) {
	r, e := ReviewControlBootstrap(document)
	if e != nil {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	var s *ControlServiceIdentityV1
	for i := range r.Services {
		if r.Services[i].Principal.Name == deployment {
			s = &r.Services[i]
		}
	}
	if s == nil {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	p := s.Principal
	if p.ImageLocation != "local" || p.ImageIdentityKind != ImageIdentityOCIIndex {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	proof, e := VerifyImageDescriptorDocuments(p.ImageLocation, p.ImageIdentityKind, p.ImageReference, p.ImageDigest, p.ImagePlatform, p.ImageSelectedManifestDigest, p.ImageConfigDigest, docs)
	if e != nil {
		return ImageDescriptorProof{}, e
	}
	if !controlServiceConfigMatches(docs.Config, s.Entrypoint) || !controlSourceLabelsMatch(docs.Config, *s) {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	exe, e := ReadVerifiedOCIArchiveRoleExecutable(archive, docs.Manifest, docs.Config)
	if e != nil || hashImageBytes(exe) != s.Launch.ExecutableDigest {
		return ImageDescriptorProof{}, ErrInvalidImageDescriptor
	}
	if s.Launch.LoaderDigest != "" {
		loader, e := ReadVerifiedOCIArchiveFDLoader(archive, docs.Manifest, docs.Config)
		if e != nil || hashImageBytes(loader) != s.Launch.LoaderDigest {
			return ImageDescriptorProof{}, ErrInvalidImageDescriptor
		}
	}
	if s.Launch.ProbeDigest != "" {
		probe, e := ReadVerifiedOCIArchiveControlProbe(archive, docs.Manifest, docs.Config)
		if e != nil || hashImageBytes(probe) != s.Launch.ProbeDigest {
			return ImageDescriptorProof{}, ErrInvalidImageDescriptor
		}
	}
	return proof, nil
}

func controlServiceConfigMatches(document []byte, entrypoint []string) bool {
	var c struct {
		Config struct {
			Entrypoint  []string       `json:"Entrypoint"`
			Cmd         []string       `json:"Cmd"`
			User        string         `json:"User"`
			WorkingDir  string         `json:"WorkingDir"`
			Env         []string       `json:"Env"`
			Volumes     map[string]any `json:"Volumes"`
			Healthcheck any            `json:"Healthcheck"`
			OnBuild     []string       `json:"OnBuild"`
		} `json:"config"`
	}
	if !decodeImageJSON(document, &c) || !slices.Equal(c.Config.Entrypoint, entrypoint) || len(c.Config.Cmd) != 0 || c.Config.User != "65532:65532" || c.Config.WorkingDir != "/" || !slices.Equal(c.Config.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) || len(c.Config.Volumes) != 0 || c.Config.Healthcheck != nil || len(c.Config.OnBuild) != 0 {
		return false
	}
	return true
}

// ControlSourceImageLabels describes the fixed local-role build metadata. It
// is not source provenance, a clean-build attestation or an admission token.
func ControlSourceImageLabels(s ControlServiceIdentityV1) map[string]string {
	const prefix = "io.github.shell-echo.sandbox-runtime."
	return map[string]string{prefix + "phase6-candidate": "local-only-non-release", prefix + "source-revision": s.Launch.SourceRevision, prefix + "role-target": s.Launch.Target, prefix + "go-version": "go1.26.8"}
}
func controlSourceLabelsMatch(document []byte, s ControlServiceIdentityV1) bool {
	if !ControlObservesSource(s.Launch.Target) {
		return true
	}
	var c struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	return decodeImageJSON(document, &c) && maps.Equal(c.Config.Labels, ControlSourceImageLabels(s))
}
