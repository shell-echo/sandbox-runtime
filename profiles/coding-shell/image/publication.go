package image

import "errors"

const (
	PublishedRepository                = "ghcr.io/shell-echo/sandbox-runtime-coding-shell"
	PublishedDigest                    = "sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
	PublishedAMD64Digest               = "sha256:a3559ade39fd86c9bb04f69a111d8da4e2f31951333b48bf6d59bd752c95aa4e"
	PublishedARM64V8Digest             = "sha256:a3d9567ee49482582baff67cc3b8679bbe08b79909f7375145004f1c92b4d5f3"
	PublishedSourceCommit              = "cf1830e9bbfcd08d6f171e60f67d949d839e1069"
	PublishedTag                       = "sha-cf1830e9bbfcd08d6f171e60f67d949d839e1069"
	PublishedWorkflow                  = "github.com/shell-echo/sandbox-runtime/.github/workflows/coding-shell-image.yml"
	PublishedRepositoryName            = "shell-echo/sandbox-runtime"
	PublishedRunnerPolicy              = "deny-self-hosted-runners"
	PublishedRegistryAttestationDigest = "sha256:bf31ce86deb5b7f6d2ba374753042e1e2a95c299bb5e6e025976249ddd4536a0"
	PublishedRunID                     = int64(35171475925)
	PublishedAttestationID             = int64(48073123)
	PublishedTransparencyLogIndex      = int64(2870923506)
)

var ErrInvalidPublication = errors.New("invalid coding/shell image publication evidence")

type PublishedPlatform struct {
	Platform string
	Digest   string
}

// Publication is the exact signed coding/shell image evidence accepted by this
// repository's release gate for later external qualification. A newer
// publication must update this authority and pass its own release gate;
// mutable tags are never accepted.
type Publication struct {
	Repository                string
	Digest                    string
	Tag                       string
	SourceCommit              string
	Workflow                  string
	RepositoryName            string
	RunnerPolicy              string
	RegistryAttestationDigest string
	RunID                     int64
	AttestationID             int64
	TransparencyLogIndex      int64
	RuntimeProfileID          string
	Platforms                 []PublishedPlatform
}

func LockedPublication() Publication {
	return Publication{
		Repository: PublishedRepository, Digest: PublishedDigest, Tag: PublishedTag,
		SourceCommit: PublishedSourceCommit, Workflow: PublishedWorkflow,
		RepositoryName: PublishedRepositoryName, RunnerPolicy: PublishedRunnerPolicy,
		RegistryAttestationDigest: PublishedRegistryAttestationDigest,
		RunID:                     PublishedRunID, AttestationID: PublishedAttestationID,
		TransparencyLogIndex: PublishedTransparencyLogIndex, RuntimeProfileID: ProfileID,
		Platforms: []PublishedPlatform{
			{Platform: "linux/amd64", Digest: PublishedAMD64Digest},
			{Platform: "linux/arm64/v8", Digest: PublishedARM64V8Digest},
		},
	}
}

func (p Publication) Image() string { return p.Repository + "@" + p.Digest }

func (p Publication) Validate() error {
	want := LockedPublication()
	if p.Repository != want.Repository || p.Digest != want.Digest || p.Tag != want.Tag ||
		p.SourceCommit != want.SourceCommit || p.Workflow != want.Workflow ||
		p.RepositoryName != want.RepositoryName || p.RunnerPolicy != want.RunnerPolicy ||
		p.RegistryAttestationDigest != want.RegistryAttestationDigest ||
		p.RunID != want.RunID || p.AttestationID != want.AttestationID ||
		p.TransparencyLogIndex != want.TransparencyLogIndex ||
		p.RuntimeProfileID != want.RuntimeProfileID || len(p.Platforms) != len(want.Platforms) {
		return ErrInvalidPublication
	}
	for index := range want.Platforms {
		if p.Platforms[index] != want.Platforms[index] {
			return ErrInvalidPublication
		}
	}
	return nil
}
