package image

import "errors"

const (
	PublishedRepository     = "ghcr.io/shell-echo/sandbox-runtime-browser"
	PublishedDigest         = "sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f"
	PublishedSourceCommit   = "58ed0093816d3daa3000750013b8e5991ef4bcf7"
	PublishedTag            = "sha-58ed0093816d3daa3000750013b8e5991ef4bcf7"
	PublishedWorkflow       = "github.com/shell-echo/sandbox-runtime/.github/workflows/browser-image.yml"
	PublishedRunID          = int64(33724368530)
	PublishedAttestationID  = int64(44912296)
	PublishedRunnerPolicy   = "deny-self-hosted-runners"
	PublishedRepositoryName = "shell-echo/sandbox-runtime"
)

var ErrInvalidPublication = errors.New("invalid browser image publication evidence")

// Publication is the exact signed image evidence accepted by the first
// Browser runtime adapter. A newer publication must update this authority and
// pass its own release gate; mutable tags are never accepted at runtime.
type Publication struct {
	Repository       string
	Digest           string
	Tag              string
	SourceCommit     string
	Workflow         string
	RepositoryName   string
	RunnerPolicy     string
	RunID            int64
	AttestationID    int64
	Platforms        []string
	SeccompDigest    string
	RuntimeProfileID string
}

func LockedPublication() Publication {
	return Publication{
		Repository: PublishedRepository, Digest: PublishedDigest, Tag: PublishedTag,
		SourceCommit: PublishedSourceCommit, Workflow: PublishedWorkflow,
		RepositoryName: PublishedRepositoryName, RunnerPolicy: PublishedRunnerPolicy,
		RunID: PublishedRunID, AttestationID: PublishedAttestationID,
		Platforms:     []string{"linux/amd64", "linux/arm64/v8"},
		SeccompDigest: SeccompDigest, RuntimeProfileID: ProfileID,
	}
}

func (p Publication) Image() string { return p.Repository + "@" + p.Digest }

func (p Publication) Validate() error {
	want := LockedPublication()
	if p.Repository != want.Repository || p.Digest != want.Digest || p.Tag != want.Tag ||
		p.SourceCommit != want.SourceCommit || p.Workflow != want.Workflow ||
		p.RepositoryName != want.RepositoryName || p.RunnerPolicy != want.RunnerPolicy ||
		p.RunID != want.RunID || p.AttestationID != want.AttestationID ||
		p.SeccompDigest != want.SeccompDigest || p.RuntimeProfileID != want.RuntimeProfileID ||
		len(p.Platforms) != len(want.Platforms) {
		return ErrInvalidPublication
	}
	for index := range want.Platforms {
		if p.Platforms[index] != want.Platforms[index] {
			return ErrInvalidPublication
		}
	}
	return nil
}
