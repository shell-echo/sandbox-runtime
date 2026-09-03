package image

import "testing"

func TestLockedPublication(t *testing.T) {
	publication := LockedPublication()
	if err := publication.Validate(); err != nil {
		t.Fatal(err)
	}
	if publication.Image() != PublishedRepository+"@"+PublishedDigest {
		t.Fatalf("published image = %q", publication.Image())
	}
}

func TestPublicationRejectsDrift(t *testing.T) {
	tests := map[string]func(*Publication){
		"digest": func(p *Publication) {
			p.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"source":      func(p *Publication) { p.SourceCommit = "0000000000000000000000000000000000000000" },
		"workflow":    func(p *Publication) { p.Workflow = "github.com/example/unsafe.yml" },
		"runner":      func(p *Publication) { p.RunnerPolicy = "allow-self-hosted-runners" },
		"platform":    func(p *Publication) { p.Platforms[1] = "linux/arm64" },
		"attestation": func(p *Publication) { p.AttestationID++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			publication := LockedPublication()
			publication.Platforms = append([]string(nil), publication.Platforms...)
			mutate(&publication)
			if err := publication.Validate(); err == nil {
				t.Fatal("publication drift was accepted")
			}
		})
	}
}
