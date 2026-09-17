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
	if len(publication.Platforms) != 2 || publication.Platforms[0].Digest != PublishedAMD64Digest ||
		publication.Platforms[1].Digest != PublishedARM64V8Digest {
		t.Fatalf("published platforms = %+v", publication.Platforms)
	}
}

func TestPublicationRejectsDrift(t *testing.T) {
	tests := map[string]func(*Publication){
		"index digest": func(p *Publication) {
			p.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"platform digest": func(p *Publication) {
			p.Platforms[0].Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"platform identity": func(p *Publication) { p.Platforms[1].Platform = "linux/arm64" },
		"source":            func(p *Publication) { p.SourceCommit = "0000000000000000000000000000000000000000" },
		"workflow":          func(p *Publication) { p.Workflow = "github.com/example/unsafe.yml" },
		"runner":            func(p *Publication) { p.RunnerPolicy = "allow-self-hosted-runners" },
		"attestation":       func(p *Publication) { p.AttestationID++ },
		"registry evidence": func(p *Publication) { p.RegistryAttestationDigest = PublishedDigest },
		"transparency log":  func(p *Publication) { p.TransparencyLogIndex++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			publication := LockedPublication()
			publication.Platforms = append([]PublishedPlatform(nil), publication.Platforms...)
			mutate(&publication)
			if err := publication.Validate(); err == nil {
				t.Fatal("publication drift was accepted")
			}
		})
	}
}
