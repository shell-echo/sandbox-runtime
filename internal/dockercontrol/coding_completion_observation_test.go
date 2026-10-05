package dockercontrol

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
	ocidigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

func TestCodingSelectedImageUsesFrozenTemplateAndEmbeddedManifest(t *testing.T) {
	template := testVolumeTemplate(t)
	manifest, err := codingimage.LockedManifest()
	if err != nil {
		t.Fatal(err)
	}
	platform, ok := codingOCIPlatform(template.Image.Platform)
	if !ok {
		t.Fatal("invalid fixture platform")
	}
	selected := client.ImageInspectResult{InspectResponse: image.InspectResponse{
		Descriptor: &ocispec.Descriptor{Digest: ocidigest.Digest(template.Image.SelectedManifestDigest),
			MediaType: "application/vnd.oci.image.manifest.v1+json", Size: template.Image.SelectedManifestSize,
			Platform: &platform},
		Config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{
			Env: slices.Clone(template.Environment), Cmd: slices.Clone(manifest.Runtime.Command),
			WorkingDir: template.WorkingDirectory, User: "65532:65532"}},
	}}
	if !validCodingSelectedImage(selected, template) {
		t.Fatal("frozen selected image projection rejected")
	}
	bad := selected
	copyConfig := *selected.Config
	copyConfig.Env = []string{"UNTRUSTED=1"}
	bad.Config = &copyConfig
	if validCodingSelectedImage(bad, template) {
		t.Fatal("selected image environment drift admitted")
	}
	bad = selected
	copyDescriptor := *selected.Descriptor
	copyDescriptor.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	bad.Descriptor = &copyDescriptor
	if validCodingSelectedImage(bad, template) {
		t.Fatal("selected image platform drift admitted")
	}
}

func TestCodingCompletionObserverCannotAcceptCallerDigestOrWrongReceipt(t *testing.T) {
	authority, plan, now := testReceiptAuthority(t)
	binding := testReceiptBinding(authority, plan)
	state, err := NewCodingReceiptState(binding)
	if err != nil {
		t.Fatal(err)
	}
	state, receipt, _, err := state.beginUnknown(binding, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	observer := &codingUnixObserver{binding: binding, authority: authority,
		template: phase6security.CodingRuntimeTemplateV2{}, bounded: &codingObservationTransport{}}
	for name, value := range map[string]CodingReceipt{
		"wrong effect": func() CodingReceipt {
			copy := receipt
			copy.Authority.EffectID = testControlDigest("0")
			return copy
		}(),
		"fabricated completion": func() CodingReceipt {
			copy := receipt
			copy.Status = ReceiptCompleted
			copy.CompletionDigest = testControlDigest("0")
			return copy
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := observer.observeCompleted(context.Background(), value, state.Revision); !errors.Is(err, ErrInvalidCodingCompletionObservation) {
				t.Fatalf("invalid receipt reached physical observation: %v", err)
			}
		})
	}
	if _, err := observer.observeCompleted(context.Background(), receipt, 0); !errors.Is(err, ErrInvalidCodingCompletionObservation) {
		t.Fatalf("zero receipt revision admitted: %v", err)
	}
	observer.gate = make(chan struct{}, 1) // one in-flight observation holds the client
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := observer.observeCompleted(short, receipt, state.Revision); !errors.Is(err, ErrInvalidCodingCompletionObservation) {
		t.Fatalf("completion observation ignored admission deadline: %v", err)
	}
}
