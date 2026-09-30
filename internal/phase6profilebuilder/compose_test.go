package phase6profilebuilder

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestComposeSlice6CandidateProfileRejectsIncompleteSource(t *testing.T) {
	for _, input := range []CompositionInputs{
		{},
		{Images: ImageDraftInputs{SourceRoot: "/one"}, ExternalImages: ExternalImageInputs{SourceRoot: "/two"}},
		{Images: ImageDraftInputs{SourceRoot: "/one"}, ExternalImages: ExternalImageInputs{SourceRoot: "/one"}},
	} {
		if candidate, err := ComposeSlice6CandidateProfile(context.Background(), input, time.Now().UTC()); !errors.Is(err, ErrInvalidComposition) || candidate.Profile.ProfileDigest != "" {
			t.Fatalf("incomplete source admitted: %v", err)
		}
	}
	if _, err := ComposeSlice6CandidateProfile(nil, CompositionInputs{}, time.Now().UTC()); !errors.Is(err, ErrInvalidComposition) {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ComposeSlice6CandidateProfile(ctx, CompositionInputs{}, time.Now().UTC()); !errors.Is(err, ErrInvalidComposition) {
		t.Fatal("cancelled context admitted")
	}
}
