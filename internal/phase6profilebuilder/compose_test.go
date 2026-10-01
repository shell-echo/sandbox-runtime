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

func TestCandidateProfileDiagnosticsDefensiveCopy(t *testing.T) {
	candidate := CandidateProfile{metrics: CompositionMetrics{ImageSupplyLoads: 2,
		ExternalArchivePasses: 2, Stages: []CompositionStage{{Name: "final_source_reopen", Duration: time.Second}}}}
	first := candidate.Diagnostics()
	first.Stages[0].Name = "modified"
	second := candidate.Diagnostics()
	if second.ImageSupplyLoads != 2 || second.ExternalArchivePasses != 2 ||
		len(second.Stages) != 1 || second.Stages[0].Name != "final_source_reopen" {
		t.Fatal("diagnostic stage slice aliases candidate state")
	}
}
