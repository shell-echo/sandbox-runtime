package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSourceReviewCandidateRejectsInvalidInputWithoutOutput(t *testing.T) {
	for name, data := range map[string]string{
		"empty": "", "unknown": `{"private_key":"forbidden"}`,
		"duplicate": `{"source_root":"x","source_root":"y"}`,
		"trailing":  "{}\n", "oversized": strings.Repeat("x", 64<<10+1),
		"relative": `{"source_root":".","profile":"p","public_key":"k","archive":"a"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(t.Context(), []string{"-candidate"}, strings.NewReader(data), &output); err == nil || output.Len() != 0 {
				t.Fatal("invalid candidate produced output", err)
			}
		})
	}
	for _, args := range [][]string{{"-unknown"}, {"-intent", "-candidate"}, {"-candidate", "extra"}} {
		var output bytes.Buffer
		if !errors.Is(run(t.Context(), args, strings.NewReader("{}"), &output), errUsage) || output.Len() != 0 {
			t.Fatal("unexpected argument admitted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, invalid := range []context.Context{nil, ctx} {
		var output bytes.Buffer
		if err := run(invalid, []string{"-candidate"}, strings.NewReader("{}"), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid context admitted")
		}
	}
}
