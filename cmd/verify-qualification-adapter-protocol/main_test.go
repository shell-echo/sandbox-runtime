package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func TestRunVerifiesDefinitionWithoutClaimingExecution(t *testing.T) {
	original := verifyAdapterProtocol
	t.Cleanup(func() { verifyAdapterProtocol = original })
	verifyAdapterProtocol = func(context.Context, string) (qualificationadapterprotocol.Report, error) {
		return qualificationadapterprotocol.Report{
			ProtocolID:             qualificationadapterprotocol.ProtocolID,
			ProtocolVersion:        qualificationadapterprotocol.ProtocolVersion,
			SchemaDigest:           qualificationadapterprotocol.ExpectedProtocolSchemaDigest,
			SemanticsDigest:        qualificationadapterprotocol.ExpectedProtocolSemanticsDigest,
			TranscriptSchemaDigest: qualificationadapterprotocol.ExpectedTranscriptSchemaDigest,
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-source-root", "/source"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no process execution or external-caller result claimed") ||
		!strings.Contains(stdout.String(), qualificationadapterprotocol.ExpectedTranscriptSchemaDigest) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}

func TestRunReportsVerifierFailure(t *testing.T) {
	original := verifyAdapterProtocol
	t.Cleanup(func() { verifyAdapterProtocol = original })
	verifyAdapterProtocol = func(context.Context, string) (qualificationadapterprotocol.Report, error) {
		return qualificationadapterprotocol.Report{}, errors.New("definition mismatch")
	}
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "definition mismatch") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
