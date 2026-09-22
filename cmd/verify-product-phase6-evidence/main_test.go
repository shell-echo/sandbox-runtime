package main

import (
	"bytes"
	"testing"
)

func TestRunRequiresExplicitRetainedArguments(t *testing.T) {
	for name, arguments := range map[string][]string{
		"missing retained arguments":     {"-mode=retained"},
		"wrong slice":                    {"-mode=retained", "-slice=product-v1-phase-6-slice-5", "-manifest=/tmp/evidence", "-closure-record=/tmp/closure", "-source-root=/tmp/repository"},
		"unknown mode":                   {"-mode=archive"},
		"retained flags in finalization": {"-slice=product-v1-phase-6-slice-4"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe verifier arguments were accepted")
			}
		})
	}
}
