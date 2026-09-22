package main

import (
	"bytes"
	"testing"
)

func TestRunRequiresClosedArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"-manifest=/tmp/value"},
		{"-source-root=/tmp/repository"},
		{"-manifest=/tmp/value", "-source-root=/tmp/repository", "extra"},
		{"-manifest=/tmp/value", "-source-root=/tmp/repository", "-slice=product-v1-phase-6-slice-5"},
		{"-mode=closure", "-manifest=/tmp/value", "-source-root=/tmp/repository"},
		{"-mode=retained", "-manifest=/tmp/value", "-source-root=/tmp/repository", "-slice=product-v1-phase-6-slice-4", "-closure-record=/tmp/closure"},
		{"-mode=unknown", "-manifest=/tmp/value", "-source-root=/tmp/repository"},
	} {
		if err := run(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe arguments accepted: %v", arguments)
		}
	}
}
