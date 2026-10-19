//go:build linux

package phase6process

import (
	"context"
	"strings"
	"testing"
)

func TestProcParserRejectsPartialAndDuplicateStatus(t *testing.T) {
	status := "Uid:\t1 1 1 1\nGid:\t2 2 2 2\nGroups:\t2\nNSpid:\t1\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	var o Observation
	if parseStatus([]byte(status), &o) != nil {
		t.Fatal("status")
	}
	for _, b := range []string{status + "Uid:\t1 1 1 1\n", strings.Replace(status, "CapEff:\t0\n", "", 1), strings.Replace(status, "1 1 1 1", "1 1", 1)} {
		var q Observation
		if parseStatus([]byte(b), &q) == nil {
			t.Fatal("invalid status")
		}
	}
	if _, e := parseStart([]byte("2 (wrong) R 1")); e == nil {
		t.Fatal("wrong PID")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ObservePID1(ctx); e == nil {
		t.Fatal("cancellation")
	}
}
