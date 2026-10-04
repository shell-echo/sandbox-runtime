//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"strings"
	"testing"
)

func TestSlice6CertificateControllerStickyDrainClassRemainsOpenNoIssuer(t *testing.T) {
	failed := errors.New("attached controller exited nonzero")
	if slice6CertificateControllerDrainClass(nil, "", true) != "clean_exit" ||
		slice6CertificateControllerDrainClass(failed, "credential-revoke", true) != "sticky_credential_revoke" ||
		slice6CertificateControllerDrainClass(failed, "credential-revoke", false) != "" ||
		slice6CertificateControllerDrainClass(failed, "unrelated-failure", true) != "" {
		t.Fatal("controller sticky fault was washed into clean exit or unrelated failure was accepted")
	}
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("d", 64)
	valid := slice6CertificateControllerOutcome{RunID: runID, ProfileDigest: profile,
		ContainerID: strings.Repeat("b", 64),
		DrainClass:  "sticky_credential_revoke", PhysicalConverged: true}
	if !valid.validForRun(runID, profile) || valid.cleanForRun(runID, profile) ||
		valid.validForRun(strings.Repeat("c", 32), profile) ||
		valid.validForRun(runID, "sha256:"+strings.Repeat("e", 64)) {
		t.Fatal("physical convergence lost exact run binding")
	}
	clean := valid
	clean.DrainClass = "clean_exit"
	if !clean.cleanForRun(runID, profile) || clean.cleanForRun(strings.Repeat("c", 32), profile) {
		t.Fatal("clean exit lost exact run binding")
	}
	for _, mutation := range []slice6CertificateControllerOutcome{
		{RunID: runID, ProfileDigest: profile, ContainerID: valid.ContainerID, DrainClass: "clean_exit"},
		{RunID: runID, ProfileDigest: profile, ContainerID: valid.ContainerID, DrainClass: "ignored_failure", PhysicalConverged: true},
		{RunID: runID, ProfileDigest: profile, ContainerID: "backend-id", DrainClass: valid.DrainClass, PhysicalConverged: true},
	} {
		if mutation.validForRun(runID, profile) {
			t.Fatal("unproved controller convergence accepted")
		}
	}
}
