//go:build integration && (darwin || linux)

package controloperator

import (
	"encoding/json"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"os"
	"reflect"
	"testing"
)

// The operator fixture owns create and exact cleanup. This test exercises
// actual attach/start/exec/sign/EOF with the real role and private run inputs.
func TestControlDeliveryDocker(t *testing.T) {
	path := os.Getenv("CONTROL_DELIVERY_REAL_INPUT")
	output := os.Getenv("CONTROL_DELIVERY_REAL_OUTPUT")
	if path == "" || output == "" {
		t.Skip("explicit unique Docker delivery run")
	}
	f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	result, e := Run(t.Context(), path)
	if err := json.NewEncoder(f).Encode(result); err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Fatal(e)
	}
	if result.Status != "verified-held" || result.Receipt.Admission != "held-not-a-permit" || result.Receipt.Scope != controldelivery.Scope || result.FirstObservation.PID <= 0 || result.FirstObservation.PID != result.OperatorObservation.PID || result.LoaderObservation.PID != result.OperatorObservation.PID {
		t.Fatal("held delivery identity")
	}
}

func TestControlTrustDeliveryDocker(t *testing.T) {
	path, output := os.Getenv("CONTROL_TRUST_REAL_INPUT"), os.Getenv("CONTROL_TRUST_REAL_OUTPUT")
	if path == "" || output == "" {
		t.Skip("explicit unique trust Docker run")
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := Run(t.Context(), path)
	if e := json.NewEncoder(f).Encode(r); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "verified-held" || r.Receipt.Scope != controldelivery.TrustScope || r.Receipt.Admission != "held-not-a-permit" || r.Challenge.Source == nil || r.Challenge.Source.Trust == nil || len(r.Challenge.Source.Trust.Anchors) != 2 || !reflect.DeepEqual(r.FirstObservation, r.OperatorObservation) || r.FirstObservation.PID <= 0 || r.LoaderObservation.PID != r.FirstObservation.PID {
		t.Fatal("trust held identity")
	}
	for _, a := range r.Challenge.Source.Trust.Anchors {
		if a.Artifact.File.Inode == 0 || a.Artifact.MountID == 0 || a.Artifact.File.Mode != 0444 || a.Artifact.Directory.Mode != 0555 {
			t.Fatal("actual CA identity")
		}
	}
}

func TestControlSourceDeliveryDocker(t *testing.T) {
	path, output := os.Getenv("CONTROL_SOURCE_REAL_INPUT"), os.Getenv("CONTROL_SOURCE_REAL_OUTPUT")
	if path == "" || output == "" {
		t.Skip("explicit source Docker run")
	}
	f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	result, e := Run(t.Context(), path)
	if err := json.NewEncoder(f).Encode(result); err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Fatal(e)
	}
	if result.Status != "verified-held" || result.Receipt.Admission != "held-not-a-permit" || result.Receipt.Scope != controldelivery.SourceScope || result.Challenge.Source == nil || result.Challenge.Source.Root == "" || result.FirstObservation.PID <= 0 || result.FirstObservation.PID != result.OperatorObservation.PID || result.LoaderObservation.PID != result.OperatorObservation.PID || result.FirstObservation.StartedAt != result.OperatorObservation.StartedAt {
		t.Fatal("source held identity")
	}
}
