//go:build !darwin && !linux

package qualificationsupervisor

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedFailsBeforeFileAccess(t *testing.T) {
	if e, err := OpenExecutable(context.Background(), nil, "missing", "invalid", 0); e != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}

func TestUnsupportedLocationsFailBeforeFileAccess(t *testing.T) {
	if f, err := OpenLocationFiles(nil, nil); f != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}

func TestUnsupportedFinalizationFailsBeforeFileAccess(t *testing.T) {
	if f, err := FinalizePreflight(nil, nil, nil, nil); f != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}

func TestUnsupportedLaunchPreparation(t *testing.T) {
	if l, err := PrepareLaunch(nil, nil); l != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}

func TestUnsupportedProcessStart(t *testing.T) {
	if p, err := StartProcess(nil, nil); p != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatal(err)
	}
}
