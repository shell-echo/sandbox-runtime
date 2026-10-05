package image

import (
	"reflect"
	"testing"
)

func TestLockedManifestMatchesRepositorySource(t *testing.T) {
	embedded, err := LockedManifest()
	if err != nil {
		t.Fatal(err)
	}
	source, err := Load(ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(embedded, source) {
		t.Fatal("embedded runtime manifest drifted from source")
	}
}
